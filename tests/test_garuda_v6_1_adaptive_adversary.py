"""GARUDA v6.1 Adaptive Adversary Benchmark Suite.
Tests the 5 hardest challenges of intelligent, adaptive attackers:
  1. Adaptive MITM (MAC-Hopping Gateway Hijack)
  2. Low-and-Slow Distributed Evasion
  3. Encrypted C2 Behavioral Cadence (Payload-Agnostic)
  4. Adversarial Baseline Poisoning Defense
  5. Recovery Under Pressure (Crash-Fault State Continuity)
"""

import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.ids_engine import LivePacketIDS
from app.services.ml_engine import BehavioralMLEngine, compute_beacon_regularity
from app.services.firewall_manager import replay_persisted_blocked_ips
from app.services.attestation_ledger import (
    append_attestation_block,
    verify_ledger_integrity,
    get_block_merkle_proof,
    verify_merkle_proof,
)

try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.models import Base
    _HAS_SQLALCHEMY = True
except ImportError:
    _HAS_SQLALCHEMY = False


def _make_temp_db():
    td = tempfile.TemporaryDirectory()
    db_file = Path(td.name) / "test_ledger_v61.db"
    if _HAS_SQLALCHEMY:
        engine = create_engine(f"sqlite:///{db_file.as_posix()}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        return td, db_file, engine, Session
    return td, db_file, None, None


def test_challenge_1_adaptive_mitm_mac_hopping():
    """Challenge 1: Adaptive MITM — Attacker hops MAC address repeatedly while spoofing gateway."""
    ids = LivePacketIDS()
    gw_ip = "192.168.1.1"
    gw_mac = "70:85:C2:44:10:01"
    ids.update_network_context("192.168.1.15", gw_ip, gw_mac)

    hopping_macs = [
        "DE:AD:BE:01:00:01",
        "DE:AD:BE:01:00:02",
        "DE:AD:BE:01:00:03",
        "DE:AD:BE:01:00:04",
    ]

    all_alerts = []
    base_t = 1000.0
    for idx, mac in enumerate(hopping_macs):
        alerts = ids.inspect_arp_event(gw_ip, mac, op=2, now=base_t + idx * 10.0)
        all_alerts.extend(alerts)

    # Every single hopping MAC must be caught
    gw_spoofs = [a for a in all_alerts if a["attack_type"] == "arp_spoof"]
    assert len(gw_spoofs) == 4, f"Expected 4 gateway spoof detections, got {len(gw_spoofs)}"

    # The adaptive hopping pattern must be recognized
    hopping_alerts = [a for a in all_alerts if a["attack_type"] == "adaptive_mitm_mac_hopping"]
    assert len(hopping_alerts) >= 1, "Expected adaptive_mitm_mac_hopping alert to be triggered"

    ev = json.loads(hopping_alerts[-1]["technical_evidence"])
    assert ev["count"] >= 2
    assert "DE:AD:BE:01:00:01" in ev["hopping_macs"]
    assert "DE:AD:BE:01:00:02" in ev["hopping_macs"]


def test_challenge_2_low_and_slow_distributed_evasion():
    """Challenge 2: Low-and-Slow Evasion — Multi-device coordinated scan spread over extended time."""
    ids = LivePacketIDS()
    target_ip = "192.168.1.15"
    ids.update_network_context(target_ip, "192.168.1.1", "70:85:C2:44:10:01")

    # 4 bot devices each scanning only 2 ports, spaced 60-120 seconds apart over 8 minutes
    bot_plan = [
        ("192.168.1.41", [22, 23]),
        ("192.168.1.42", [80, 443]),
        ("192.168.1.43", [445, 3389]),
        ("192.168.1.44", [8080, 8443]),
    ]

    all_alerts = []
    current_time = 1000.0
    for bot_ip, ports in bot_plan:
        for p in ports:
            current_time += 60.0  # Spaced 1 minute apart
            alerts = ids.inspect_tcp_syn(bot_ip, target_ip, p, now=current_time)
            all_alerts.extend(alerts)

    # Individual fast sweep should NOT be triggered (since each bot only sent 2 probes)
    fast_sweeps = [a for a in all_alerts if a["attack_type"] == "port_sweep"]
    assert len(fast_sweeps) == 0, "Individual bots should have evaded the single-host fast sweep threshold"

    # Coordinated distributed detection MUST catch the correlation across devices
    dist_alerts = [a for a in all_alerts if a["attack_type"] == "distributed_port_scan"]
    assert len(dist_alerts) >= 1, "Coordinated distributed sweep must be flagged"
    ev = json.loads(dist_alerts[-1]["technical_evidence"])
    assert len(ev["sources"]) >= 3


def test_challenge_3_encrypted_c2_behavioral_cadence():
    """Challenge 3: Encrypted C2 — Behavioral timing cadence detection without inspecting packet payloads."""
    ids = LivePacketIDS()
    victim_ip = "192.168.1.88"
    victim_mac = "B8:27:EB:AA:55:11"
    c2_ip = "198.51.100.77"
    c2_port = 443  # Encrypted HTTPS / TLS 1.3 / WireGuard port

    alerts = []
    # 7 strict callbacks on 20-second cadence with slight jitter (19-21s)
    cadence = [0.0, 20.1, 40.2, 59.9, 80.3, 100.1, 120.0]
    base_t = 5000.0

    for dt in cadence:
        # Zero payload inspected — strictly L4 flow timing
        a = ids.inspect_outbound_flow(victim_ip, victim_mac, c2_ip, c2_port, now=base_t + dt)
        alerts.extend(a)

    beacon_alerts = [x for x in alerts if x["attack_type"] == "c2_beacon"]
    assert len(beacon_alerts) >= 1, "Encrypted C2 periodic cadence must be detected via flow timing alone"
    assert beacon_alerts[-1]["severity"] == "critical"
    ev = json.loads(beacon_alerts[-1]["technical_evidence"])
    assert ev["regularity"] >= 0.85


def test_challenge_4_adversarial_baseline_poisoning():
    """Challenge 4: Baseline Poisoning Defense — Resist repeated abnormal inputs designed to warp baseline."""
    eng = BehavioralMLEngine()
    attacker_mac = "AA:BB:CC:DD:EE:01"
    attacker_ip = "192.168.1.66"

    # Attacker performs 25 repeated abnormal cycles trying to desensitize the model
    for i in range(25):
        eng.inject_simulated_anomaly(attacker_mac, {"syn_fanout_norm": 0.88, "arp_burst_norm": 0.82})
        rep = eng.evaluate_snapshot([{"mac": attacker_mac, "ip": attacker_ip, "is_safe": False, "is_online": True, "latency_ms": 160}], [], {})
        # Model must NOT accept the attacker as normal
        score = rep["device_scores"][0]["anomaly_score"]
        assert score >= 70.0, f"Cycle {i}: Anomaly score dropped to {score}, baseline was poisoned!"

    # Even if someone marks the device as safe, the anti-poisoning guardrail injects only canonical benign vectors
    eng.reinforce_safe_device(attacker_mac)
    # Inject active malicious behavior again
    eng.inject_simulated_anomaly(attacker_mac, {"syn_fanout_norm": 0.95})
    post_retrain_rep = eng.evaluate_snapshot([{"mac": attacker_mac, "ip": attacker_ip, "is_safe": True, "is_online": True, "latency_ms": 150}], [], {})
    assert post_retrain_rep["device_scores"][0]["anomaly_score"] >= 65.0, "Model retraining suppressed active threat detection!"


def test_challenge_5_recovery_under_pressure_crash_resilience():
    """Challenge 5: Recovery Under Pressure — Crash & restart during active attack with full state continuity."""
    td, db_file, engine1, Session1 = _make_temp_db()
    if not _HAS_SQLALCHEMY:
        td.cleanup()
        return

    engine2 = None
    db2 = None
    try:
        # Phase 1: Active Attack before crash
        db1 = Session1()
        b1 = append_attestation_block(db1, "active_mitm", "MITM Attack in progress", {"ip": "192.168.1.99"})
        b2 = append_attestation_block(db1, "fw_lockdown", "Firewall lockdown engaged", {"action": "isolate"})
        db1.close()

        # Simulate simulated crash: terminate engine and sessions abruptly
        engine1.dispose()

        # Phase 2: Post-Crash Cold Restart
        engine2 = create_engine(f"sqlite:///{db_file.as_posix()}", connect_args={"check_same_thread": False})
        Session2 = sessionmaker(autocommit=False, autoflush=False, bind=engine2)
        db2 = Session2()

        # 1. Verify ledger integrity survived crash
        integrity = verify_ledger_integrity(db2)
        assert integrity["valid"] is True
        assert integrity["blocks_checked"] >= 2

        # 2. Verify firewall state continuity
        mock_fw_logs = [
            {"target_ip": "192.168.1.99", "action": "block", "enforced": True},
            {"target_ip": "192.168.1.200", "action": "block", "enforced": True},
            {"target_ip": "192.168.1.200", "action": "unblock", "enforced": True},
        ]
        active_blocked = replay_persisted_blocked_ips(mock_fw_logs)
        assert active_blocked == ["192.168.1.99"]

        # 3. Append new block post-restart and verify Merkle proof
        b3 = append_attestation_block(db2, "post_crash_recovery", "System online, attacker blocked", {"ip": "192.168.1.99"})
        assert b3.block_index == 2
        assert b3.prev_hash == b2.block_hash

        proof_obj = get_block_merkle_proof(db2, 2)
        assert proof_obj["verified_locally"] is True
        assert verify_merkle_proof(proof_obj["leaf_hash"], proof_obj["proof"], proof_obj["merkle_root"]) is True
    finally:
        if db2 is not None:
            db2.close()
        if engine2 is not None:
            engine2.dispose()
        td.cleanup()
