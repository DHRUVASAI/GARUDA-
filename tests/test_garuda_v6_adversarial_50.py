"""GARUDA v6 Adversarial Validation Suite — Complete 50-Test Benchmark.
Categories:
  A. Red Team (RT-01 .. RT-12)              : 12 tests
  B. ML & Behavioral Testing (ML-01 .. ML-08):  8 tests
  C. Prevention / Blue Team (BT-01 .. BT-07) :  7 tests
  D. Forensic Ledger (FR-01 .. FR-08)        :  8 tests
  E. Purple Team Campaigns (PT-01 .. PT-08)  :  8 tests
  F. Performance & Resilience (PR-01 .. PR-07): 7 tests
  TOTAL                                      : 50 tests
"""

import concurrent.futures
import json
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import sqlite3
import types

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

try:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.database import Base
    from app.models import AttestationBlock, FirewallRuleLog
    _HAS_SQLALCHEMY = True
except ImportError:
    _HAS_SQLALCHEMY = False
    AttestationBlock = None
from app.services.attestation_ledger import (
    append_attestation_block,
    compute_merkle_root,
    generate_merkle_proof,
    get_block_merkle_proof,
    sha256_hex,
    signer,
    verify_ledger_integrity,
    verify_merkle_proof,
)
from app.services.aws_bridge import (
    SAMPLE_VPC_FLOW_LOGS,
    dispatch_aws_finding,
    parse_vpc_flow_logs,
    to_aws_security_hub_asff,
)
from app.services.campaign_correlator import correlate_attack_campaigns
from app.services.capability_probe import (
    clamp_subnet_to_safe_24,
    detect_proxy_arp,
    probe_network_environment,
)
from app.services.device_scanner import resolve_device_identity
from app.services.firewall_manager import (
    build_block_ip_command,
    enforce_block_ip,
    enforce_lockdown_mode,
    replay_persisted_blocked_ips,
)
from app.services.ids_engine import (
    LivePacketIDS,
    evaluate_baseline_and_passive_threats,
    pin_static_gateway_arp,
)
from app.services.ml_engine import BehavioralMLEngine, analyze_domain_dga
from app.services.plugin_engine import DiscoveryPlugin, PluginOrchestrator
from app.services.rule_updater import rule_manager


class _SqliteBlockRow:
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)


class _SqliteQuery:
    def __init__(self, conn, filter_idx=None):
        self._conn = conn
        self._filter_idx = filter_idx

    def order_by(self, *args, **kwargs):
        return self

    def filter(self, cond):
        return _SqliteQuery(self._conn, filter_idx=cond)

    def all(self):
        cur = self._conn.execute(
            "SELECT block_index, timestamp_utc, event_type, summary, payload_json, payload_sha256, "
            "prev_hash, merkle_root, block_hash, signature_alg, signature_hex, signer_pubkey_hex, "
            "anchor_status, chain_name, tx_hash, contract_address FROM attestation_blocks ORDER BY block_index ASC"
        )
        cols = [d[0] for d in cur.description]
        rows = [_SqliteBlockRow(**dict(zip(cols, r))) for r in cur.fetchall()]
        if self._filter_idx is not None:
            rows = [r for r in rows if r.block_index == self._filter_idx]
        return rows

    def first(self):
        rows = self.all()
        return rows[0] if rows else None

    def delete(self):
        if self._filter_idx is not None:
            self._conn.execute("DELETE FROM attestation_blocks WHERE block_index = ?", (self._filter_idx,))


class _SqliteLedgerSession:
    def __init__(self, db_file: Path):
        self._conn = sqlite3.connect(str(db_file), check_same_thread=False)
        self._pending_updates = []

    def query(self, _model):
        return _SqliteQuery(self._conn)

    def add(self, blk):
        self._conn.execute(
            "INSERT INTO attestation_blocks (block_index, timestamp_utc, event_type, summary, payload_json, "
            "payload_sha256, prev_hash, merkle_root, block_hash, signature_alg, signature_hex, signer_pubkey_hex, "
            "anchor_status, chain_name, tx_hash, contract_address) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                blk.block_index, blk.timestamp_utc, blk.event_type, blk.summary, blk.payload_json,
                blk.payload_sha256, blk.prev_hash, blk.merkle_root, blk.block_hash, blk.signature_alg,
                blk.signature_hex, blk.signer_pubkey_hex, blk.anchor_status, blk.chain_name,
                getattr(blk, "tx_hash", None), getattr(blk, "contract_address", None),
            ),
        )

    def update_block(self, blk):
        self._conn.execute(
            "UPDATE attestation_blocks SET payload_json=?, signature_hex=? WHERE block_index=?",
            (blk.payload_json, blk.signature_hex, blk.block_index),
        )

    def commit(self):
        self._conn.commit()

    def refresh(self, _blk):
        pass

    def close(self):
        self._conn.close()


class _FakeCol:
    def asc(self):
        return self

    def __eq__(self, other):
        return other


def _install_sqlite_models_shim():
    if "app.models" not in sys.modules:
        mod = types.ModuleType("app.models")

        class _BlockModel(_SqliteBlockRow):
            block_index = _FakeCol()

        mod.AttestationBlock = _BlockModel
        sys.modules["app.models"] = mod


def _init_sqlite_file(db_file: Path):
    conn = sqlite3.connect(str(db_file))
    conn.execute(
        """CREATE TABLE IF NOT EXISTS attestation_blocks (
            block_index INTEGER UNIQUE NOT NULL,
            timestamp_utc TEXT NOT NULL,
            event_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            payload_json TEXT NOT NULL,
            payload_sha256 TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            merkle_root TEXT NOT NULL,
            block_hash TEXT UNIQUE NOT NULL,
            signature_alg TEXT NOT NULL,
            signature_hex TEXT NOT NULL,
            signer_pubkey_hex TEXT NOT NULL,
            anchor_status TEXT NOT NULL,
            chain_name TEXT,
            tx_hash TEXT,
            contract_address TEXT
        )"""
    )
    conn.commit()
    conn.close()


def _make_temp_db():
    td = tempfile.TemporaryDirectory()
    db_file = Path(td.name) / "test_ledger.db"
    if _HAS_SQLALCHEMY:
        engine = create_engine(f"sqlite:///{db_file.as_posix()}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(bind=engine)
        Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        return td, db_file, engine, Session
    _install_sqlite_models_shim()
    _init_sqlite_file(db_file)
    return td, db_file, None, lambda: _SqliteLedgerSession(db_file)


# =====================================================================
# A. RED TEAM — NETWORK ATTACK SIMULATION (RT-01 .. RT-12)
# =====================================================================

def test_RT01_arp_spoofing_and_intermittent():
    ids = LivePacketIDS()
    ids.update_network_context("192.168.1.14", "192.168.1.1", "70:85:C2:44:10:01")
    a1 = ids.inspect_arp_event("192.168.1.1", "DE:AD:BE:9F:01:22", op=2, now=100.0)
    a2 = ids.inspect_arp_event("192.168.1.1", "DE:AD:BE:9F:01:22", op=2, now=280.0)
    assert any(a["attack_type"] == "arp_spoof" and a["severity"] == "critical" for a in a1)
    assert any(a["attack_type"] == "arp_spoof" for a in a2)


def test_RT02_arp_reply_storm():
    ids = LivePacketIDS()
    ids.update_network_context("192.168.1.14", "192.168.1.1", "70:85:C2:44:10:01")
    alerts = []
    for i in range(18):
        alerts.extend(ids.inspect_arp_event("192.168.1.77", "AA:BB:CC:DD:EE:11", op=2, now=100.0 + i * 0.1))
    assert any(a["attack_type"] == "arp_storm" for a in alerts)


def test_RT03_rogue_dhcp_and_competing_servers():
    ids = LivePacketIDS()
    ids.update_network_context("192.168.1.14", "192.168.1.1", "70:85:C2:44:10:01")
    a1 = ids.inspect_dhcp_event(msg_type=2, src_ip="192.168.1.200", src_mac="DE:AD:BE:00:00:01", hostname="Rogue1")
    a2 = ids.inspect_dhcp_event(msg_type=5, src_ip="192.168.1.201", src_mac="DE:AD:BE:00:00:02", hostname="Rogue2")
    assert any(a["attack_type"] == "rogue_dhcp" for a in a1)
    assert any(a["attack_type"] == "rogue_dhcp" for a in a2)
    assert len(ids._dhcp_servers_seen) >= 2


def test_RT04_fast_syn_port_sweep():
    ids = LivePacketIDS()
    ids.update_network_context("192.168.1.14", "192.168.1.1", "70:85:C2:44:10:01")
    alerts = []
    for p in range(100, 115):
        alerts.extend(ids.inspect_tcp_syn("192.168.1.90", "192.168.1.14", p, now=50.0 + (p - 100) * 0.2))
    assert any(a["attack_type"] == "port_sweep" and a["severity"] == "critical" for a in alerts)


def test_RT05_slow_port_scan_over_minutes():
    ids = LivePacketIDS()
    ids.update_network_context("192.168.1.14", "192.168.1.1", "70:85:C2:44:10:01")
    alerts = []
    # Spread 11 distinct ports over 6 minutes (36s apart -> evades 10s fast sweep)
    for idx, port in enumerate([21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389]):
        alerts.extend(ids.inspect_tcp_syn("192.168.1.91", "192.168.1.14", port, now=1000.0 + idx * 36.0))
    assert any(a["attack_type"] == "slow_port_scan" for a in alerts)


def test_RT06_distributed_port_scan_correlation():
    ids = LivePacketIDS()
    ids.update_network_context("192.168.1.14", "192.168.1.1", "70:85:C2:44:10:01")
    alerts = []
    # 3 distinct attacking hosts each probe only 3-4 ports (none triggers single-host threshold alone)
    triples = [
        ("192.168.1.51", [22, 23, 25]),
        ("192.168.1.52", [80, 110, 139]),
        ("192.168.1.53", [443, 445, 3389]),
    ]
    t = 200.0
    for src, ports in triples:
        for p in ports:
            alerts.extend(ids.inspect_tcp_syn(src, "192.168.1.14", p, now=t))
            t += 2.0
    assert any(a["attack_type"] == "distributed_port_scan" and a["severity"] == "critical" for a in alerts)


def test_RT07_dns_hijacking_detection():
    net = {
        "ssid": "HomeWiFi", "gateway_ip": "192.168.1.1", "gateway_mac": "70:85:C2:44:10:01",
        "encryption_grade": "Strong", "security_protocol": "WPA3",
        "is_public_or_untrusted": False, "vpn_active": False, "dns_servers": ["185.220.101.45"],
    }
    baseline = {"ssid": "HomeWiFi", "gateway_ip": "192.168.1.1", "gateway_mac": "70:85:C2:44:10:01", "dns_servers": "1.1.1.1,192.168.1.1"}
    alerts = evaluate_baseline_and_passive_threats(net, [], set(), set(), baseline=baseline)
    assert any(a["attack_type"] == "dns_hijack" and a["severity"] == "critical" for a in alerts)


def test_RT08_dns_tunneling_encoded_payload():
    ids = LivePacketIDS()
    ids.update_network_context("192.168.1.14", "192.168.1.1", "70:85:C2:44:10:01")
    encoded_q = "4a7f9c12e8b304d1a9f0c7e6b2189a34f5c6d7e8.exfil.attacker.example"
    alerts = ids.inspect_dns_query("192.168.1.94", "B8:27:EB:88:11:09", encoded_q, now=300.0)
    assert any(a["attack_type"] == "dns_tunneling" and a["severity"] == "critical" for a in alerts)


def test_RT09_dga_domain_generation():
    ids = LivePacketIDS()
    alerts = ids.inspect_dns_query("192.168.1.94", "B8:27:EB:88:11:09", "x9k2qz7m4p1w8v3b9c4t.ru", now=310.0)
    assert any(a["attack_type"] == "dga_domain" for a in alerts)
    benign = ids.inspect_dns_query("192.168.1.14", "A4:83:E7:21:9B:04", "github.com", now=311.0)
    assert benign == []


def test_RT10_c2_beaconing_periodic_callbacks():
    ids = LivePacketIDS()
    alerts = []
    # 6 strict 30-second callbacks to external C2 server
    for i in range(6):
        alerts.extend(ids.inspect_outbound_flow("192.168.1.94", "B8:27:EB:88:11:09", "203.0.113.55", 4444, now=1000.0 + i * 30.0))
    assert any(a["attack_type"] == "c2_beacon" and a["severity"] == "critical" for a in alerts)


def test_RT11_cleartext_traffic_ftp_telnet():
    ids = LivePacketIDS()
    ids.update_network_context("192.168.1.14", "192.168.1.1", "70:85:C2:44:10:01")
    ftp_alerts = ids.inspect_tcp_syn("192.168.1.14", "198.51.100.10", 21, now=400.0)
    telnet_alerts = ids.inspect_tcp_syn("192.168.1.14", "198.51.100.11", 23, now=401.0)
    assert any(a["attack_type"] == "cleartext_traffic" for a in ftp_alerts)
    assert any(a["attack_type"] == "cleartext_traffic" for a in telnet_alerts)


def test_RT12_mac_spoofing_identity_change():
    ids = LivePacketIDS()
    ids.update_network_context("192.168.1.14", "192.168.1.1", "70:85:C2:44:10:01")
    # Establish legitimate host first
    assert ids.inspect_arp_event("192.168.1.40", "A4:83:E7:11:22:33", op=2, now=10.0) == []
    # Abrupt MAC flip on same IP -> MAC spoofing alert
    alerts = ids.inspect_arp_event("192.168.1.40", "DE:AD:BE:77:88:99", op=2, now=20.0)
    assert any(a["attack_type"] == "mac_spoof" for a in alerts)


# =====================================================================
# B. ML & BEHAVIORAL TESTING (ML-01 .. ML-08)
# =====================================================================

def _dev(mac, ip, is_safe=True, latency=6, vendor="Apple", name="WorkLaptop"):
    return {
        "mac": mac, "ip": ip, "real_name": name, "display_name": name,
        "vendor": vendor, "name_source": "mdns" if is_safe else "dhcp",
        "is_safe": is_safe, "is_online": True, "is_gateway": False,
        "is_self": False, "latency_ms": latency,
    }


def test_ML01_unknown_device_anomaly():
    eng = BehavioralMLEngine()
    mac = "DE:AD:BE:11:00:01"
    eng.inject_simulated_anomaly(mac, {"syn_fanout_norm": 0.9, "dns_entropy_norm": 0.85})
    rep = eng.evaluate_snapshot([_dev(mac, "192.168.1.99", is_safe=False, latency=160, vendor="Unknown Manufacturer", name="xk9q2z7m")], [], {})
    assert rep["device_scores"][0]["anomaly_score"] >= 70.0


def test_ML02_trusted_device_compromise():
    eng = BehavioralMLEngine()
    mac = "AA:BB:CC:22:00:02"
    # Even though is_safe=True, C2 beaconing + ARP storm must trigger critical risk
    eng.inject_simulated_anomaly(mac, {"beacon_regularity": 0.96, "arp_burst_norm": 0.90})
    rep = eng.evaluate_snapshot([_dev(mac, "192.168.1.10", is_safe=True, latency=10)], [], {})
    assert rep["device_scores"][0]["anomaly_score"] >= 70.0
    assert rep["device_scores"][0]["risk_level"] == "critical"


def test_ML03_slow_behavioral_drift():
    eng = BehavioralMLEngine()
    mac = "AA:BB:CC:33:00:03"
    # Establish normal 10ms baseline
    for _ in range(6):
        eng.evaluate_snapshot([_dev(mac, "192.168.1.11", is_safe=True, latency=10)], [], {})
    # Gradually drift latency upward (+12ms each step)
    last_score = 0.0
    for step in range(1, 14):
        rep = eng.evaluate_snapshot([_dev(mac, "192.168.1.11", is_safe=True, latency=10 + step * 12)], [], {})
        last_score = rep["device_scores"][0]["anomaly_score"]
    assert last_score >= 42.0


def test_ML04_off_hours_anomaly():
    eng = BehavioralMLEngine()
    mac = "AA:BB:CC:44:00:04"
    cur_hr = datetime.now(timezone.utc).hour
    # Simulate device only ever active 12 hours away from current UTC hour
    hist = [0] * 24
    hist[(cur_hr + 12) % 24] = 40
    eng._device_hour_hist[mac] = hist
    rep = eng.evaluate_snapshot([_dev(mac, "192.168.1.12", is_safe=True, latency=8)], [], {})
    factors = [f["feature"] for f in rep["device_scores"][0]["top_factors"]]
    assert "off_hours_score" in factors


def test_ML05_false_positive_resistance_benign_heavy_usage():
    eng = BehavioralMLEngine()
    false_positives = 0
    total = 50
    for i in range(total):
        mac = f"A4:83:E7:00:{i // 10:02X}:{i % 10:02X}"
        rep = eng.evaluate_snapshot(
            [_dev(mac, f"192.168.1.{20 + i}", is_safe=True, latency=12 + (i % 15))],
            [], {}, arp_rates_by_mac={mac: 1}, syn_ports_by_ip={f"192.168.1.{20 + i}": 1},
        )
        if rep["device_scores"][0]["risk_level"] != "normal":
            false_positives += 1
    fp_rate = false_positives / total
    assert fp_rate < 0.02, f"False positive rate too high: {fp_rate:.2%}"


def test_ML06_baseline_poisoning_resistance():
    eng = BehavioralMLEngine()
    mac = "DE:AD:BE:66:00:06"
    before_samples = len(eng._trained_samples)
    eng.inject_simulated_anomaly(mac, {"syn_fanout_norm": 0.92, "arp_burst_norm": 0.85})
    for _ in range(15):
        rep = eng.evaluate_snapshot([_dev(mac, "192.168.1.66", is_safe=True, latency=140)], [], {})
        assert rep["device_scores"][0]["anomaly_score"] >= 70.0
    assert len(eng._trained_samples) == before_samples
    assert eng.poisoning_attempts_blocked >= 15


def test_ML07_feature_evasion_single_malicious_dimension():
    eng = BehavioralMLEngine()
    mac = "AA:BB:CC:77:00:07"
    # Attacker keeps 7 features completely clean, only triggers C2 beacon_regularity
    eng.inject_simulated_anomaly(mac, {"beacon_regularity": 0.95})
    rep = eng.evaluate_snapshot([_dev(mac, "192.168.1.77", is_safe=True, latency=5)], [], {})
    assert rep["device_scores"][0]["anomaly_score"] >= 50.0


def test_ML08_model_retraining_does_not_suppress_future_threats():
    eng = BehavioralMLEngine()
    mac = "AA:BB:CC:88:00:08"
    fb = eng.reinforce_safe_device(mac)
    assert fb["retrained"] is True
    # Later compromise on the exact same MAC must still alert critically
    eng.inject_simulated_anomaly(mac, {"dns_entropy_norm": 0.94, "beacon_regularity": 0.92})
    rep = eng.evaluate_snapshot([_dev(mac, "192.168.1.88", is_safe=True, latency=10)], [], {})
    assert rep["device_scores"][0]["risk_level"] == "critical"


# =====================================================================
# C. PREVENTION / BLUE TEAM TESTING (BT-01 .. BT-07)
# =====================================================================

def test_BT01_firewall_ip_blocking_rule():
    rule, cmd = build_block_ip_command("192.168.1.109", "windows_netsh", unblock=False)
    assert rule == "GARUDA_BLOCK_192_168_1_109" and "action=block" in cmd
    with patch("app.services.firewall_manager.is_admin_or_root", return_value=True),          patch("app.services.firewall_manager.detect_firewall_backend", return_value="linux_ufw"),          patch("app.services.firewall_manager._run", return_value=(0, "Rule inserted", "")):
        res = enforce_block_ip("192.168.1.109", unblock=False)
        assert res["enforced"] is True and "Blocked 192.168.1.109" in res["message"]


def test_BT02_firewall_unblock_rule_removal():
    with patch("app.services.firewall_manager.is_admin_or_root", return_value=True),          patch("app.services.firewall_manager.detect_firewall_backend", return_value="linux_ufw"),          patch("app.services.firewall_manager._run", return_value=(0, "Rule deleted", "")):
        res = enforce_block_ip("192.168.1.109", unblock=True)
        assert res["enforced"] is True and "Unblocked 192.168.1.109" in res["message"]


def test_BT03_emergency_lockdown_enforcement():
    with patch("app.services.firewall_manager.is_admin_or_root", return_value=True),          patch("app.services.firewall_manager.detect_firewall_backend", return_value="windows_netsh"),          patch("app.services.firewall_manager._run", return_value=(0, "Ok.", "")) as mock_run:
        res = enforce_lockdown_mode(True)
        assert res["enforced"] is True and "blockinboundalways" in res["command"]
        assert mock_run.call_count == 2


def test_BT04_arp_gateway_pinning():
    with patch("app.services.ids_engine.is_admin_or_root", return_value=True),          patch("subprocess.run") as mock_sub:
        mock_sub.return_value.returncode = 0
        mock_sub.return_value.stdout = "OK"
        mock_sub.return_value.stderr = ""
        res = pin_static_gateway_arp("192.168.1.1", "70:85:C2:44:10:01", "Wi-Fi")
        assert res["enforced"] is True and "pinned permanently" in res["message"]


def test_BT05_privilege_failure_safe_error():
    with patch("app.services.firewall_manager.is_admin_or_root", return_value=False),          patch("app.services.firewall_manager.detect_firewall_backend", return_value="windows_netsh"):
        res_blk = enforce_block_ip("192.168.1.109", unblock=False)
        res_lck = enforce_lockdown_mode(True)
        assert res_blk["enforced"] is False and "Administrator" in res_blk["message"]
        assert res_lck["enforced"] is False
    # Red-team command-injection IP validation check
    try:
        enforce_block_ip("192.168.1.1; rm -rf /")
        assert False, "Command injection string must raise ValueError"
    except ValueError:
        pass


def test_BT06_firewall_persistence_across_restart():
    logs = [
        {"target_ip": "192.168.1.87", "action": "block", "enforced": True},
        {"target_ip": "192.168.1.99", "action": "block", "enforced": True},
        {"target_ip": "192.168.1.87", "action": "unblock", "enforced": True},
    ]
    assert replay_persisted_blocked_ips(logs) == ["192.168.1.99"]


def test_BT07_recovery_after_lockdown():
    with patch("app.services.firewall_manager.is_admin_or_root", return_value=True),          patch("app.services.firewall_manager.detect_firewall_backend", return_value="windows_netsh"),          patch("app.services.firewall_manager._run", return_value=(0, "Ok.", "")):
        res_on = enforce_lockdown_mode(True)
        res_off = enforce_lockdown_mode(False)
        assert res_on["enforced"] is True and res_off["enforced"] is True
        assert "blockinboundalways" in res_on["command"]
        assert "blockinboundalways" not in res_off["command"]
        assert "restored" in res_off["message"].lower()


# =====================================================================
# D. FORENSIC LEDGER TESTING (FR-01 .. FR-08)
# =====================================================================

def test_FR01_ledger_tampering_detected():
    td, _, eng, Session = _make_temp_db()
    try:
        db = Session()
        append_attestation_block(db, "genesis", "Boot", {"ok": True})
        append_attestation_block(db, "arp_spoof", "MITM detected", {"ip": "192.168.1.1"})
        assert verify_ledger_integrity(db)["valid"] is True
        # Tamper 1 byte in stored payload_json
        blk_cls = sys.modules["app.models"].AttestationBlock
        blk = db.query(blk_cls).filter(blk_cls.block_index == 1).first()
        blk.payload_json = '{"ip":"192.168.1.254"}'
        if hasattr(db, "update_block"):
            db.update_block(blk)
        db.commit()
        ver = verify_ledger_integrity(db)
        assert ver["valid"] is False and "payload_modified" in ver["tampered_blocks"][0]["issues"]
        db.close()
    finally:
        if 'eng' in locals() and eng is not None:
            eng.dispose()
        td.cleanup()


def test_FR02_block_deletion_breaks_chain():
    td, _, eng, Session = _make_temp_db()
    try:
        db = Session()
        for i in range(4):
            append_attestation_block(db, f"evt_{i}", f"Event {i}", {"i": i})
        # Delete middle block #1
        blk_cls = sys.modules["app.models"].AttestationBlock
        db.query(blk_cls).filter(blk_cls.block_index == 1).delete()
        db.commit()
        ver = verify_ledger_integrity(db)
        assert ver["valid"] is False
        issues = {iss for t in ver["tampered_blocks"] for iss in t["issues"]}
        assert "broken_chain_link" in issues or "missing_or_deleted_block_index" in issues
        db.close()
    finally:
        if 'eng' in locals() and eng is not None:
            eng.dispose()
        td.cleanup()


def test_FR03_signature_forgery_rejected():
    td, _, eng, Session = _make_temp_db()
    try:
        db = Session()
        append_attestation_block(db, "genesis", "Boot", {"ok": True})
        blk_cls = sys.modules["app.models"].AttestationBlock
        blk = db.query(blk_cls).first()
        blk.signature_hex = "00" * (len(blk.signature_hex) // 2)
        if hasattr(db, "update_block"):
            db.update_block(blk)
        db.commit()
        ver = verify_ledger_integrity(db)
        assert ver["valid"] is False and "invalid_signature" in ver["tampered_blocks"][0]["issues"]
        db.close()
    finally:
        if 'eng' in locals() and eng is not None:
            eng.dispose()
        td.cleanup()


def test_FR04_merkle_proof_manipulation_rejected():
    td, _, eng, Session = _make_temp_db()
    try:
        db = Session()
        for i in range(5):
            append_attestation_block(db, "alert", f"Incident {i}", {"id": i})
        proof_obj = get_block_merkle_proof(db, 2)
        assert proof_obj["verified_locally"] is True
        # Manipulate first sibling hash in proof
        tampered_proof = list(proof_obj["proof"])
        tampered_proof[0] = {"position": tampered_proof[0]["position"], "hash": "f" * 64}
        assert verify_merkle_proof(proof_obj["leaf_hash"], tampered_proof, proof_obj["merkle_root"]) is False
        db.close()
    finally:
        if 'eng' in locals() and eng is not None:
            eng.dispose()
        td.cleanup()


def test_FR05_duplicate_incident_handling():
    td, _, eng, Session = _make_temp_db()
    try:
        db = Session()
        b1 = append_attestation_block(db, "arp_spoof", "Duplicate test", {"ip": "192.168.1.1"})
        b2 = append_attestation_block(db, "arp_spoof", "Duplicate test", {"ip": "192.168.1.1"})
        assert b1.block_index == 0 and b2.block_index == 1 and b1.block_hash != b2.block_hash
        assert verify_ledger_integrity(db)["valid"] is True
        db.close()
    finally:
        if 'eng' in locals() and eng is not None:
            eng.dispose()
        td.cleanup()


def test_FR06_concurrent_incidents_no_corruption():
    td, _, eng, Session = _make_temp_db()
    try:
        def _worker(idx: int):
            s = Session()
            try:
                append_attestation_block(s, "concurrent_alert", f"Worker {idx}", {"worker": idx})
            finally:
                s.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(_worker, i) for i in range(16)]
            for f in futs:
                f.result()

        db = Session()
        ver = verify_ledger_integrity(db)
        assert ver["valid"] is True and ver["blocks_checked"] == 16
        db.close()
    finally:
        if 'eng' in locals() and eng is not None:
            eng.dispose()
        td.cleanup()


def test_FR07_restart_recovery_persistence():
    td, db_file, engine1, Session1 = _make_temp_db()
    try:
        db1 = Session1()
        for i in range(3):
            append_attestation_block(db1, "persist_test", f"Evt {i}", {"i": i})
        db1.close()
        if engine1 is not None:
            engine1.dispose()

        # Reopen fresh connection simulating full process restart
        if _HAS_SQLALCHEMY:
            engine2 = create_engine(f"sqlite:///{db_file.as_posix()}", connect_args={"check_same_thread": False})
            Session2 = sessionmaker(autocommit=False, autoflush=False, bind=engine2)
            db2 = Session2()
        else:
            engine2 = None
            db2 = _SqliteLedgerSession(db_file)
        ver = verify_ledger_integrity(db2)
        assert ver["valid"] is True and ver["blocks_checked"] == 3
        db2.close()
        if engine2 is not None:
            engine2.dispose()
    finally:
        if 'eng' in locals() and eng is not None:
            eng.dispose()
        td.cleanup()


def test_FR08_onchain_contract_verification():
    sol = (ROOT / "contracts/GarudaAttestation.sol").read_text(encoding="utf-8")
    assert "function anchorRoot(" in sol and "function verifyIncident(" in sol
    leaves = [sha256_hex(f"onchain-{i}".encode()) for i in range(6)]
    root = compute_merkle_root(leaves)
    proof = generate_merkle_proof(leaves, 3)
    assert verify_merkle_proof(leaves[3], proof, root) is True
    assert verify_merkle_proof(sha256_hex(b"forged"), proof, root) is False


# =====================================================================
# E. PURPLE TEAM — ADVANCED ATTACK CAMPAIGNS (PT-01 .. PT-08)
# =====================================================================

def test_PT01_arp_spoof_plus_dns_hijack_correlation():
    now = datetime.now(timezone.utc)
    alerts = [
        {"attack_type": "arp_spoof", "severity": "critical", "category": "active_attack", "related_ip": "192.168.1.1", "related_mac": "DE:AD:BE:01:02:03", "created_at": now.isoformat()},
        {"attack_type": "dns_hijack", "severity": "critical", "category": "active_attack", "related_ip": "185.220.101.45", "related_mac": "DE:AD:BE:01:02:03", "created_at": (now + timedelta(seconds=5)).isoformat()},
    ]
    res = correlate_attack_campaigns(alerts)
    assert any(c["campaign_id"] == "PT-01" for c in res["campaigns"])


def test_PT02_scan_plus_beaconing_kill_chain():
    now = datetime.now(timezone.utc)
    alerts = [
        {"attack_type": "slow_port_scan", "severity": "high", "category": "active_attack", "related_ip": "192.168.1.94", "created_at": now.isoformat()},
        {"attack_type": "c2_beacon", "severity": "critical", "category": "active_attack", "related_ip": "192.168.1.94", "created_at": (now + timedelta(seconds=45)).isoformat()},
    ]
    res = correlate_attack_campaigns(alerts)
    assert any(c["campaign_id"] == "PT-02" for c in res["campaigns"])


def test_PT03_rogue_dhcp_plus_dns_manipulation():
    now = datetime.now(timezone.utc)
    alerts = [
        {"attack_type": "rogue_dhcp", "severity": "critical", "category": "active_attack", "related_ip": "192.168.1.200", "created_at": now.isoformat()},
        {"attack_type": "dns_tunneling", "severity": "critical", "category": "active_attack", "related_ip": "192.168.1.200", "created_at": (now + timedelta(seconds=10)).isoformat()},
    ]
    res = correlate_attack_campaigns(alerts)
    assert any(c["campaign_id"] == "PT-03" for c in res["campaigns"])


def test_PT04_trusted_device_compromise_reassessment():
    now = datetime.now(timezone.utc)
    devices = [{"mac": "A4:83:E7:11:22:33", "ip": "192.168.1.10", "is_safe": True}]
    alerts = [{"attack_type": "c2_beacon", "severity": "critical", "category": "active_attack", "related_mac": "A4:83:E7:11:22:33", "related_ip": "192.168.1.10", "created_at": now.isoformat()}]
    res = correlate_attack_campaigns(alerts, devices=devices)
    assert any(c["campaign_id"] == "PT-04" for c in res["campaigns"])


def test_PT05_multi_device_coordinated_attack():
    now = datetime.now(timezone.utc)
    alerts = [
        {"attack_type": "port_sweep", "severity": "critical", "category": "active_attack", "related_ip": "192.168.1.51", "created_at": now.isoformat()},
        {"attack_type": "arp_spoof", "severity": "critical", "category": "active_attack", "related_ip": "192.168.1.52", "created_at": (now + timedelta(seconds=3)).isoformat()},
    ]
    res = correlate_attack_campaigns(alerts)
    assert any(c["campaign_id"] == "PT-05" for c in res["campaigns"])


def test_PT06_intermittent_attacker_retained_across_sessions():
    t0 = datetime.now(timezone.utc)
    alerts = [
        {"attack_type": "arp_spoof", "severity": "critical", "category": "active_attack", "related_mac": "DE:AD:BE:99:00:01", "created_at": t0.isoformat()},
        {"attack_type": "arp_spoof", "severity": "critical", "category": "active_attack", "related_mac": "DE:AD:BE:99:00:01", "created_at": (t0 + timedelta(minutes=15)).isoformat()},
    ]
    res = correlate_attack_campaigns(alerts)
    assert any(c["campaign_id"] == "PT-06" and c["span_seconds"] >= 600 for c in res["campaigns"])


def test_PT07_attack_followed_by_lockdown_and_ledger_seal():
    td, _, eng, Session = _make_temp_db()
    try:
        db = Session()
        blk = append_attestation_block(db, "ids_arp_spoof", "MITM contained", {"ip": "192.168.1.109"})
        res = correlate_attack_campaigns(
            alerts=[{"attack_type": "arp_spoof", "severity": "critical", "category": "active_attack", "related_ip": "192.168.1.109", "created_at": datetime.now(timezone.utc).isoformat()}],
            firewall_logs=[{"action": "lockdown_on", "enforced": True}],
            ledger_blocks=[{"block_index": blk.block_index, "block_hash": blk.block_hash}],
        )
        assert any(c["campaign_id"] == "PT-07" for c in res["campaigns"])
        assert verify_ledger_integrity(db)["valid"] is True
        db.close()
    finally:
        if 'eng' in locals() and eng is not None:
            eng.dispose()
        td.cleanup()


def test_PT08_repeated_attack_campaign_timeline():
    t0 = datetime.now(timezone.utc)
    alerts = [
        {"attack_type": "c2_beacon", "severity": "critical", "title": "Stage 3 C2", "created_at": (t0 + timedelta(minutes=5)).isoformat()},
        {"attack_type": "port_sweep", "severity": "high", "title": "Stage 1 Recon", "created_at": t0.isoformat()},
        {"attack_type": "arp_spoof", "severity": "critical", "title": "Stage 2 MITM", "created_at": (t0 + timedelta(minutes=2)).isoformat()},
    ]
    res = correlate_attack_campaigns(alerts)
    order = [e["attack_type"] for e in res["timeline"]]
    assert order == ["port_sweep", "arp_spoof", "c2_beacon"]


# =====================================================================
# F. PERFORMANCE & RESILIENCE (PR-01 .. PR-07)
# =====================================================================

def test_PR01_campus_cidr_clamping_to_safe_24():
    safe, clamped = clamp_subnet_to_safe_24("10.12.0.0/16", local_ip="10.12.44.89")
    assert clamped is True and safe == "10.12.44.0/24"


def test_PR02_proxy_arp_shield_zero_false_positives():
    gw_mac = "00:1A:2B:CC:DD:EE"
    arp_table = [("10.12.44.1", gw_mac), ("10.12.44.10", gw_mac), ("10.12.44.11", gw_mac), ("10.12.44.12", gw_mac)]
    assert detect_proxy_arp(arp_table, gateway_mac=gw_mac)["proxy_arp_detected"] is True
    ids = LivePacketIDS()
    ids.update_network_context("10.12.44.89", "10.12.44.1", gw_mac)
    ids.set_proxy_arp_mode(True, proxy_mac=gw_mac)
    for i in range(25):
        assert ids.inspect_arp_event(f"10.12.44.{20 + i}", gw_mac, op=2, now=500.0 + i * 0.05) == []
    assert ids.proxy_arp_suppressed_count == 25


def test_PR03_vpn_auto_skip_and_capability_probe():
    vpn_env = probe_network_environment({"ssid": "HomeWiFi", "subnet_cidr": "192.168.1.0/24", "local_ip": "192.168.1.15", "vpn_active": True, "vpn_interface": "wg0"})
    assert vpn_env["mode"] == "vpn_protected" and vpn_env["allow_active_sweep"] is False


def test_PR04_randomized_mac_ttl_and_port_os_fusion():
    ident = resolve_device_identity(
        ip="10.20.5.77", mac="DA:A1:19:44:55:66", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={}, dhcp_map={}, ttl=64, open_ports=[62078],
    )
    assert ident["is_randomized_mac"] is True and "Apple iOS" in ident["real_name"]


def test_PR05_plugin_orchestrator_fault_and_timeout_isolation():
    orch = PluginOrchestrator(max_workers=3)
    res = orch.run_all([
        DiscoveryPlugin("ok", lambda: {"k": 1}, timeout_sec=1.0),
        DiscoveryPlugin("err", lambda: 1 / 0, timeout_sec=1.0),
        DiscoveryPlugin("slow", lambda: time.sleep(0.4), timeout_sec=0.1),
        DiscoveryPlugin("skip", lambda: None, enabled=False),
    ])
    assert res["ok"].status == "ok" and res["err"].status == "error"
    assert res["slow"].status == "timeout" and res["skip"].status == "skipped"


def test_PR06_hot_reloadable_rules_manifest():
    rule_manager.reload()
    s = rule_manager.summary()
    assert s["schema_version"].startswith("5.") and s["port_signatures_count"] >= 6


def test_PR07_aws_asff_and_vpc_flow_log_throughput():
    asff = to_aws_security_hub_asff({"id": 7, "severity": "critical", "attack_type": "arp_spoof", "title": "MITM", "related_ip": "192.168.1.1"})
    assert asff["SchemaVersion"] == "2018-10-08" and dispatch_aws_finding(asff, dry_run=True)["mode"] == "dry_run_preview"
    t0 = time.perf_counter()
    vpc = parse_vpc_flow_logs(SAMPLE_VPC_FLOW_LOGS)
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    assert vpc["records_parsed"] == 7 and vpc["findings_count"] >= 2 and elapsed_ms < 50.0
