import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.capability_probe import clamp_subnet_to_safe_24, detect_proxy_arp, probe_network_environment
from app.services.plugin_engine import DiscoveryPlugin, PluginOrchestrator
from app.services.rule_updater import rule_manager
from app.services.device_scanner import resolve_device_identity
from app.services.ids_engine import LivePacketIDS
from app.services.aws_bridge import SAMPLE_VPC_FLOW_LOGS, parse_vpc_flow_logs, to_aws_security_hub_asff, dispatch_aws_finding


def test_v5_campus_cidr_clamping_to_safe_24():
    safe, clamped = clamp_subnet_to_safe_24("10.12.0.0/16", local_ip="10.12.44.89")
    assert clamped is True and safe == "10.12.44.0/24"
    home, clamped_home = clamp_subnet_to_safe_24("192.168.1.0/24", local_ip="192.168.1.14")
    assert clamped_home is False and home == "192.168.1.0/24"


def test_v5_proxy_arp_detection_and_ids_false_positive_shield():
    gw_mac = "00:1A:2B:CC:DD:EE"
    arp_table = [
        ("10.12.44.1", gw_mac),
        ("10.12.44.10", gw_mac),
        ("10.12.44.11", gw_mac),
        ("10.12.44.12", gw_mac),
    ]
    res = detect_proxy_arp(arp_table, gateway_mac=gw_mac)
    assert res["proxy_arp_detected"] is True and res["shared_ip_count"] == 4

    ids = LivePacketIDS()
    ids.update_network_context("10.12.44.89", "10.12.44.1", gw_mac)
    ids.set_proxy_arp_mode(True, proxy_mac=gw_mac)
    # Burst of legitimate Proxy-ARP replies from gateway MAC for other student IPs must NOT fire false-positive arp_storm
    for i in range(20):
        alerts = ids.inspect_arp_event(f"10.12.44.{20 + i}", gw_mac, op=2, now=500.0 + i * 0.05)
        assert alerts == []
    assert ids.proxy_arp_suppressed_count == 20
    # Real attacker spoofing gateway IP with a rogue MAC MUST still trigger critical arp_spoof
    real_attack = ids.inspect_arp_event("10.12.44.1", "DE:AD:BE:11:22:33", op=2, now=502.0)
    assert any(a["attack_type"] == "arp_spoof" and a["severity"] == "critical" for a in real_attack)


def test_v5_vpn_auto_skip_and_campus_probe_modes():
    vpn_env = probe_network_environment({"ssid": "HomeWiFi", "subnet_cidr": "192.168.1.0/24", "local_ip": "192.168.1.15", "vpn_active": True, "vpn_interface": "wg0"})
    assert vpn_env["mode"] == "vpn_protected" and vpn_env["allow_active_sweep"] is False

    campus_env = probe_network_environment({"ssid": "KLU_Campus_WiFi", "subnet_cidr": "10.20.0.0/16", "local_ip": "10.20.5.42", "vpn_active": False})
    assert campus_env["mode"] == "campus_safe" and campus_env["cidr_clamped"] is True and campus_env["effective_cidr"] == "10.20.5.0/24"


def test_v5_randomized_mac_ttl_and_port_os_fusion():
    ident_ios = resolve_device_identity(
        ip="10.20.5.77", mac="DA:A1:19:44:55:66", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={}, dhcp_map={}, ttl=64, open_ports=[62078],
    )
    assert ident_ios["is_randomized_mac"] is True
    assert ident_ios["device_type"] == "phone"
    assert "Apple iOS" in ident_ios["real_name"]
    assert ident_ios["name_source"] == "port_ttl_fusion"

    ident_win = resolve_device_identity(
        ip="10.20.5.88", mac="EA:B2:29:44:55:66", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={}, dhcp_map={}, ttl=128, open_ports=[],
    )
    assert "Windows" in ident_win["real_name"]


def test_v5_plugin_orchestrator_timeout_and_error_isolation():
    orch = PluginOrchestrator(max_workers=3)

    def _fast():
        return {"192.168.1.5": ("MacBook", "mdns")}

    def _crash():
        raise RuntimeError("Multicast blocked by AP")

    def _slow():
        time.sleep(0.6)
        return {"late": True}

    res = orch.run_all([
        DiscoveryPlugin("fast_ok", _fast, timeout_sec=1.0),
        DiscoveryPlugin("crashing", _crash, timeout_sec=1.0),
        DiscoveryPlugin("blocked_slow", _slow, timeout_sec=0.12),
        DiscoveryPlugin("disabled", _fast, enabled=False),
    ])
    assert res["fast_ok"].status == "ok" and "192.168.1.5" in res["fast_ok"].data
    assert res["crashing"].status == "error"
    assert res["blocked_slow"].status == "timeout"
    assert res["disabled"].status == "skipped"


def test_v5_hot_reloadable_rules_manifest():
    rule_manager.reload()
    summary = rule_manager.summary()
    assert summary["schema_version"].startswith("5.")
    assert summary["port_signatures_count"] >= 6
    assert summary["max_active_sweep_prefix"] == 24


def test_v5_aws_security_hub_asff_and_vpc_flow_log_analysis():
    asff = to_aws_security_hub_asff({
        "id": 42,
        "severity": "critical",
        "category": "active_attack",
        "attack_type": "arp_spoof",
        "title": "Gateway ARP Spoof",
        "plain_explanation": "Rogue MAC impersonated gateway.",
        "what_to_do": "Pin gateway ARP.",
        "related_ip": "192.168.1.1",
        "related_mac": "DE:AD:BE:00:11:22",
    })
    assert asff["SchemaVersion"] == "2018-10-08"
    assert asff["Severity"]["Label"] == "CRITICAL"
    preview = dispatch_aws_finding(asff, dry_run=True)
    assert preview["mode"] == "dry_run_preview"

    vpc = parse_vpc_flow_logs(SAMPLE_VPC_FLOW_LOGS)
    assert vpc["records_parsed"] == 7
    attack_types = {f["attack_type"] for f in vpc["findings"]}
    assert "vpc_rejected_port_sweep" in attack_types
    assert "vpc_suspicious_egress" in attack_types
