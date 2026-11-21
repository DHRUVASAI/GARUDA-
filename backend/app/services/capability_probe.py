"""GARUDA v5 Startup Capability Probe & Auto-Adapting Environment Guardrails.
Prevents campus Wi-Fi freezes (/16 CIDR explosion), VPN ARP noise, and enterprise Proxy-ARP false positives.
"""

import ipaddress
from typing import Dict, List, Optional, Tuple

from .rule_updater import rule_manager


def clamp_subnet_to_safe_24(subnet_cidr: str, local_ip: Optional[str] = None) -> Tuple[str, bool]:
    """Clamp large enterprise/campus subnets (e.g. /16, /20, /22) to the local /24 neighborhood.
    Returns (safe_cidr, was_clamped).
    """
    try:
        net = ipaddress.ip_network(subnet_cidr, strict=False)
        min_prefix = int(rule_manager.rules.get("max_active_sweep_prefix", 24))
        if net.prefixlen < min_prefix:
            anchor = local_ip if (local_ip and local_ip != "127.0.0.1") else str(net.network_address)
            safe_net = ipaddress.ip_network(f"{anchor}/{min_prefix}", strict=False)
            return str(safe_net), True
        return str(net), False
    except Exception:
        if local_ip and "." in local_ip:
            octets = local_ip.split(".")
            return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24", True
        return "192.168.1.0/24", False


def detect_proxy_arp(arp_entries: List[Tuple[str, str]], gateway_mac: Optional[str] = None) -> Dict[str, object]:
    """Detect enterprise Proxy-ARP where a single router/AP MAC answers for many distinct client IPs."""
    min_shared = int(rule_manager.rules.get("proxy_arp_min_shared_ips", 3))
    mac_to_ips: Dict[str, set] = {}
    for ip, mac in arp_entries:
        m = (mac or "").upper().strip()
        if not m or m in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            continue
        mac_to_ips.setdefault(m, set()).add(ip)

    if not mac_to_ips:
        return {"proxy_arp_detected": False, "proxy_mac": None, "shared_ip_count": 0}

    top_mac, ips = max(mac_to_ips.items(), key=lambda kv: len(kv[1]))
    is_gw_match = bool(gateway_mac and top_mac == gateway_mac.upper())
    detected = len(ips) >= min_shared and (is_gw_match or len(ips) >= min_shared + 2)
    return {
        "proxy_arp_detected": detected,
        "proxy_mac": top_mac if detected else None,
        "shared_ip_count": len(ips) if detected else 0,
    }


def probe_network_environment(net_info: dict, arp_entries: Optional[List[Tuple[str, str]]] = None) -> dict:
    """Evaluate the active network environment and automatically select safe discovery & IDS guardrails."""
    ssid = (net_info.get("ssid") or "").lower()
    subnet = net_info.get("subnet_cidr") or "192.168.1.0/24"
    local_ip = net_info.get("local_ip") or "127.0.0.1"
    gateway_mac = (net_info.get("gateway_mac") or "").upper()
    vpn_active = bool(net_info.get("vpn_active"))
    vpn_iface = net_info.get("vpn_interface")

    safe_cidr, was_clamped = clamp_subnet_to_safe_24(subnet, local_ip)
    proxy_info = detect_proxy_arp(arp_entries or [], gateway_mac=gateway_mac)
    campus_hints = rule_manager.rules.get("campus_ssid_hints", [])
    is_campus_ssid = any(h in ssid for h in campus_hints)
    is_enterprise = is_campus_ssid or was_clamped or proxy_info["proxy_arp_detected"]

    if vpn_active:
        mode = "vpn_protected"
        label = f"VPN Protected ({vpn_iface or 'Encrypted Tunnel'})"
        plain_summary = (
            "An active VPN tunnel is encrypting your traffic. GARUDA automatically skips noisy LAN ARP sweeps "
            "and focuses on host firewall, DNS leak, and behavioral ML checks."
        )
        active_plugins = ["os_arp_cache", "oui_randomized_mac", "ttl_os_fusion", "ml_behavioral", "host_malware"]
        skipped_plugins = ["active_arp_sweep", "mdns_multicast", "ssdp_multicast"]
    elif is_enterprise:
        mode = "campus_safe"
        label = "Campus / Enterprise Safe Mode"
        plain_summary = (
            "Large or managed Wi-Fi detected (multicast filtering / Proxy-ARP likely active). "
            f"GARUDA capped scanning to {safe_cidr}, enabled the Proxy-ARP false-positive shield, "
            "and activated Randomized-MAC + TTL OS fusion."
        )
        active_plugins = ["os_arp_cache", "safe_24_sweep", "oui_randomized_mac", "ttl_os_fusion", "proxy_arp_shield", "ml_behavioral"]
        skipped_plugins = ["full_cidr_sweep"]
    else:
        mode = "home_lan"
        label = "Home / Private LAN Mode"
        plain_summary = (
            "Private local network detected. All 5 discovery layers (mDNS, SSDP, DHCP, NetBIOS/rDNS, OUI+TTL) "
            "and live ARP/IDS sensors are running at full precision."
        )
        active_plugins = ["mdns_multicast", "ssdp_multicast", "dhcp_passive", "netbios_rdns", "oui_randomized_mac", "ttl_os_fusion", "ml_behavioral"]
        skipped_plugins = []

    return {
        "mode": mode,
        "label": label,
        "plain_summary": plain_summary,
        "original_cidr": subnet,
        "effective_cidr": safe_cidr,
        "cidr_clamped": was_clamped,
        "vpn_active": vpn_active,
        "vpn_interface": vpn_iface,
        "proxy_arp_detected": proxy_info["proxy_arp_detected"],
        "proxy_arp_shared_ips": proxy_info["shared_ip_count"],
        "allow_active_sweep": not vpn_active,
        "active_plugins": active_plugins,
        "skipped_plugins": skipped_plugins,
        "rules_version": rule_manager.rules.get("schema_version", "5.0.0"),
    }
