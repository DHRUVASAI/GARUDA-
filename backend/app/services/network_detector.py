"""Cross-platform Network Environment Detector (Windows 10/11, Linux, macOS).
Honest SSID reporting: never fakes 'Wired Ethernet' when Windows 11 Location Privacy blocks SSID access.
Detects SSID, BSSID, Wi-Fi Cipher/Protocol, Signal %, Gateway IP/MAC, DNS servers, and Active VPN tunnel.
"""

import ipaddress
import os
import platform
import re
import socket
import subprocess
from typing import List, Optional, Tuple

PUBLIC_WIFI_HINTS = (
    "guest", "free", "public", "cafe", "coffee", "airport", "hotel", "mall",
    "starbucks", "railwire", "station", "metro", "lounge", "open", "visitor"
)
HOTSPOT_HINTS = ("iphone", "androidap", "pixel", "galaxy", "hotspot", "oneplus", "redmi", "realme", "jiofi", "vivo", "oppo")
CORP_HINTS = ("corp", "enterprise", "office", "campus", "university", "klu", "eduroam", "staff")
VPN_IFACE_HINTS = ("tun", "tap", "wg", "wireguard", "tailscale", "utun", "nordlynx", "proton", "cloudflare", "warp", "mullvad", "openvpn", "zt")


def _run_cmd(cmd: List[str], timeout: float = 3.5) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return res.stdout or ""
    except Exception:
        return ""


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        s.connect(("1.1.1.1", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def normalize_mac(mac: str) -> str:
    if not mac:
        return "00:00:00:00:00:00"
    parts = [p.zfill(2) for p in mac.strip().upper().replace("-", ":").split(":") if p]
    return ":".join(parts) if len(parts) == 6 else mac.strip().upper().replace("-", ":")


def detect_active_vpn() -> Tuple[bool, Optional[str]]:
    """Check if a local VPN tunnel interface (WireGuard, OpenVPN, WARP, Tailscale, Proton) is active."""
    try:
        import psutil  # type: ignore
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for iface, st in stats.items():
            if not st.isup:
                continue
            low = iface.lower()
            if any(h in low for h in VPN_IFACE_HINTS):
                # Ensure interface has an IPv4/IPv6 address assigned
                if addrs.get(iface):
                    return True, iface
    except Exception:
        pass
    return False, None


def _classify_network(ssid: str, medium: str, protocol: str, permission_warn: Optional[str]) -> Tuple[str, str, bool, str]:
    proto_low = (protocol or "").lower()
    ssid_low = (ssid or "").lower()

    if medium == "Ethernet":
        return (
            "Wired Private Network (Ethernet)",
            "Strong",
            False,
            "Connected via a physical Ethernet cable. Wireless eavesdroppers outside the building cannot passively intercept this link.",
        )

    if "open" in proto_low or "none" in proto_low:
        return (
            "Public / Open Wi-Fi (Unencrypted)",
            "None",
            True,
            "This Wi-Fi has NO password encryption. Anyone nearby can passively observe unencrypted traffic without leaving a trace.",
        )

    if "wep" in proto_low or "tkip" in proto_low:
        return (
            "Outdated Wi-Fi (Weak Encryption)",
            "Weak",
            True,
            f"This Wi-Fi uses outdated encryption ({protocol}) that attackers can crack passively.",
        )

    if "wpa3" in proto_low:
        grade = "Strong"
    elif "wpa2" in proto_low:
        grade = "Good"
    elif "wpa" in proto_low:
        grade = "Weak"
    else:
        grade = "Good"

    if any(h in ssid_low for h in HOTSPOT_HINTS):
        net_type = "Personal Mobile Hotspot"
        untrusted = False
        summary = f"Connected to a personal mobile hotspot ({protocol}). Private to devices that have your hotspot password."
    elif any(h in ssid_low for h in PUBLIC_WIFI_HINTS):
        net_type = "Shared / Public Wi-Fi"
        untrusted = True
        summary = f"Connected to a shared or public Wi-Fi ({protocol}). Strangers sharing this router can attempt probing or interception."
    elif any(h in ssid_low for h in CORP_HINTS) or "enterprise" in proto_low or "802.1x" in proto_low:
        net_type = "Campus / Office Shared Wi-Fi"
        untrusted = False
        summary = f"Connected to an office or campus Wi-Fi ({protocol}). Encryption is active, though many devices share the network."
    else:
        net_type = "Home / Private Wi-Fi"
        untrusted = False
        summary = f"Connected to a private Wi-Fi network protected by {protocol}."

    if permission_warn:
        summary += f" ({permission_warn})"
    return net_type, grade, untrusted, summary


def _detect_windows() -> dict:
    ssid = ""
    bssid = None
    protocol = "Unknown"
    cipher = None
    signal_pct = None
    medium = "Wi-Fi"
    interface_name = "Wi-Fi"
    gateway_ip = ""
    gateway_mac = "00:00:00:00:00:00"
    dns_servers: List[str] = []
    perm_warning = None

    wlan_out = _run_cmd(["netsh", "wlan", "show", "interfaces"])
    wlan_lower = wlan_out.lower()

    if "location" in wlan_lower and "permission" in wlan_lower:
        perm_warning = "Windows Location permission is off — enable Settings > Privacy & Security > Location to read exact Wi-Fi SSID."

    is_wifi_connected = ("state" in wlan_lower and "connected" in wlan_lower and "disconnected" not in wlan_lower)

    if is_wifi_connected:
        medium = "Wi-Fi"
        m_name = re.search(r"^\s*Name\s*:\s*(.+)$", wlan_out, re.MULTILINE)
        m_ssid = re.search(r"^\s*SSID\s*:\s*(.+)$", wlan_out, re.MULTILINE)
        m_bssid = re.search(r"^\s*(?:AP\s+)?BSSID\s*:\s*([0-9a-fA-F:]{17})", wlan_out, re.MULTILINE)
        m_auth = re.search(r"^\s*Authentication\s*:\s*(.+)$", wlan_out, re.MULTILINE)
        m_ciph = re.search(r"^\s*Cipher\s*:\s*(.+)$", wlan_out, re.MULTILINE)
        m_sig = re.search(r"^\s*Signal\s*:\s*(\d+)%", wlan_out, re.MULTILINE)
        if m_name:
            interface_name = m_name.group(1).strip()
        if m_ssid:
            ssid = m_ssid.group(1).strip()
        if m_bssid:
            bssid = normalize_mac(m_bssid.group(1))
        if m_auth:
            protocol = m_auth.group(1).strip()
        if m_ciph:
            cipher = m_ciph.group(1).strip()
        if m_sig:
            signal_pct = int(m_sig.group(1))

    # Fallback: PowerShell Get-NetConnectionProfile often returns the real Network Name even when Windows 11 blocks netsh SSID!
    if not ssid:
        ps_out = _run_cmd([
            "powershell", "-NoProfile", "-Command",
            "Get-NetConnectionProfile | Select-Object -First 1 Name,InterfaceAlias | ConvertTo-Json"
        ], timeout=4.0)
        if ps_out.strip().startswith("{"):
            import json
            try:
                obj = json.loads(ps_out)
                name_val = (obj.get("Name") or "").strip()
                alias_val = (obj.get("InterfaceAlias") or "").strip()
                if alias_val:
                    interface_name = alias_val
                if name_val and name_val.lower() not in ("unidentified network", "network"):
                    ssid = name_val
                if "wi-fi" in alias_val.lower() or "wlan" in alias_val.lower() or "wireless" in alias_val.lower():
                    medium = "Wi-Fi"
                elif not is_wifi_connected:
                    medium = "Ethernet"
                    protocol = "Wired Ethernet"
            except Exception:
                pass

    if not ssid:
        if is_wifi_connected or "wi-fi" in interface_name.lower():
            medium = "Wi-Fi"
            ssid = "Wi-Fi Connected (Enable OS Location to read exact SSID)"
            perm_warning = perm_warning or "Windows blocked SSID reading. Enable Location Access or run as Administrator."
        else:
            medium = "Ethernet"
            ssid = f"Wired Ethernet ({interface_name})"
            protocol = "Wired Ethernet"

    ipcfg = _run_cmd(["ipconfig", "/all"])
    m_gw = re.search(r"Default Gateway[ .]*:\s*(\d+\.\d+\.\d+\.\d+)", ipcfg)
    if m_gw:
        gateway_ip = m_gw.group(1).strip()

    for m_dns in re.finditer(r"DNS Servers[ .]*:\s*(\d+\.\d+\.\d+\.\d+)", ipcfg):
        ip = m_dns.group(1).strip()
        if ip not in dns_servers:
            dns_servers.append(ip)

    if gateway_ip:
        arp_out = _run_cmd(["arp", "-a", gateway_ip])
        m_mac = re.search(r"([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}", arp_out)
        if m_mac:
            gateway_mac = normalize_mac(m_mac.group(0))

    return {
        "ssid": ssid, "bssid": bssid, "ssid_permission_warning": perm_warning,
        "medium": medium, "protocol": protocol, "cipher": cipher, "signal_percent": signal_pct,
        "interface_name": interface_name, "gateway_ip": gateway_ip, "gateway_mac": gateway_mac,
        "dns_servers": dns_servers,
    }


def _detect_linux() -> dict:
    ssid = ""
    bssid = None
    protocol = "WPA2/WPA3-Personal"
    cipher = None
    signal_pct = None
    medium = "Ethernet"
    interface_name = "eth0"
    gateway_ip = ""
    gateway_mac = "00:00:00:00:00:00"
    dns_servers: List[str] = []
    perm_warning = None

    route_out = _run_cmd(["ip", "route", "show", "default"])
    m_route = re.search(r"default via (\d+\.\d+\.\d+\.\d+) dev (\S+)", route_out)
    if m_route:
        gateway_ip = m_route.group(1)
        interface_name = m_route.group(2)

    is_wireless = os.path.isdir(f"/sys/class/net/{interface_name}/wireless") or interface_name.startswith(("wl", "wifi"))

    # 1. nmcli (most accurate on desktop Ubuntu/Fedora)
    nm_out = _run_cmd(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SECURITY,SIGNAL", "dev", "wifi"])
    for line in nm_out.splitlines():
        if line.startswith("yes:"):
            # BSSID colons are escaped as \: in nmcli -t
            unesc = line.replace("\:", "__COLON__")
            parts = [p.replace("__COLON__", ":") for p in unesc.split(":")]
            if len(parts) >= 4:
                ssid = parts[1].strip() or ssid
                bssid = normalize_mac(parts[2]) if len(parts[2]) >= 17 else None
                sec = parts[3].strip()
                protocol = "Open (Unencrypted)" if sec in ("", "--", "none") else sec
                if len(parts) >= 5 and parts[4].isdigit():
                    signal_pct = int(parts[4])
                medium = "Wi-Fi"
                break

    # 2. iw dev <iface> link fallback
    if not ssid and is_wireless:
        iw_out = _run_cmd(["iw", "dev", interface_name, "link"])
        m_s = re.search(r"SSID:\s*(.+)", iw_out)
        m_b = re.search(r"Connected to\s+([0-9a-fA-F:]{17})", iw_out)
        if m_s:
            ssid = m_s.group(1).strip()
            medium = "Wi-Fi"
        if m_b:
            bssid = normalize_mac(m_b.group(1))

    # 3. iwgetid fallback
    if not ssid and is_wireless:
        iwg = _run_cmd(["iwgetid", "-r"]).strip()
        if iwg:
            ssid = iwg
            medium = "Wi-Fi"

    if not ssid:
        if is_wireless:
            medium = "Wi-Fi"
            ssid = f"Wi-Fi Interface ({interface_name})"
            perm_warning = "Install network-manager (nmcli) or iw to display exact Linux Wi-Fi SSID."
        else:
            medium = "Ethernet"
            ssid = f"Wired Ethernet ({interface_name})"
            protocol = "Wired Ethernet"

    if gateway_ip:
        neigh = _run_cmd(["ip", "neigh", "show", gateway_ip])
        m_mac = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", neigh)
        if m_mac:
            gateway_mac = normalize_mac(m_mac.group(1))

    try:
        with open("/etc/resolv.conf", "r", encoding="utf-8") as f:
            for line in f:
                if line.strip().startswith("nameserver"):
                    parts = line.strip().split()
                    if len(parts) >= 2 and parts[1] not in dns_servers:
                        dns_servers.append(parts[1])
    except Exception:
        pass

    return {
        "ssid": ssid, "bssid": bssid, "ssid_permission_warning": perm_warning,
        "medium": medium, "protocol": protocol, "cipher": cipher, "signal_percent": signal_pct,
        "interface_name": interface_name, "gateway_ip": gateway_ip, "gateway_mac": gateway_mac,
        "dns_servers": dns_servers,
    }


def _detect_macos() -> dict:
    ssid = ""
    bssid = None
    protocol = "WPA2/WPA3-Personal"
    medium = "Wi-Fi"
    interface_name = "en0"
    gateway_ip = ""
    gateway_mac = "00:00:00:00:00:00"
    dns_servers: List[str] = []
    perm_warning = None

    route_out = _run_cmd(["route", "-n", "get", "default"])
    m_gw = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", route_out)
    m_if = re.search(r"interface:\s*(\S+)", route_out)
    if m_gw:
        gateway_ip = m_gw.group(1)
    if m_if:
        interface_name = m_if.group(1)

    wifi_out = _run_cmd(["networksetup", "-getairportnetwork", interface_name])
    if "Current Wi-Fi Network:" in wifi_out:
        ssid = wifi_out.split("Current Wi-Fi Network:", 1)[1].strip()
        medium = "Wi-Fi"
    else:
        summary = _run_cmd(["ipconfig", "getsummary", interface_name])
        m_ss = re.search(r"SSID\s*:\s*(.+)", summary)
        if m_ss:
            ssid = m_ss.group(1).strip()
            medium = "Wi-Fi"
            if "<redacted>" in ssid.lower():
                perm_warning = "macOS redacted the Wi-Fi SSID due to Location Privacy permissions."
        else:
            medium = "Ethernet"
            ssid = f"Wired Ethernet ({interface_name})"
            protocol = "Wired Ethernet"

    if gateway_ip:
        arp_out = _run_cmd(["arp", "-n", gateway_ip])
        m_mac = re.search(r"([0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2}", arp_out)
        if m_mac:
            gateway_mac = normalize_mac(m_mac.group(0))

    scutil = _run_cmd(["scutil", "--dns"])
    for m_dns in re.finditer(r"nameserver\[\d+\]\s*:\s*(\d+\.\d+\.\d+\.\d+)", scutil):
        ip = m_dns.group(1)
        if ip not in dns_servers:
            dns_servers.append(ip)

    return {
        "ssid": ssid or f"Network ({interface_name})", "bssid": bssid, "ssid_permission_warning": perm_warning,
        "medium": medium, "protocol": protocol, "cipher": None, "signal_percent": None,
        "interface_name": interface_name, "gateway_ip": gateway_ip, "gateway_mac": gateway_mac,
        "dns_servers": dns_servers[:4],
    }


def detect_network_environment() -> dict:
    """Inspect the real local OS network interface and return a structured plain-English profile."""
    local_ip = get_local_ip()
    sys_name = platform.system().lower()
    if sys_name == "windows":
        raw = _detect_windows()
    elif sys_name == "darwin":
        raw = _detect_macos()
    else:
        raw = _detect_linux()

    gateway_ip = raw["gateway_ip"]
    if not gateway_ip and local_ip != "127.0.0.1":
        parts = local_ip.split(".")
        if len(parts) == 4:
            gateway_ip = f"{parts[0]}.{parts[1]}.{parts[2]}.1"

    try:
        subnet = str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    except Exception:
        subnet = "192.168.1.0/24"

    vpn_active, vpn_iface = detect_active_vpn()
    net_type, enc_grade, is_public, plain_summary = _classify_network(
        raw["ssid"], raw["medium"], raw["protocol"], raw["ssid_permission_warning"]
    )

    dns_list = raw["dns_servers"] or ([gateway_ip] if gateway_ip else ["1.1.1.1"])

    return {
        "ssid": raw["ssid"],
        "bssid": raw["bssid"],
        "ssid_permission_warning": raw["ssid_permission_warning"],
        "connection_medium": raw["medium"],
        "network_type": net_type,
        "security_protocol": raw["protocol"],
        "cipher": raw["cipher"],
        "signal_percent": raw["signal_percent"],
        "encryption_grade": enc_grade,
        "local_ip": local_ip,
        "gateway_ip": gateway_ip or "192.168.1.1",
        "gateway_mac": raw["gateway_mac"],
        "subnet_cidr": subnet,
        "dns_servers": dns_list[:4],
        "interface_name": raw["interface_name"],
        "vpn_active": vpn_active,
        "vpn_interface": vpn_iface,
        "is_public_or_untrusted": is_public,
        "arp_pinned": False,
        "plain_summary": plain_summary,
    }
