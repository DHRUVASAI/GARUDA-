"""GARUDA v3 Real Cross-Platform OS Firewall Controller.
- Windows: Audits & enforces Windows Defender Firewall via `netsh advfirewall`.
- Linux: Audits & enforces `ufw`, `nftables`, or `iptables`.
- macOS: Audits `socketfilterfw` (Application Firewall).
- Audits open listening ports on the local host in plain English.
- Strictly honest about elevation: never fakes enforcement if not Admin/root.
"""

import ipaddress
import platform
import re
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple

from ..config import LATERAL_SPREAD_PORTS, is_admin_or_root

PORT_EXPLANATIONS = {
    21: ("high", "Unencrypted FTP file server exposed"),
    22: ("medium", "SSH remote login port open"),
    23: ("high", "Insecure Telnet remote shell open"),
    80: ("low", "Local HTTP web server"),
    135: ("medium", "Windows RPC service"),
    139: ("medium", "NetBIOS file sharing port"),
    445: ("high", "SMB file sharing open — target for network worms on public Wi-Fi"),
    3306: ("medium", "MySQL database port listening"),
    3389: ("high", "Remote Desktop (RDP) open — disable on untrusted Wi-Fi"),
    5432: ("medium", "PostgreSQL database port listening"),
    5900: ("high", "VNC screen sharing open"),
    8000: ("low", "Local web app / GARUDA server"),
    8080: ("low", "Local web proxy / dev server"),
}


def _run(cmd: List[str], timeout: float = 4.0) -> Tuple[int, str, str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return res.returncode, (res.stdout or ""), (res.stderr or "")
    except Exception as exc:
        return 1, "", str(exc)


def detect_firewall_backend() -> str:
    sys_name = platform.system().lower()
    if sys_name == "windows":
        return "windows_netsh"
    if sys_name == "darwin":
        return "macos_pf"
    if shutil.which("ufw"):
        return "linux_ufw"
    if shutil.which("nft"):
        return "linux_nft"
    if shutil.which("iptables"):
        return "linux_iptables"
    return "unavailable"


def list_listening_ports() -> List[dict]:
    """List local listening TCP ports in plain English so users know what their PC exposes to the Wi-Fi."""
    ports: List[dict] = []
    seen = set()
    try:
        import psutil  # type: ignore
        for conn in psutil.net_connections(kind="tcp"):
            if conn.status != "LISTEN" or not conn.laddr:
                continue
            ip = conn.laddr.ip
            port = conn.laddr.port
            # Skip strictly loopback services (safe from network peers)
            if ip in ("127.0.0.1", "::1"):
                continue
            key = (port, ip)
            if key in seen:
                continue
            seen.add(key)
            pname = "System Service"
            if conn.pid:
                try:
                    pname = psutil.Process(conn.pid).name()
                except Exception:
                    pass
            risk, note = PORT_EXPLANATIONS.get(
                port,
                ("high" if port in LATERAL_SPREAD_PORTS else "low", f"Listening service ({pname}) reachable on LAN"),
            )
            ports.append({
                "port": port,
                "protocol": "TCP",
                "process_name": pname,
                "bind_address": ip,
                "risk_level": risk,
                "plain_note": note,
            })
    except Exception:
        pass
    ports.sort(key=lambda x: (0 if x["risk_level"] == "high" else 1 if x["risk_level"] == "medium" else 2, x["port"]))
    return ports[:25]


def get_firewall_status(blocked_ips: Optional[List[str]] = None, lockdown_active: bool = False) -> dict:
    """Inspect real OS firewall status across Windows, Linux, and macOS."""
    backend = detect_firewall_backend()
    can_enforce = is_admin_or_root() and backend != "unavailable"
    profiles: Dict[str, str] = {}
    enabled = False
    privilege_note = None if can_enforce else (
        "Running in Read-Only Audit Mode. Start GARUDA as Administrator (Windows) or with sudo (Linux/macOS) to activate 1-click IP blocking and Lockdown Mode."
    )

    if backend == "windows_netsh":
        rc, out, _ = _run(["netsh", "advfirewall", "show", "allprofiles"])
        current_prof = None
        for line in out.splitlines():
            m_prof = re.match(r"^(Domain|Private|Public)\s+Profile\s+Settings", line.strip(), re.IGNORECASE)
            if m_prof:
                current_prof = m_prof.group(1).title()
            m_state = re.match(r"^State\s+(ON|OFF)", line.strip(), re.IGNORECASE)
            if m_state and current_prof:
                profiles[current_prof] = m_state.group(1).upper()
        enabled = any(v == "ON" for v in profiles.values())
    elif backend == "linux_ufw":
        rc, out, _ = _run(["ufw", "status"])
        if "status: active" in out.lower():
            enabled = True
            profiles["UFW"] = "ON"
        elif "status: inactive" in out.lower():
            enabled = False
            profiles["UFW"] = "OFF"
        else:
            profiles["UFW"] = "NEEDS_SUDO"
    elif backend == "linux_nft":
        rc, out, _ = _run(["nft", "list", "tables"])
        enabled = rc == 0 and bool(out.strip())
        profiles["nftables"] = "ON" if enabled else ("OFF" if rc == 0 else "NEEDS_SUDO")
    elif backend == "linux_iptables":
        rc, out, _ = _run(["iptables", "-L", "-n"])
        enabled = rc == 0 and ("DROP" in out or "REJECT" in out)
        profiles["iptables"] = "ON" if enabled else ("DEFAULT_ACCEPT" if rc == 0 else "NEEDS_SUDO")
    elif backend == "macos_pf":
        rc, out, _ = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        enabled = "enabled" in out.lower()
        profiles["macOS Firewall"] = "ON" if enabled else "OFF"
    else:
        profiles["System Firewall"] = "NOT_FOUND"

    listening = list_listening_ports()
    high_risk_ports = sum(1 for p in listening if p["risk_level"] == "high")

    if enabled:
        summary = f"OS Firewall ({backend}) is ACTIVE."
        if high_risk_ports:
            summary += f" {high_risk_ports} high-risk service port(s) are exposed to the local network."
    else:
        summary = "Your system firewall appears OFF or unverified. Enable it before using shared or public Wi-Fi."

    return {
        "backend": backend,
        "enabled": enabled,
        "profiles": profiles,
        "can_enforce": can_enforce,
        "lockdown_active": lockdown_active,
        "blocked_ips": blocked_ips or [],
        "listening_ports": listening,
        "plain_summary": summary,
        "privilege_note": privilege_note,
    }


def _validate_ip(ip: str) -> str:
    obj = ipaddress.ip_address(ip.strip())
    return str(obj)


def build_block_ip_command(ip: str, backend: str, unblock: bool = False) -> Tuple[str, List[str]]:
    clean_ip = _validate_ip(ip)
    rule_name = f"GARUDA_BLOCK_{clean_ip.replace('.', '_').replace(':', '_')}"
    if backend == "windows_netsh":
        if unblock:
            return rule_name, ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]
        return rule_name, [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block", f"remoteip={clean_ip}",
        ]
    if backend == "linux_ufw":
        if unblock:
            return rule_name, ["ufw", "delete", "deny", "from", clean_ip]
        return rule_name, ["ufw", "insert", "1", "deny", "from", clean_ip, "to", "any"]
    if backend == "linux_iptables":
        flag = "-D" if unblock else "-I"
        return rule_name, ["iptables", flag, "INPUT", "-s", clean_ip, "-j", "DROP"]
    if backend == "linux_nft":
        return rule_name, ["nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", clean_ip, "drop"]
    return rule_name, []


def enforce_block_ip(ip: str, unblock: bool = False) -> dict:
    """Block or unblock a malicious IP in the real OS firewall (with strict IP validation)."""
    clean_ip = _validate_ip(ip)
    backend = detect_firewall_backend()
    rule_name, cmd = build_block_ip_command(clean_ip, backend, unblock=unblock)
    cmd_str = " ".join(cmd)

    if not cmd:
        return {"enforced": False, "rule_name": rule_name, "command": "", "message": f"No supported firewall CLI found ({backend})."}

    if not is_admin_or_root():
        return {
            "enforced": False,
            "rule_name": rule_name,
            "command": cmd_str,
            "message": f"Administrator/sudo rights required to {'unblock' if unblock else 'block'} {clean_ip}. Run elevated or execute: {cmd_str}",
        }

    rc, out, err = _run(cmd)
    ok = rc == 0
    return {
        "enforced": ok,
        "rule_name": rule_name,
        "command": cmd_str,
        "message": (
            f"{'Unblocked' if unblock else 'Blocked'} {clean_ip} in OS firewall ({backend})."
            if ok else (err.strip() or out.strip() or "OS firewall command failed.")
        ),
    }


def enforce_lockdown_mode(enable: bool) -> dict:
    """1-Click Public Wi-Fi Lockdown: blocks all unsolicited inbound connections."""
    backend = detect_firewall_backend()
    if backend == "windows_netsh":
        policy = "blockinboundalways,allowoutbound" if enable else "blockinbound,allowoutbound"
        cmd = ["netsh", "advfirewall", "set", "publicprofile", "state", "on"]
        cmd2 = ["netsh", "advfirewall", "set", "publicprofile", "firewallpolicy", policy]
        cmd_str = f"{' '.join(cmd)} && {' '.join(cmd2)}"
        if not is_admin_or_root():
            return {"enforced": False, "command": cmd_str, "message": "Run GARUDA as Administrator to toggle Windows Firewall Lockdown."}
        rc1, _, e1 = _run(cmd)
        rc2, _, e2 = _run(cmd2)
        ok = (rc1 == 0 and rc2 == 0)
        msg = "Public Wi-Fi Firewall Lockdown ACTIVE." if enable else "Public Wi-Fi Firewall Lockdown DISABLED (standard policy restored)."
        return {"enforced": ok, "command": cmd_str, "message": msg if ok else (e1 or e2)}

    if backend == "linux_ufw":
        cmd = ["ufw", "default", "deny", "incoming"] if enable else ["ufw", "default", "allow", "routed"]
        cmd_str = " ".join(cmd)
        if not is_admin_or_root():
            return {"enforced": False, "command": cmd_str, "message": "Run GARUDA with sudo to toggle UFW Lockdown."}
        rc, _, err = _run(cmd)
        if enable and rc == 0:
            _run(["ufw", "--force", "enable"])
        msg = "Linux UFW Inbound Lockdown ACTIVE." if enable else "Linux UFW Lockdown DISABLED (connectivity restored)."
        return {"enforced": rc == 0, "command": cmd_str, "message": msg if rc == 0 else err}

    return {"enforced": False, "command": "", "message": f"1-Click Lockdown not supported on backend '{backend}'."}


def replay_persisted_blocked_ips(rule_logs: List[dict]) -> List[str]:
    """Reconstruct active blocked IP state from persisted SQLite FirewallRuleLog rows across restarts (BT-06)."""
    blocked = set()
    for row in rule_logs:
        action = row.get("action")
        ip = row.get("target_ip")
        if not ip or ip == "0.0.0.0/0":
            continue
        if action == "block" and row.get("enforced"):
            blocked.add(ip)
        elif action == "unblock" and row.get("enforced", True):
            blocked.discard(ip)
    return sorted(blocked)
