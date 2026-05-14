"""
Network helpers: ping parse, OS fingerprinting, DHCP range checks.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Optional, Tuple

from config import DHCP_VOLATILE_RANGE


def parse_ping_rtt_ttl(stdout: str, stderr: str = "") -> Tuple[Optional[float], Optional[int]]:
    """Extract RTT (ms) and TTL from ping command output (Windows / Linux / macOS)."""
    text = (stdout or "") + "\n" + (stderr or "")
    rtt: Optional[float] = None
    ttl: Optional[int] = None

    m = re.search(r"(?i)ttl[=\s]+(\d+)", text)
    if m:
        try:
            ttl = int(m.group(1))
        except ValueError:
            pass

    m = re.search(r"(?i)time[<=]+(\d+)\s*ms", text)
    if m:
        try:
            rtt = float(m.group(1))
        except ValueError:
            pass
    if rtt is None:
        m = re.search(r"(?i)time=([\d.]+)\s*ms", text)
        if m:
            try:
                rtt = float(m.group(1))
            except ValueError:
                pass
    if rtt is None and re.search(r"time<1ms", text, re.I):
        rtt = 0.5
    return rtt, ttl


def is_randomized_mac(mac: str) -> bool:
    if not mac:
        return False
    try:
        first = mac.split(":")[0].split("-")[0]
        return (int(first, 16) & 0x02) != 0
    except ValueError:
        return False


def ip_in_volatile_dhcp_range(ip: str) -> bool:
    """
    If DHCP_VOLATILE_RANGE is set (e.g. 192.168.1.100-200 or 192.168.1.100-192.168.1.200),
    return True when ip falls in that inclusive IPv4 range.
    """
    spec = (DHCP_VOLATILE_RANGE or "").strip()
    if not spec or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if "-" not in spec:
        return False
    left, right = spec.split("-", 1)
    left = left.strip()
    right = right.strip()
    try:
        a = ipaddress.ip_address(left)
        if "." in right and right.replace(".", "").isdigit():
            b = ipaddress.ip_address(right)
        else:
            parts = left.split(".")
            if len(parts) != 4:
                return False
            b = ipaddress.ip_address(".".join(parts[:3] + [right]))
        lo, hi = (a, b) if int(a) <= int(b) else (b, a)
        return lo <= addr <= hi
    except ValueError:
        return False


def guess_os_from_ports_and_ttl(open_ports: list, ttl: Optional[int]) -> str:
    """Heuristic OS / device class from open ports and ICMP TTL."""
    ports = set(open_ports or [])
    if 62078 in ports:
        return "Apple iOS"
    if 5353 in ports and (5900 in ports or 5000 in ports):
        return "Apple / mDNS"
    if 445 in ports and 139 in ports:
        return "Windows"
    if 22 in ports and 445 not in ports:
        return "Linux / Unix"
    if 9100 in ports:
        return "Network printer"
    if ttl is not None:
        if ttl <= 64:
            return "Unix-like (TTL hint)"
        if ttl <= 128:
            return "Windows-like (TTL hint)"
        if ttl >= 200:
            return "Network device (TTL hint)"
    return "Unknown"
