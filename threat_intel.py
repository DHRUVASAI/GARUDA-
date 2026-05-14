"""
Context-aware threat scoring helpers (additive; does not change API envelope).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from threat_ports import RISKY_PORT_META


def adjust_port_change_confidence(
    base_conf: float,
    device: Dict[str, Any],
    risky_new: List[Tuple[int, str, str]],
    all_open_ports: Optional[List[int]],
) -> float:
    """Raise confidence when hostname is missing or many risky ports are exposed."""
    c = float(base_conf)
    if not device.get("hostname"):
        c += 20.0
    ports = set(all_open_ports or [])
    risky_on_host = len([p for p in ports if p in RISKY_PORT_META])
    if risky_on_host >= 5:
        c = max(c, 92.0)
    if len(risky_new) >= 3:
        c += 10.0
    return max(40.0, min(98.0, c))


def lateral_movement_hits(port_data: Dict[str, List[int]]) -> List[Dict[str, Any]]:
    """Ports in RISKY_PORT_META open on 3+ distinct hosts (same scan snapshot)."""
    hits: List[Dict[str, Any]] = []
    if not port_data:
        return hits
    by_port: Dict[int, List[str]] = {}
    for ip, plist in port_data.items():
        for p in plist or []:
            if p in RISKY_PORT_META:
                by_port.setdefault(p, []).append(ip)
    for port, ips in by_port.items():
        if len(ips) >= 3:
            name, sev = RISKY_PORT_META[port]
            hits.append({"port": port, "service": name, "severity": sev, "ips": ips})
    return hits
