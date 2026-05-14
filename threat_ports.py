from __future__ import annotations

"""
Risky TCP port metadata: service label and alert severity tier.
Used by port-change detection and attack prediction.
"""

# port -> (service_name, severity: LOW | MEDIUM | HIGH | CRITICAL)
RISKY_PORT_META = {
    21: ("FTP", "MEDIUM"),
    22: ("SSH", "MEDIUM"),
    23: ("Telnet", "HIGH"),
    80: ("HTTP", "LOW"),
    443: ("HTTPS", "LOW"),
    135: ("RPC", "MEDIUM"),
    139: ("NetBIOS", "MEDIUM"),
    445: ("SMB", "CRITICAL"),
    3389: ("RDP", "CRITICAL"),
    5900: ("VNC", "HIGH"),
    1433: ("MSSQL", "HIGH"),
    3306: ("MySQL", "MEDIUM"),
    6379: ("Redis", "HIGH"),
    27017: ("MongoDB", "HIGH"),
}

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# Optional UI / API metadata for non-port alert types (additive).
ALERT_TYPE_META = {
    "ARP_SPOOF": {
        "title": "ARP spoofing",
        "description": "IP to MAC binding changed versus stable history — possible cache poisoning.",
        "badge": "danger",
    },
    "LATERAL_MOVEMENT": {
        "title": "Lateral movement pattern",
        "description": "The same risky service appears open on multiple hosts — investigate sprawl or worm activity.",
        "badge": "warn",
    },
    "PERSISTENT_THREAT": {
        "title": "Persistent threat host",
        "description": "This host triggered multiple alerts within one hour — prioritize inspection.",
        "badge": "danger",
    },
    "NEW_DEVICE": {
        "title": "New device",
        "description": "First-seen MAC on the network.",
        "badge": "warn",
    },
    "PORT_CHANGE": {
        "title": "Risky port change",
        "description": "A risky TCP port newly appeared on a host versus the prior scan.",
        "badge": "warn",
    },
    "HIGH_RISK": {
        "title": "High aggregate risk",
        "description": "Attack predictor score crossed the critical threshold.",
        "badge": "danger",
    },
}


def highest_severity(port_metas: list[tuple[int, str, str]]) -> str:
    """Given list of (port, name, severity), return worst severity string."""
    best = "LOW"
    br = 0
    for _, _, sev in port_metas:
        r = SEVERITY_RANK.get(sev, 0)
        if r > br:
            br = r
            best = sev
    return best
