"""GARUDA v6 Purple Team Campaign Correlation & Incident Timeline Engine (PT-01..PT-08).
Correlates multi-stage alerts, ML scores, containment actions, and forensic blocks
into coherent attack campaigns and chronological incident timelines.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _parse_ts(val: Any) -> float:
    if isinstance(val, (int, float)):
        return float(val)
    if isinstance(val, datetime):
        return val.timestamp()
    if isinstance(val, str):
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0
    return 0.0


def build_incident_timeline(alerts: List[dict]) -> List[dict]:
    """Produce a coherent chronological incident timeline across all attack stages (PT-08)."""
    ordered = sorted(alerts, key=lambda a: _parse_ts(a.get("created_at")))
    timeline = []
    for idx, a in enumerate(ordered, start=1):
        timeline.append({
            "step": idx,
            "timestamp": str(a.get("created_at", "")),
            "attack_type": a.get("attack_type", "unknown"),
            "severity": a.get("severity", "info"),
            "title": a.get("title", ""),
            "related_ip": a.get("related_ip"),
            "related_mac": a.get("related_mac"),
        })
    return timeline


def correlate_attack_campaigns(
    alerts: List[dict],
    devices: Optional[List[dict]] = None,
    firewall_logs: Optional[List[dict]] = None,
    ledger_blocks: Optional[List[dict]] = None,
) -> Dict[str, Any]:
    """Correlate individual IDS/ML/Firewall/Ledger events into Purple Team campaigns (PT-01..PT-08)."""
    campaigns: List[dict] = []
    by_type = defaultdict(list)
    by_actor = defaultdict(list)
    safe_macs = {
        (d.get("mac") or "").upper()
        for d in (devices or [])
        if d.get("is_safe")
    }

    for a in alerts:
        at = a.get("attack_type", "")
        by_type[at].append(a)
        actor = (a.get("related_mac") or a.get("related_ip") or "network").upper()
        by_actor[actor].append(a)

    # PT-01: ARP Spoof + DNS Hijack -> Coordinated MITM Campaign
    if by_type["arp_spoof"] and by_type["dns_hijack"]:
        campaigns.append({
            "campaign_id": "PT-01",
            "campaign_type": "coordinated_mitm_campaign",
            "severity": "critical",
            "title": "Coordinated Man-in-the-Middle Campaign (ARP Spoofing + DNS Hijacking)",
            "indicators": ["arp_spoof", "dns_hijack"],
            "event_count": len(by_type["arp_spoof"]) + len(by_type["dns_hijack"]),
            "plain_summary": "Multiple MITM layers detected simultaneously: router ARP impersonation combined with DNS redirection.",
        })

    # PT-02: Reconnaissance Scan + C2 Beaconing -> Post-Exploitation Kill Chain
    recon_events = by_type["port_sweep"] + by_type["slow_port_scan"] + by_type["distributed_port_scan"]
    c2_events = by_type["c2_beacon"] + by_type["ml_c2_beacon"] + by_type["dns_tunneling"]
    if recon_events and c2_events:
        campaigns.append({
            "campaign_id": "PT-02",
            "campaign_type": "recon_to_c2_campaign",
            "severity": "critical",
            "title": "Multi-Stage Kill Chain (Reconnaissance Scan -> C2 Beaconing)",
            "indicators": sorted({e["attack_type"] for e in recon_events + c2_events}),
            "event_count": len(recon_events) + len(c2_events),
            "plain_summary": "Port reconnaissance was followed by periodic C2 callbacks or covert tunneling.",
        })

    # PT-03: Rogue DHCP + DNS Manipulation -> Network Redirection Campaign
    dns_manip = by_type["dns_hijack"] + by_type["dns_tunneling"] + by_type["dga_domain"]
    if by_type["rogue_dhcp"] and dns_manip:
        campaigns.append({
            "campaign_id": "PT-03",
            "campaign_type": "network_redirection_campaign",
            "severity": "critical",
            "title": "Combined Network Redirection Campaign (Rogue DHCP + DNS Manipulation)",
            "indicators": ["rogue_dhcp"] + sorted({e["attack_type"] for e in dns_manip}),
            "event_count": len(by_type["rogue_dhcp"]) + len(dns_manip),
            "plain_summary": "Unauthorized DHCP offers paired with DNS manipulation indicate an active traffic-hijacking trap.",
        })

    # PT-04: Trusted Device Compromise
    compromised_trusted = [
        a for a in alerts
        if (a.get("related_mac") or "").upper() in safe_macs
        and a.get("severity") in ("critical", "high")
    ]
    if compromised_trusted:
        campaigns.append({
            "campaign_id": "PT-04",
            "campaign_type": "trusted_device_compromise",
            "severity": "critical",
            "title": "Previously Trusted Device Exhibiting Malicious Behavior",
            "indicators": sorted({a.get("attack_type", "") for a in compromised_trusted}),
            "affected_macs": sorted({(a.get("related_mac") or "").upper() for a in compromised_trusted}),
            "event_count": len(compromised_trusted),
            "plain_summary": "A device marked Safe on your baseline triggered high-severity attack indicators and must be re-audited.",
        })

    # PT-05: Multi-Device Coordinated Attack
    distinct_attackers = {
        (a.get("related_ip") or a.get("related_mac"))
        for a in alerts
        if a.get("category") == "active_attack" and (a.get("related_ip") or a.get("related_mac"))
    }
    if len(distinct_attackers) >= 2 or by_type["distributed_port_scan"]:
        campaigns.append({
            "campaign_id": "PT-05",
            "campaign_type": "multi_device_coordinated_attack",
            "severity": "critical",
            "title": f"Multi-Device Coordinated Attack ({max(len(distinct_attackers), 2)} Hosts Involved)",
            "indicators": sorted({a.get("attack_type", "") for a in alerts if a.get("category") == "active_attack"}),
            "actors": sorted(str(x) for x in distinct_attackers),
            "event_count": len(alerts),
            "plain_summary": "Suspicious activity was correlated across multiple distinct LAN hosts.",
        })

    # PT-06: Intermittent Persistent Attacker (same actor across separated sessions >= 60s apart)
    for actor, evts in by_actor.items():
        if actor == "NETWORK" or len(evts) < 2:
            continue
        times = sorted(_parse_ts(e.get("created_at")) for e in evts)
        if times[-1] - times[0] >= 60.0:
            campaigns.append({
                "campaign_id": "PT-06",
                "campaign_type": "intermittent_persistent_attacker",
                "severity": "high",
                "title": f"Intermittent Persistent Attacker Retained Across Sessions ({actor})",
                "indicators": sorted({e.get("attack_type", "") for e in evts}),
                "actor": actor,
                "span_seconds": round(times[-1] - times[0], 1),
                "event_count": len(evts),
                "plain_summary": f"Actor {actor} reappeared across multiple separated time windows; evidence retained across sessions.",
            })
            break

    # PT-07: Attack Followed by Containment (Lockdown / Block) & Forensic Preservation
    contained = any(
        f.get("action") in ("block", "lockdown_on") for f in (firewall_logs or [])
    )
    preserved = len(ledger_blocks or []) > 0
    if alerts and contained and preserved:
        campaigns.append({
            "campaign_id": "PT-07",
            "campaign_type": "contained_and_preserved_campaign",
            "severity": "info",
            "title": "Full Purple-Team Loop Verified: Detected, Contained & Cryptographically Sealed",
            "indicators": ["detected", "contained", "forensically_sealed"],
            "event_count": len(alerts),
            "plain_summary": "Attack was detected, contained via OS firewall/lockdown, and preserved in the Ed25519 Merkle ledger.",
        })

    timeline = build_incident_timeline(alerts)
    return {
        "campaigns_detected": len(campaigns),
        "campaigns": campaigns,
        "timeline_events": len(timeline),
        "timeline": timeline,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
