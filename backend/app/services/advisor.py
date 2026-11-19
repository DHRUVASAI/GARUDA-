"""GARUDA v4 Unified Plain-English Secure Communication Advisor.
Combines Network Encryption, Active/Passive IDS Alerts, AI Behavioral Anomaly Score,
Unverified Devices, Malware Findings, Firewall Health, and VPN status into clear human guidance.
"""

from typing import List, Optional


def build_security_advice(
    net_info: dict,
    devices: List[dict],
    active_alerts: List[dict],
    malware_summary: dict,
    firewall_status: dict,
    ml_summary: Optional[dict] = None,
) -> dict:
    score = 100
    recommendations = []

    enc_grade = net_info.get("encryption_grade", "Good")
    is_public = bool(net_info.get("is_public_or_untrusted", False))
    vpn_on = bool(net_info.get("vpn_active", False))
    unverified_count = sum(1 for d in devices if not d["is_safe"] and d["is_online"])
    unresolved = [a for a in active_alerts if not a["resolved"]]
    critical_alerts = [a for a in unresolved if a["severity"] == "critical"]
    active_attacks = [a for a in unresolved if a["category"] == "active_attack"]
    passive_risks = [a for a in unresolved if a["category"] == "passive_risk"]
    malware_threats = int(malware_summary.get("threats_found", 0))
    fw_on = bool(firewall_status.get("enabled", False))
    ml_peak = float((ml_summary or {}).get("network_anomaly_score", 0.0))

    if enc_grade == "None":
        score -= 22 if vpn_on else 45
    elif enc_grade == "Weak":
        score -= 14 if vpn_on else 28
    elif enc_grade == "Good":
        score -= 4

    if is_public and not vpn_on:
        score -= 14
    if not fw_on:
        score -= 12
    score -= min(18, unverified_count * 4)
    score -= min(35, len(critical_alerts) * 22)
    score -= min(12, len(passive_risks) * 5)
    score -= min(30, malware_threats * 18)
    if ml_peak >= 70.0:
        score -= 18
    elif ml_peak >= 45.0:
        score -= 8
    score = max(5, min(100, score))

    if score >= 82 and not critical_alerts and malware_threats == 0 and ml_peak < 70.0:
        label = "Protected"
        headline = "Your network, AI behavioral baseline, and device shield look healthy. Safe for everyday banking and logins."
    elif score >= 55 and not active_attacks and malware_threats == 0:
        label = "Caution Needed"
        headline = "A few quick steps below will close passive eavesdropping gaps and verify unknown devices."
    else:
        label = "At Risk"
        headline = "Pause sensitive banking or passwords until you resolve the urgent security alerts below."

    if active_attacks:
        recommendations.append({
            "id": "stop-active-attack",
            "priority": "urgent",
            "title": "Active Network Attack Detected — Isolate or Pin Router Now",
            "why_it_matters": "Someone on this network is actively trying to impersonate your router, hijack DNS, or probe your ports.",
            "simple_step": "Turn off Wi-Fi (switch to 4G/5G), or use GARUDA's 'Pin Router Against MITM' & Firewall IP Block immediately.",
            "safe_for": "Banking, OTPs & Account Passwords",
        })

    if ml_peak >= 65.0:
        recommendations.append({
            "id": "inspect-ml-anomaly",
            "priority": "urgent",
            "title": f"AI Detected High Behavioral Anomaly ({ml_peak:.0f}/100)",
            "why_it_matters": "GARUDA's IsolationForest ensemble spotted robotic beaconing, latency relay spikes, or randomized DGA traffic.",
            "simple_step": "Open the AI & Ledger tab to inspect the top contributing factors and block the flagged device if unrecognized.",
            "safe_for": "Early Zero-Day & C2 Defense",
        })

    if malware_threats > 0:
        recommendations.append({
            "id": "clean-malware",
            "priority": "urgent",
            "title": f"Remove {malware_threats} Detected Malware / Suspicious Process Finding(s)",
            "why_it_matters": "Even a secure Wi-Fi cannot protect you if malicious software is already running on your computer.",
            "simple_step": "Open GARUDA's Virus & Firewall Shield, delete/quarantine flagged files, and stop suspicious processes.",
            "safe_for": "Device Integrity & Stored Passwords",
        })

    if (enc_grade in ("None", "Weak") or is_public) and not vpn_on:
        recommendations.append({
            "id": "enable-vpn",
            "priority": "urgent",
            "title": "Turn On a Trusted VPN to Stop Passive Eavesdropping",
            "why_it_matters": "On open or shared Wi-Fi, silent listeners can observe unencrypted browsing without sending a single packet.",
            "simple_step": "Connect to Proton VPN, Mullvad, or Cloudflare WARP before signing into any accounts.",
            "safe_for": "Public Wi-Fi Privacy",
        })

    if not fw_on:
        recommendations.append({
            "id": "enable-firewall",
            "priority": "recommended",
            "title": "Turn On Your System Firewall",
            "why_it_matters": "Without a firewall, other devices on the same Wi-Fi can reach open ports and file shares on your computer.",
            "simple_step": "Open GARUDA's Virus & Firewall tab and activate 1-Click Public Wi-Fi Lockdown.",
            "safe_for": "Blocking Local Intruders",
        })

    if unverified_count > 0:
        recommendations.append({
            "id": "verify-devices",
            "priority": "recommended",
            "title": f"Verify {unverified_count} Unmarked Device{'s' if unverified_count != 1 else ''}",
            "why_it_matters": "Marking your own devices as Safe calibrates GARUDA's ML baseline and catches intruders the moment they join.",
            "simple_step": "Open Devices, verify each real name, and click 'Mark Safe' on the ones you own.",
            "safe_for": "Home & Office Access Control",
        })

    recommendations.append({
        "id": "encrypted-dns",
        "priority": "good_habit",
        "title": "Keep Encrypted DNS (1.1.1.1 / 9.9.9.9) & HTTPS-Only Enabled",
        "why_it_matters": "Encrypted DNS stops passive snoops and rogue routers from seeing or tampering with website lookups.",
        "simple_step": "Enable 'Secure DNS (DNS-over-HTTPS)' in your browser and OS settings, and use Signal/WhatsApp for sensitive chats.",
        "safe_for": "Private Browsing & Messaging",
    })

    if active_attacks or malware_threats > 0 or ml_peak >= 70.0 or (enc_grade == "None" and not vpn_on):
        activity_guide = [
            {"activity": "Online Banking, UPI & Payments", "status": "avoid", "note": "Switch to mobile 4G/5G data or resolve urgent alerts first."},
            {"activity": "Work & Email Passwords", "status": "avoid", "note": "Do not enter credentials until threats are cleared and VPN is active."},
            {"activity": "WhatsApp / Signal Encrypted Calls", "status": "caution", "note": "Contents stay end-to-end encrypted, though network metadata is exposed."},
            {"activity": "News & Video Streaming", "status": "caution", "note": "Stick strictly to HTTPS websites; avoid downloading executables."},
        ]
    elif is_public or enc_grade == "Weak" or not fw_on:
        activity_guide = [
            {"activity": "Online Banking, UPI & Payments", "status": "caution", "note": "Use a trusted VPN or your phone's mobile data."},
            {"activity": "Work & Email Passwords", "status": "caution", "note": "Enable VPN + verify the browser HTTPS padlock."},
            {"activity": "WhatsApp / Signal Encrypted Calls", "status": "safe", "note": "Protected by end-to-end encryption."},
            {"activity": "Local Printer & File Sharing", "status": "avoid", "note": "Keep file sharing off on shared Wi-Fi or while Firewall is off."},
        ]
    else:
        activity_guide = [
            {"activity": "Online Banking, UPI & Payments", "status": "safe", "note": "Encrypted private network with active firewall & clean ML baseline."},
            {"activity": "Work & Email Passwords", "status": "safe", "note": "Protected by Wi-Fi encryption and HTTPS."},
            {"activity": "WhatsApp / Signal Encrypted Calls", "status": "safe", "note": "Double-protected by Wi-Fi encryption and end-to-end encryption."},
            {"activity": "Local Printer & Smart TV Sharing", "status": "safe" if unverified_count == 0 else "caution", "note": "Safe once all connected devices are marked Safe."},
        ]

    passive_honesty_note = (
        "How GARUDA handles Passive Attacks honestly: Active attacks (ARP spoofing, Rogue DHCP, DNS hijacking, port scans, C2 beaconing) "
        "emit packets or timing anomalies that GARUDA's live IDS + IsolationForest ML engine catch in real time. A 100% silent RF sniffer "
        "transmits zero packets and cannot be seen by any single laptop — so GARUDA defends against passive sniffing by detecting open/weak "
        "Wi-Fi, flagging cleartext traffic, verifying VPN & DoH DNS, and sealing critical forensic evidence into an Ed25519 Merkle ledger."
    )

    return {
        "safety_score": score,
        "safety_label": label,
        "headline": headline,
        "recommendations": recommendations,
        "activity_guide": activity_guide,
        "passive_honesty_note": passive_honesty_note,
    }
