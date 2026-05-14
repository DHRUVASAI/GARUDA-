"""
GARUDA Background Monitor Service
Runs continuously — scans every N minutes, detects threats, saves to DB, sends alerts
Run this separately: python monitor.py
"""

import time
import threading
import platform
import sys
import os
import logging
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from config import (
    MONITOR_SCAN_INTERVAL_SEC,
    MONITOR_ARP_INTERVAL_SEC,
    ARP_NEW_MAC_MIN_SIGHTINGS,
    ARP_OLD_MAC_MIN_SECONDS,
)

from database import (
    init_db,
    save_scan,
    save_alert,
    get_known_devices,
    record_arp_snapshots_bulk,
    arp_mac_sightings_count,
    arp_mac_pair_span_seconds,
    arp_total_observations_for_ip,
    count_alerts_for_ip_hours,
)

from garuda_backend import WiFiScanner, NetworkScanner, AttackPredictor, get_real_traffic, scan_device_ports
from garuda_net_utils import guess_os_from_ports_and_ttl, ip_in_volatile_dhcp_range, is_randomized_mac
import concurrent.futures

from threat_ports import RISKY_PORT_META, highest_severity, SEVERITY_RANK, ALERT_TYPE_META
from threat_intel import adjust_port_change_confidence, lateral_movement_hits

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("garuda.monitor")

OS = platform.system()
SCAN_INTERVAL = MONITOR_SCAN_INTERVAL_SEC
ARP_CHECK_INTERVAL = MONITOR_ARP_INTERVAL_SEC

wifi_sc = WiFiScanner()
net_sc = NetworkScanner()
predictor = AttackPredictor()

_last_arp_table = {}
_last_port_state = {}
_known_macs = set()


def notify(title: str, message: str, urgency: str = "normal"):
    """Send desktop notification cross-platform."""
    try:
        if OS == "Windows":
            ps_script = f'''
Add-Type -AssemblyName System.Windows.Forms
$notify = New-Object System.Windows.Forms.NotifyIcon
$notify.Icon = [System.Drawing.SystemIcons]::Shield
$notify.Visible = $true
$notify.ShowBalloonTip(5000, "{title}", "{message}", [System.Windows.Forms.ToolTipIcon]::Warning)
Start-Sleep -s 6
$notify.Dispose()
'''
            import subprocess
            subprocess.Popen(
                ["powershell", "-WindowStyle", "Hidden", "-Command", ps_script],
                creationflags=subprocess.CREATE_NO_WINDOW,
            )

        elif OS == "Darwin":
            import subprocess
            subprocess.run(
                ["osascript", "-e", f'display notification "{message}" with title "{title}"'],
                capture_output=True,
            )

        elif OS == "Linux":
            import subprocess
            icon = "dialog-warning" if urgency in ("critical", "high") else "dialog-information"
            subprocess.run(
                ["notify-send", "-u", urgency, "-i", icon, title, message],
                capture_output=True,
            )

        log.info("[NOTIFY] %s: %s", title, message)
    except Exception as e:
        log.warning("[NOTIFY ERROR] %s", e)


def check_arp_spoofing():
    """
    Compare current ARP table with previous snapshot and historical DB bindings.
    Uses conservative gates to reduce DHCP churn / randomized-MAC false positives.
    """
    global _last_arp_table

    current_arp = net_sc.get_arp_table()
    try:
        record_arp_snapshots_bulk(current_arp)
    except Exception as e:
        log.warning("[ARP] snapshot record failed: %s", e)

    gateway_ip = net_sc.get_gateway()

    next_arp_table = _last_arp_table.copy()

    for ip, mac in current_arp.items():
        if ip not in _last_arp_table:
            next_arp_table[ip] = mac
            continue
        old_mac = _last_arp_table[ip]
        if old_mac == mac or old_mac in ("Unknown", "<INCOMPLETE>"):
            next_arp_table[ip] = mac
            continue
        if ip_in_volatile_dhcp_range(ip):
            next_arp_table[ip] = mac
            continue
        if is_randomized_mac(mac):
            next_arp_table[ip] = mac
            continue
        if arp_mac_sightings_count(ip, mac) < ARP_NEW_MAC_MIN_SIGHTINGS:
            continue
        if arp_mac_pair_span_seconds(ip, old_mac) < float(ARP_OLD_MAC_MIN_SECONDS):
            continue

        total_obs = arp_total_observations_for_ip(ip) or 1
        new_cnt = arp_mac_sightings_count(ip, mac)
        freq = new_cnt / float(total_obs)
        old_span = arp_mac_pair_span_seconds(ip, old_mac)
        time_w = min(1.0, old_span / float(ARP_OLD_MAC_MIN_SECONDS))
        conf = 100.0 * freq * max(0.15, time_w)
        conf = max(35.0, min(98.0, conf))

        is_gateway = ip == gateway_ip
        severity = "CRITICAL" if is_gateway and conf >= 70 else "HIGH" if conf >= 60 else "MEDIUM"
        title = f"ARP Spoof — {conf:.0f}% confidence — {'GATEWAY' if is_gateway else ip}"
        desc = (
            f"IP {ip} changed MAC from {old_mac} to {mac}. "
            f"{'This is your GATEWAY — possible MITM attack!' if is_gateway else 'Possible ARP cache poisoning.'} "
            f"(Sightings={new_cnt}/{total_obs}, old binding span {old_span:.0f}s.)"
        )

        log.warning("[ARP ALERT] %s", desc)
        aid = save_alert(
            "ARP_SPOOF",
            severity,
            title,
            desc,
            ip=ip,
            mac=mac,
            extra={"old_mac": old_mac, "new_mac": mac, "is_gateway": is_gateway, "confidence": conf},
            confidence=conf,
        )
        if aid:
            notify(title, desc, urgency="critical" if is_gateway else "normal")

        next_arp_table[ip] = mac

    _last_arp_table = next_arp_table


def check_new_devices(devices: list):
    """Alert when a device with an unknown MAC joins the network."""
    global _known_macs

    if not _known_macs:
        known = get_known_devices()
        _known_macs = {d["mac"] for d in known if d.get("mac")}
        log.info("[MONITOR] Loaded %s known MACs from DB", len(_known_macs))

    for d in devices:
        mac = d.get("mac", "")
        ip = d.get("ip", "")
        vendor = d.get("vendor", "Unknown")

        if not mac or mac in ("Unknown", "<INCOMPLETE>"):
            continue

        if mac not in _known_macs:
            conf = 78.0
            title = f"New Device Joined Network — {conf:.0f}% confidence"
            desc = f"Unknown device detected: {vendor} ({mac}) at {ip}. First time seen on this network."
            log.warning("[NEW DEVICE] %s", desc)
            aid = save_alert(
                "NEW_DEVICE",
                "HIGH",
                title,
                desc,
                ip=ip,
                mac=mac,
                extra={"vendor": vendor, "hostname": d.get("hostname"), "confidence": conf},
                confidence=conf,
            )
            if aid:
                notify(title, desc)
            _known_macs.add(mac)


def check_port_changes(port_data: dict, dev_by_ip: dict = None):
    """Alert if a device suddenly opened a risky port."""
    global _last_port_state
    dev_by_ip = dev_by_ip or {}

    for ip, ports in port_data.items():
        current = set(ports)

        if ip not in _last_port_state:
            _last_port_state[ip] = current
            continue

        previous = _last_port_state[ip]
        new_ports = current - previous
        risky_new = []
        for p in new_ports:
            if p in RISKY_PORT_META:
                name, sev = RISKY_PORT_META[p]
                risky_new.append((p, name, sev))

        if risky_new:
            sev_label = highest_severity(risky_new)
            all_risky_on_host = [p for p in current if p in RISKY_PORT_META]
            if len(all_risky_on_host) >= 5:
                db_sev = "CRITICAL"
            else:
                db_sev = (
                    "CRITICAL"
                    if sev_label == "CRITICAL"
                    else "HIGH"
                    if sev_label == "HIGH"
                    else "MEDIUM"
                )
            base_conf = min(95.0, 58.0 + len(risky_new) * 7.0 + SEVERITY_RANK.get(sev_label, 1) * 4.0)
            device = dev_by_ip.get(ip, {})
            conf = adjust_port_change_confidence(base_conf, device, risky_new, list(ports))
            services = ", ".join(f"{name} ({port}) [{sev}]" for port, name, sev in risky_new)
            title = f"Risky Port Opened — {conf:.0f}% confidence — {ip}"
            desc = f"Device {ip} just opened: {services}. These services are commonly exploited."
            log.warning("[PORT ALERT] %s", desc)
            aid = save_alert(
                "PORT_CHANGE",
                db_sev,
                title,
                desc,
                ip=ip,
                extra={"new_ports": list(new_ports), "risky": risky_new, "confidence": conf},
                confidence=conf,
            )
            if aid:
                notify(title, desc)

        _last_port_state[ip] = current


def check_lateral_movement(port_data: dict):
    for hit in lateral_movement_hits(port_data):
        port = hit["port"]
        ips = hit["ips"]
        name = hit["service"]
        conf = min(95.0, 55.0 + len(ips) * 6.0)
        meta = ALERT_TYPE_META.get("LATERAL_MOVEMENT", {})
        title = f"Lateral movement — {name} (port {port}) on {len(ips)} hosts"
        desc = (meta.get("description") or "").strip()
        if desc:
            desc = f"{desc} Affected: {', '.join(ips[:16])}"
        else:
            desc = f"Affected hosts: {', '.join(ips[:16])}"
        aid = save_alert(
            "LATERAL_MOVEMENT",
            "HIGH",
            title,
            desc,
            ip=f"lateral:{port}",
            extra={"port": port, "ips": ips, "service": name, "confidence": conf},
            confidence=conf,
        )
        if aid:
            notify(title, desc, urgency="high")


def check_persistent_threat(devices_list: list):
    for d in devices_list:
        if d.get("type") != "NODE":
            continue
        ip = d.get("ip")
        if not ip:
            continue
        if count_alerts_for_ip_hours(ip, 1) < 3:
            continue
        conf = 86.0
        title = f"Persistent threat host — {ip} — {conf:.0f}% confidence"
        desc = (
            ALERT_TYPE_META.get("PERSISTENT_THREAT", {}).get("description")
            or "Multiple alerts for this host within one hour."
        )
        aid = save_alert(
            "PERSISTENT_THREAT",
            "HIGH",
            title,
            desc,
            ip=ip,
            mac=d.get("mac"),
            extra={"persistent_threat": True, "confidence": conf},
            confidence=conf,
        )
        if aid:
            notify(title, desc, urgency="high")


def run_full_scan():
    """Run a complete scan, save to DB, check for threats."""
    log.info("Starting full scan at %s", datetime.now().strftime("%H:%M:%S"))
    t_start = time.time()

    try:
        connected = wifi_sc.get_connected_network()
        if "error" in connected:
            log.warning("[SCAN] Not connected: %s", connected["error"])
            return

        security = wifi_sc.assess_security(connected.get("encryption", ""))
        connected["security_assessment"] = security

        traffic = get_real_traffic()
        local_ip = net_sc.get_local_ip()
        gateway_ip = net_sc.get_gateway()
        scan_result = net_sc.get_connected_devices()
        all_devices, total_found, net_size = (
            scan_result if isinstance(scan_result, tuple) else (scan_result, len(scan_result), "small")
        )

        log.info("[SCAN] Found %s devices (total: %s, network: %s)", len(all_devices), total_found, net_size)

        targets = [gateway_ip, local_ip] + [d["ip"] for d in all_devices if d["ip"] not in (gateway_ip, local_ip)][:8]
        port_workers = max(1, min(32, len(targets)))
        port_data = {}
        rtt_by_ip = {d["ip"]: d.get("ping_rtt_ms") for d in all_devices if d.get("ip")}
        with concurrent.futures.ThreadPoolExecutor(max_workers=port_workers) as ex:
            fm = {
                ex.submit(scan_device_ports, ip, None, net_size, rtt_by_ip.get(ip)): ip
                for ip in targets
            }
            for future in concurrent.futures.as_completed(fm):
                ip = fm[future]
                try:
                    ports = future.result()
                    if ports:
                        port_data[ip] = ports
                except Exception:
                    log.debug("Port scan failed for %s", ip, exc_info=True)

        for d in all_devices:
            d["os_guess"] = guess_os_from_ports_and_ttl(
                port_data.get(d.get("ip"), []),
                d.get("icmp_ttl"),
            )

        devices = []
        for d in all_devices:
            ip = d["ip"]
            dtype = "GATEWAY" if ip == gateway_ip else "THIS_DEVICE" if ip == local_ip else "NODE"
            devices.append(
                {
                    **d,
                    "type": dtype,
                    "open_ports": port_data.get(ip, []),
                    "threat_level": "SECURE" if dtype in ("GATEWAY", "THIS_DEVICE") else "MONITORING",
                }
            )

        dev_by_ip = {d["ip"]: d for d in devices}

        summary = {
            "threat_level": security.get("threat_level", "UNKNOWN"),
            "mitm_risk": security.get("mitm_risk", "UNKNOWN"),
            "total_devices": len(devices),
            "active_devices": len([d for d in devices if d.get("status") == "ACTIVE"]),
            "unknown_vendors": len([d for d in devices if d.get("vendor") in ("Unknown", "Unknown Vendor")]),
        }

        prediction = predictor.predict(
            {
                "connected_network": connected,
                "connected_devices": all_devices,
                "security_summary": summary,
                "network_traffic": traffic,
                "port_scan": port_data,
            }
        )

        scan_result = {
            "scan_duration": f"{round(time.time()-t_start, 1)}s",
            "connected_network": connected,
            "local_ip": local_ip,
            "gateway": gateway_ip,
            "nodes_detected": len(devices),
            "addresses_scanned": 254,
            "devices": devices,
            "network_traffic": traffic,
            "connected_devices": all_devices,
            "port_scan": port_data,
            "security_summary": summary,
            "attack_prediction": prediction,
        }

        scan_id = save_scan(scan_result)
        log.info("[SCAN] Saved as scan #%s — risk: %s%% (%s)", scan_id, prediction["risk_score"], prediction["risk_label"])

        check_new_devices(all_devices)
        check_port_changes(port_data, dev_by_ip)
        check_lateral_movement(port_data)
        check_persistent_threat(devices)

        if prediction["risk_score"] >= 70:
            conf = min(97.0, 70.0 + prediction["risk_score"] * 0.25)
            aid = save_alert(
                "HIGH_RISK",
                "CRITICAL",
                f"Critical Risk Score: {prediction['risk_score']:.0f}% — {conf:.0f}% confidence",
                f"Network risk is CRITICAL. Top threat: {prediction['attack_predictions'][0]['type'] if prediction['attack_predictions'] else 'Unknown'}",
                extra={"risk_score": prediction["risk_score"], "predictions": prediction["attack_predictions"], "confidence": conf},
                confidence=conf,
            )
            if aid:
                notify(
                    f"GARUDA: Critical Risk {prediction['risk_score']:.0f}%",
                    "Your network has critical security issues. Open GARUDA dashboard.",
                )

    except Exception as e:
        log.exception("[SCAN ERROR] %s", e)


def arp_watcher_loop():
    log.info("[ARP WATCHER] Started")
    while True:
        try:
            check_arp_spoofing()
        except Exception as e:
            log.exception("[ARP WATCHER ERROR] %s", e)
        time.sleep(ARP_CHECK_INTERVAL)


def main():
    log.info("GARUDA Background Monitor | scan=%ss arp=%ss OS=%s", SCAN_INTERVAL, ARP_CHECK_INTERVAL, OS)

    init_db()

    log.info("[MONITOR] Running initial scan...")
    run_full_scan()

    arp_thread = threading.Thread(target=arp_watcher_loop, daemon=True)
    arp_thread.start()

    notify("GARUDA Monitor Started", f"Monitoring your network every {SCAN_INTERVAL // 60} minutes")

    log.info("[MONITOR] Main loop started. Press Ctrl+C to stop.")
    while True:
        try:
            time.sleep(SCAN_INTERVAL)
            run_full_scan()
        except KeyboardInterrupt:
            log.info("[MONITOR] Stopped by user.")
            break
        except Exception as e:
            log.exception("[MONITOR] Loop error (will continue): %s", e)
            time.sleep(30)


if __name__ == "__main__":
    main()
