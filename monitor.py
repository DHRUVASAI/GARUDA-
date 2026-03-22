"""
GARUDA Background Monitor Service
Runs continuously — scans every 5 min, detects threats, saves to DB, sends alerts
Run this separately: python monitor.py
"""

import time
import threading
import platform
import sys
import os
import json
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(__file__))

from database import (
    init_db, save_scan, save_alert,
    get_arp_history, get_known_devices,
    get_port_changes, get_recent_alerts
)

OS = platform.system()
SCAN_INTERVAL = 300   # seconds between scans (5 min)
ARP_CHECK_INTERVAL = 30  # seconds between ARP checks (30 sec)

# Import scanner classes from backend
from garuda_backend import WiFiScanner, NetworkScanner, AttackPredictor, get_real_traffic, scan_device_ports, COMMON_PORTS
import concurrent.futures

wifi_sc = WiFiScanner()
net_sc = NetworkScanner()
predictor = AttackPredictor()

# Track state between scans
_last_arp_table = {}       # ip → mac
_last_port_state = {}      # ip → set of ports
_known_macs = set()        # MACs we've seen before


# ─────────────────────────────────────────────
#  DESKTOP NOTIFICATIONS
# ─────────────────────────────────────────────

def notify(title: str, message: str, urgency: str = 'normal'):
    """Send desktop notification cross-platform."""
    try:
        if OS == 'Windows':
            # Use PowerShell toast notification
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
            subprocess.Popen(['powershell', '-WindowStyle', 'Hidden', '-Command', ps_script],
                           creationflags=subprocess.CREATE_NO_WINDOW)

        elif OS == 'Darwin':
            import subprocess
            subprocess.run(['osascript', '-e',
                f'display notification "{message}" with title "{title}"'],
                capture_output=True)

        elif OS == 'Linux':
            import subprocess
            icon = 'dialog-warning' if urgency in ('critical', 'high') else 'dialog-information'
            subprocess.run(['notify-send', '-u', urgency, '-i', icon, title, message],
                         capture_output=True)

        print(f"[NOTIFY] {title}: {message}")
    except Exception as e:
        print(f"[NOTIFY ERROR] {e}")


# ─────────────────────────────────────────────
#  ARP SPOOF DETECTOR
# ─────────────────────────────────────────────

def check_arp_spoofing():
    """
    Compare current ARP table with previous snapshot.
    Alert if gateway MAC changed — classic MITM setup.
    """
    global _last_arp_table

    current_arp = net_sc.get_arp_table()
    gateway_ip = net_sc.get_gateway()

    for ip, mac in current_arp.items():
        if ip in _last_arp_table:
            old_mac = _last_arp_table[ip]
            if old_mac != mac and old_mac not in ('Unknown', '<INCOMPLETE>'):
                # MAC changed for this IP!
                is_gateway = (ip == gateway_ip)
                severity = 'CRITICAL' if is_gateway else 'HIGH'
                title = f'⚠ ARP SPOOFING DETECTED — {"GATEWAY" if is_gateway else ip}'
                desc = f'IP {ip} changed MAC from {old_mac} to {mac}. {"This is your GATEWAY — possible MITM attack!" if is_gateway else "Possible ARP cache poisoning."}'

                print(f"[ARP ALERT] {desc}")
                save_alert('ARP_SPOOF', severity, title, desc, ip=ip, mac=mac,
                          extra={'old_mac': old_mac, 'new_mac': mac, 'is_gateway': is_gateway})
                notify(title, desc, urgency='critical' if is_gateway else 'normal')

    _last_arp_table = current_arp


# ─────────────────────────────────────────────
#  NEW DEVICE DETECTOR
# ─────────────────────────────────────────────

def check_new_devices(devices: list):
    """Alert when a device with an unknown MAC joins the network."""
    global _known_macs

    # Load all known MACs from DB on first run
    if not _known_macs:
        known = get_known_devices()
        _known_macs = {d['mac'] for d in known if d.get('mac')}
        print(f"[MONITOR] Loaded {len(_known_macs)} known MACs from DB")

    for d in devices:
        mac = d.get('mac', '')
        ip = d.get('ip', '')
        vendor = d.get('vendor', 'Unknown')

        if not mac or mac in ('Unknown', '<INCOMPLETE>'):
            continue

        if mac not in _known_macs:
            title = f'🔴 New Device Joined Network'
            desc = f'Unknown device detected: {vendor} ({mac}) at {ip}. First time seen on this network.'
            print(f"[NEW DEVICE] {desc}")
            save_alert('NEW_DEVICE', 'HIGH', title, desc, ip=ip, mac=mac,
                      extra={'vendor': vendor, 'hostname': d.get('hostname')})
            notify(title, desc)
            _known_macs.add(mac)


# ─────────────────────────────────────────────
#  PORT CHANGE DETECTOR
# ─────────────────────────────────────────────

def check_port_changes(port_data: dict):
    """Alert if a device suddenly opened a risky port."""
    global _last_port_state

    RISKY = {21: 'FTP', 23: 'Telnet', 135: 'RPC', 139: 'NetBIOS',
             445: 'SMB', 3389: 'RDP', 5900: 'VNC', 1433: 'MSSQL',
             3306: 'MySQL', 27017: 'MongoDB', 6379: 'Redis'}

    for ip, ports in port_data.items():
        current = set(ports)

        # First time seeing this IP — just record, don't alert
        if ip not in _last_port_state:
            _last_port_state[ip] = current
            continue

        previous = _last_port_state[ip]
        new_ports = current - previous
        risky_new = {p: RISKY[p] for p in new_ports if p in RISKY}

        if risky_new:
            services = ', '.join(f'{name} ({port})' for port, name in risky_new.items())
            title = f'⚠ Risky Port Opened — {ip}'
            desc = f'Device {ip} just opened: {services}. These services are commonly exploited.'
            print(f"[PORT ALERT] {desc}")
            save_alert('PORT_CHANGE', 'HIGH', title, desc, ip=ip,
                      extra={'new_ports': list(new_ports), 'risky': risky_new})
            notify(title, desc)

        _last_port_state[ip] = current


# ─────────────────────────────────────────────
#  FULL SCAN RUNNER
# ─────────────────────────────────────────────

def run_full_scan():
    """Run a complete scan, save to DB, check for threats."""
    print(f"\n[SCAN] Starting at {datetime.now().strftime('%H:%M:%S')}")
    t_start = time.time()

    try:
        connected = wifi_sc.get_connected_network()
        if 'error' in connected:
            print(f"[SCAN] Not connected: {connected['error']}")
            return

        security = wifi_sc.assess_security(connected.get('encryption', ''))
        connected['security_assessment'] = security

        traffic = get_real_traffic()
        local_ip = net_sc.get_local_ip()
        gateway_ip = net_sc.get_gateway()
        scan_result = net_sc.get_connected_devices()
        all_devices, total_found, net_size = scan_result if isinstance(scan_result, tuple) else (scan_result, len(scan_result), 'small')

        print(f"[SCAN] Found {len(all_devices)} devices (total: {total_found}, network: {net_size})")

        # Port scan (gateway + local + up to 8 others)
        targets = [gateway_ip, local_ip] + \
                  [d['ip'] for d in all_devices if d['ip'] not in (gateway_ip, local_ip)][:8]
        port_data = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(targets)) as ex:
            fm = {ex.submit(scan_device_ports, ip): ip for ip in targets}
            for future in concurrent.futures.as_completed(fm):
                ip = fm[future]
                try:
                    ports = future.result()
                    if ports:
                        port_data[ip] = ports
                except:
                    pass

        devices = []
        for d in all_devices:
            ip = d['ip']
            dtype = 'GATEWAY' if ip == gateway_ip else 'THIS_DEVICE' if ip == local_ip else 'NODE'
            devices.append({
                **d,
                'type': dtype,
                'open_ports': port_data.get(ip, []),
                'threat_level': 'SECURE' if dtype in ('GATEWAY', 'THIS_DEVICE') else 'MONITORING',
            })

        summary = {
            'threat_level': security.get('threat_level', 'UNKNOWN'),
            'mitm_risk': security.get('mitm_risk', 'UNKNOWN'),
            'total_devices': len(devices),
            'active_devices': len([d for d in devices if d.get('status') == 'ACTIVE']),
            'unknown_vendors': len([d for d in devices if d.get('vendor') in ('Unknown', 'Unknown Vendor')]),
        }

        prediction = predictor.predict({
            'connected_network': connected,
            'connected_devices': all_devices,
            'security_summary': summary,
            'network_traffic': traffic,
            'port_scan': port_data,
        })

        scan_result = {
            'scan_duration': f'{round(time.time()-t_start, 1)}s',
            'connected_network': connected,
            'local_ip': local_ip,
            'gateway': gateway_ip,
            'nodes_detected': len(devices),
            'addresses_scanned': 254,
            'devices': devices,
            'network_traffic': traffic,
            'connected_devices': all_devices,
            'port_scan': port_data,
            'security_summary': summary,
            'attack_prediction': prediction,
        }

        # Save to database
        scan_id = save_scan(scan_result)
        print(f"[SCAN] Saved as scan #{scan_id} — risk: {prediction['risk_score']}% ({prediction['risk_label']})")

        # Run threat checks
        check_new_devices(all_devices)
        check_port_changes(port_data)

        # Alert if risk score is high
        if prediction['risk_score'] >= 70:
            save_alert('HIGH_RISK', 'CRITICAL',
                      f'🚨 Critical Risk Score: {prediction["risk_score"]}%',
                      f'Network risk is CRITICAL. Top threat: {prediction["attack_predictions"][0]["type"] if prediction["attack_predictions"] else "Unknown"}',
                      extra={'risk_score': prediction['risk_score'], 'predictions': prediction['attack_predictions']})
            notify(f'GARUDA: Critical Risk {prediction["risk_score"]}%',
                  'Your network has critical security issues. Open GARUDA dashboard.')

    except Exception as e:
        print(f"[SCAN ERROR] {e}")
        import traceback
        traceback.print_exc()


# ─────────────────────────────────────────────
#  ARP WATCHER THREAD (runs every 30 sec)
# ─────────────────────────────────────────────

def arp_watcher_loop():
    """Runs in background thread — checks ARP every 30 seconds."""
    print("[ARP WATCHER] Started")
    while True:
        try:
            check_arp_spoofing()
        except Exception as e:
            print(f"[ARP WATCHER ERROR] {e}")
        time.sleep(ARP_CHECK_INTERVAL)


# ─────────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────────

def main():
    print("=" * 55)
    print("  GARUDA Background Monitor")
    print("=" * 55)
    print(f"  Scan interval:     {SCAN_INTERVAL // 60} minutes")
    print(f"  ARP check interval: {ARP_CHECK_INTERVAL} seconds")
    print(f"  OS: {OS}")
    print("=" * 55)

    # Initialize database
    init_db()

    # Run one scan immediately on startup
    print("\n[MONITOR] Running initial scan...")
    run_full_scan()

    # Start ARP watcher in background thread
    arp_thread = threading.Thread(target=arp_watcher_loop, daemon=True)
    arp_thread.start()

    notify("GARUDA Monitor Started",
           f"Monitoring your network every {SCAN_INTERVAL // 60} minutes")

    # Main scan loop
    print(f"\n[MONITOR] Next scan in {SCAN_INTERVAL // 60} minutes. Press Ctrl+C to stop.\n")
    while True:
        try:
            time.sleep(SCAN_INTERVAL)
            run_full_scan()
        except KeyboardInterrupt:
            print("\n[MONITOR] Stopped by user.")
            break
        except Exception as e:
            print(f"[MONITOR ERROR] {e}")
            time.sleep(30)


if __name__ == '__main__':
    main()