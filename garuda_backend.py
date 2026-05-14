"""
GARUDA Network Defense System - Backend v4.0
100% Real Data: psutil traffic, real port scanning, real ARP/ping detection
+ History & Dashboard endpoints backed by SQLite
+ 300+ device support: chunked multi-subnet ARP, live MAC vendor API fallback,
  mDNS/Bonjour lookup, raised device cap, faster parallel scanning
"""

from flask import Flask, jsonify, request, send_from_directory, Response, stream_with_context
import os
import json
from flask_cors import CORS
import subprocess, re, platform, socket, time, concurrent.futures, threading
import queue
from datetime import datetime
import ipaddress
from typing import Optional
import psutil
import logging
from werkzeug.exceptions import HTTPException

from config import (
    HOST,
    PORT,
    FLASK_DEBUG,
    FLASK_THREADED,
    LOG_LEVEL,
    CONTENT_SECURITY_POLICY,
    SCAN_FULL_RATE,
    SCAN_CONNECTED_RATE,
    PORT_CRITICAL,
    PORT_TIMEOUT_FAST_MS,
    PORT_TIMEOUT_MED_MS,
    PORT_TIMEOUT_SLOW_MS,
    PORT_CRITICAL_FLOOR_MS,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from threat_ports import RISKY_PORT_META, SEVERITY_RANK
from garuda_net_utils import parse_ping_rtt_ttl, guess_os_from_ports_and_ttl

try:
    import urllib.request as _urlreq
    _URLIB_OK = True
except ImportError:
    _URLIB_OK = False

logging.basicConfig(
    level=getattr(logging, str(LOG_LEVEL).upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("garuda")

app = Flask(__name__, static_folder=os.path.dirname(os.path.abspath(__file__)))
app.config["GARUDA_CSP"] = CONTENT_SECURITY_POLICY
CORS(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["400 per minute"], storage_uri="memory://")

_scan_state_lock = threading.Lock()
_scan_in_progress = False


def _iso_now():
    return datetime.now().isoformat()


def _api_envelope(success: bool, data=None, error=None, status: int = 200):
    body = {"success": success, "data": data, "error": error, "timestamp": _iso_now()}
    return jsonify(body), status


def _workers_for_host_count(n_hosts: int, cap: int = 512, floor: int = 32) -> int:
    if n_hosts <= 0:
        return floor
    return max(floor, min(cap, n_hosts // 2 + 48))


def _port_thread_workers(num_ports: int, net_size: str) -> int:
    cap = 64 if net_size in ("enterprise", "large") else 48
    return max(8, min(cap, num_ports))

OS = platform.system()
COMMON_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,
                1433,1521,3000,3306,3389,5432,5900,6379,8080,8443,8888,27017]

# ─────────────────────────────────────────────
#  DATABASE (optional — graceful fallback)
# ─────────────────────────────────────────────
try:
    from database import (
        init_db, save_scan, save_alert,
        get_scan_history, get_recent_alerts,
        get_known_devices, get_traffic_history,
        get_dashboard_summary, acknowledge_alert,
        get_port_changes, get_device_timeline
    )
    init_db()
    DB_AVAILABLE = True
    logger.info("Database connected")
except Exception as e:
    DB_AVAILABLE = False
    logger.warning("Database not available: %s", e)


# ─────────────────────────────────────────────
#  REAL TRAFFIC via psutil
# ─────────────────────────────────────────────
def get_real_traffic():
    try:
        n = psutil.net_io_counters()
        def fmt(b):
            if b >= 1_073_741_824: return f"{b/1_073_741_824:.2f} GB"
            if b >= 1_048_576: return f"{b/1_048_576:.2f} MB"
            if b >= 1024: return f"{b/1024:.2f} KB"
            return f"{b} B"
        return {
            "bytes_sent": fmt(n.bytes_sent),
            "bytes_received": fmt(n.bytes_recv),
            "packets_sent": f"{n.packets_sent:,}",
            "packets_received": f"{n.packets_recv:,}",
            "bytes_sent_raw": n.bytes_sent,
            "bytes_recv_raw": n.bytes_recv,
            "packets_sent_raw": n.packets_sent,
            "packets_recv_raw": n.packets_recv,
            "errin": n.errin,
            "errout": n.errout,
            "dropin": n.dropin,
            "dropout": n.dropout,
        }
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────
#  REAL PORT SCANNER
# ─────────────────────────────────────────────
def _port_connect_timeout_sec(port: int, rtt_ms: Optional[float]) -> float:
    if rtt_ms is None:
        ms = PORT_TIMEOUT_MED_MS
    elif rtt_ms < 10:
        ms = PORT_TIMEOUT_FAST_MS
    elif rtt_ms <= 50:
        ms = PORT_TIMEOUT_MED_MS
    else:
        ms = PORT_TIMEOUT_SLOW_MS
    if port in PORT_CRITICAL:
        ms = max(ms, PORT_CRITICAL_FLOOR_MS)
    return ms / 1000.0


def _tcp_probe(ip: str, port: int, timeout_sec: float):
    """
    Returns True if port accepts TCP, False if refused/reset quickly,
    None if timed out (inconclusive — caller may retry with longer timeout).
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout_sec)
    try:
        s.connect((ip, port))
    except socket.timeout:
        try:
            s.close()
        except OSError:
            pass
        return None
    except OSError:
        try:
            s.close()
        except OSError:
            pass
        return False
    else:
        try:
            s.close()
        except OSError:
            pass
        return True


def scan_port(ip, port, rtt_ms: Optional[float] = None):
    t = _port_connect_timeout_sec(port, rtt_ms)
    r = _tcp_probe(ip, port, t)
    if r is True:
        return port
    if r is None:
        t2 = max(PORT_TIMEOUT_SLOW_MS / 1000.0, t * 1.5)
        if port in PORT_CRITICAL:
            t2 = max(t2, PORT_CRITICAL_FLOOR_MS / 1000.0)
        if _tcp_probe(ip, port, t2) is True:
            return port
    return None


def scan_device_ports(ip, ports=None, net_size="small", rtt_ms: Optional[float] = None):
    if ports is None:
        ports = COMMON_PORTS
    workers = _port_thread_workers(len(ports), net_size)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(lambda p: scan_port(ip, p, rtt_ms), ports))
    return [p for p in results if p is not None]


# ─────────────────────────────────────────────
#  WIFI SCANNER
# ─────────────────────────────────────────────
class WiFiScanner:
    def get_connected_network(self):
        try:
            if OS == "Windows":
                result = subprocess.check_output(
                    ["netsh", "wlan", "show", "interfaces"],
                    encoding='utf-8', errors='ignore'
                )
                info = {}
                for line in result.split('\n'):
                    l = line.strip()
                    if "SSID" in l and "BSSID" not in l:
                        info['ssid'] = l.split(":", 1)[1].strip()
                    elif "BSSID" in l:
                        info['bssid'] = l.split(":", 1)[1].strip()
                    elif "Signal" in l:
                        info['signal'] = l.split(":", 1)[1].strip()
                    elif "Authentication" in l:
                        info['encryption'] = l.split(":", 1)[1].strip()
                    elif "Receive rate" in l:
                        info['rx_rate'] = l.split(":", 1)[1].strip()
                    elif "Transmit rate" in l:
                        info['tx_rate'] = l.split(":", 1)[1].strip()
                    elif "Radio type" in l:
                        info['radio'] = l.split(":", 1)[1].strip()
                    elif "Channel" in l:
                        info['channel'] = l.split(":", 1)[1].strip()
                return info
            elif OS == "Darwin":
                result = subprocess.check_output(
                    ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"],
                    encoding='utf-8'
                )
                info = {}
                for line in result.split('\n'):
                    l = line.strip()
                    if " SSID:" in line: info['ssid'] = l.split(":", 1)[1].strip()
                    elif "BSSID:" in line: info['bssid'] = l.split(":", 1)[1].strip()
                    elif "agrCtlRSSI:" in line: info['signal'] = l.split(":", 1)[1].strip() + " dBm"
                    elif "link auth:" in line: info['encryption'] = l.split(":", 1)[1].strip()
                    elif "channel:" in line: info['channel'] = l.split(":", 1)[1].strip()
                return info
            elif OS == "Linux":
                result = subprocess.check_output(
                    ["nmcli", "-t", "-f", "active,ssid,bssid,signal,security,freq", "dev", "wifi"],
                    encoding='utf-8'
                )
                for line in result.split('\n'):
                    if line.startswith("yes:"):
                        parts = line.split(':')
                        return {
                            'ssid': parts[1] if len(parts) > 1 else 'Unknown',
                            'bssid': parts[2] if len(parts) > 2 else 'Unknown',
                            'signal': parts[3] + "%" if len(parts) > 3 else 'Unknown',
                            'encryption': parts[4] if len(parts) > 4 else 'Unknown',
                            'frequency': parts[5] if len(parts) > 5 else 'Unknown',
                        }
                return {"error": "Not connected to WiFi"}
        except Exception as e:
            return {"error": str(e)}

    def assess_security(self, encryption_type):
        enc = encryption_type.lower()
        if any(x in enc for x in ['open', 'none', 'wep']):
            return {'threat_level': 'CRITICAL', 'mitm_risk': 'VERY HIGH',
                    'vulnerability': 'Unencrypted / WEP',
                    'description': 'No encryption. All traffic visible to anyone on network.',
                    'recommendation': 'Do not use. Connect via VPN only if unavoidable.',
                    'exploit_risk': '99.9%'}
        elif 'wpa3' in enc:
            return {'threat_level': 'SECURE', 'mitm_risk': 'VERY LOW',
                    'vulnerability': 'WPA3',
                    'description': 'WPA3 SAE prevents offline dictionary attacks and provides forward secrecy.',
                    'recommendation': 'Keep firmware updated. Monitor for rogue APs.',
                    'exploit_risk': '3.7%'}
        elif 'wpa2' in enc and 'enterprise' in enc:
            return {'threat_level': 'LOW', 'mitm_risk': 'LOW',
                    'vulnerability': 'WPA2-Enterprise (802.1X)',
                    'description': 'Per-user authentication prevents shared-key attacks.',
                    'recommendation': 'Validate server certificates. Deploy RADIUS.',
                    'exploit_risk': '12.3%'}
        elif 'wpa2' in enc:
            return {'threat_level': 'MEDIUM', 'mitm_risk': 'MODERATE',
                    'vulnerability': 'WPA2-PSK',
                    'description': 'KRACK vulnerability and 4-way handshake capture enable offline brute-force.',
                    'recommendation': 'Use passphrase 20+ characters. Upgrade to WPA3.',
                    'exploit_risk': '45.2%'}
        elif 'wpa' in enc:
            return {'threat_level': 'HIGH', 'mitm_risk': 'HIGH',
                    'vulnerability': 'WPA-TKIP (Deprecated)',
                    'description': 'TKIP is cryptographically broken. Subject to KRACK attacks.',
                    'recommendation': 'Upgrade router firmware to WPA2/WPA3 immediately.',
                    'exploit_risk': '85.4%'}
        else:
            return {'threat_level': 'UNKNOWN', 'mitm_risk': 'UNKNOWN',
                    'vulnerability': 'Unknown encryption',
                    'description': 'Cannot determine encryption type. Treat as untrusted.',
                    'recommendation': 'Investigate network security settings before using.',
                    'exploit_risk': 'N/A'}


# ─────────────────────────────────────────────
#  NETWORK SCANNER  (v4: 300+ device support)
# ─────────────────────────────────────────────
class NetworkScanner:

    _vendor_cache: dict = {}
    _vendor_cache_lock = threading.Lock()

    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "Unable to determine"

    def get_gateway(self):
        try:
            if OS == "Windows":
                result = subprocess.check_output(["ipconfig"], encoding='utf-8', errors='ignore')
                for line in result.split('\n'):
                    if "Default Gateway" in line and ":" in line:
                        gw = line.split(":")[-1].strip()
                        if gw and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', gw):
                            return gw
            else:
                result = subprocess.check_output(["ip", "route"], encoding='utf-8')
                for line in result.split('\n'):
                    if 'default' in line:
                        parts = line.split()
                        if len(parts) >= 3 and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parts[2]):
                            return parts[2]
        except:
            pass
        return "192.168.1.1"

    def get_network_range(self):
        try:
            local_ip = self.get_local_ip()
            if local_ip == "Unable to determine":
                return None
            addrs = psutil.net_if_addrs()
            for iface, addr_list in addrs.items():
                for addr in addr_list:
                    if addr.family == socket.AF_INET and addr.address == local_ip:
                        if addr.netmask:
                            interface = ipaddress.IPv4Interface(f"{local_ip}/{addr.netmask}")
                            return str(interface.network)
            parts = local_ip.split('.')
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        except:
            return None

    def detect_network_size(self, network_range):
        try:
            network = ipaddress.IPv4Network(network_range, strict=False)
            hosts = network.num_addresses - 2
            if hosts > 500:   return 'enterprise'
            elif hosts > 100: return 'large'
            else:             return 'small'
        except:
            return 'small'

    def _ping_ip_metrics(self, ip, timeout=0.5):
        try:
            cmd = (
                ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
                if OS == "Windows"
                else ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
            )
            r = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=timeout + 1.5,
            )
            ok = r.returncode == 0
            rtt, ttl = parse_ping_rtt_ttl(r.stdout or "", r.stderr or "")
            return ok, rtt, ttl
        except Exception:
            return False, None, None

    def _ping_ip(self, ip, timeout=0.5):
        ok, _, _ = self._ping_ip_metrics(ip, timeout)
        return ok

    def get_arp_table(self):
        devices = {}
        try:
            result = subprocess.check_output(["arp", "-a"], encoding='utf-8', errors='ignore')
            if OS == "Windows":
                for line in result.split('\n'):
                    ip_m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                    mac_m = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', line)
                    if ip_m and mac_m:
                        ip = ip_m.group(1)
                        mac = mac_m.group(0).upper().replace('-', ':')
                        if mac != 'FF:FF:FF:FF:FF:FF' and not mac.startswith('01:00:5E'):
                            devices[ip] = mac
            else:
                for line in result.split('\n'):
                    m = re.search(r'\(([\d.]+)\)\s+at\s+([\w:]+)', line)
                    if m:
                        ip, mac = m.group(1), m.group(2).upper()
                        if mac not in ('FF:FF:FF:FF:FF:FF', '<INCOMPLETE>') and 'incomplete' not in line.lower():
                            devices[ip] = mac
        except Exception as e:
            logger.warning("ARP error: %s", e)
        return devices

    def _arp_refresh_subnet(self, subnet_prefix, workers=None):
        batch = [f"{subnet_prefix}.{i}" for i in range(1, 255)]
        w = workers if workers is not None else _workers_for_host_count(len(batch), cap=512, floor=48)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(w, 512)) as ex:
                ex.map(lambda ip: subprocess.run(
                    ["ping", "-n", "1", "-w", "80", ip] if OS == "Windows"
                    else ["ping", "-c", "1", "-W", "1", ip],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=0.4
                ), batch)
        except Exception as e:
            logger.warning("[ARP_REFRESH] %s", e)

    def _get_vendor_live(self, mac):
        if not mac or mac in ('Unknown', '<INCOMPLETE>'):
            return None
        prefix = ':'.join(mac.upper().replace('-',':').split(':')[:3])
        with self._vendor_cache_lock:
            if prefix in self._vendor_cache:
                return self._vendor_cache[prefix]
        try:
            url = f"https://api.macvendors.com/{prefix}"
            req = _urlreq.Request(url, headers={'User-Agent': 'GARUDA/4.0'})
            with _urlreq.urlopen(req, timeout=2) as resp:
                vendor = resp.read().decode('utf-8').strip()
                if vendor and len(vendor) < 80:
                    with self._vendor_cache_lock:
                        self._vendor_cache[prefix] = vendor
                    return vendor
        except:
            pass
        with self._vendor_cache_lock:
            self._vendor_cache[prefix] = None
        return None

    def _get_vendor(self, mac):
        if not mac or mac in ('Unknown', '<INCOMPLETE>'):
            return 'Unknown'
        try:
            first_byte = int(mac.split(':')[0].replace('-',''), 16)
            if first_byte & 0x02:
                return 'Randomized MAC'
        except:
            pass
        oui = {
            # Apple
            '00:03:93':'Apple','00:05:02':'Apple','00:0A:27':'Apple','00:0A:95':'Apple',
            '00:11:24':'Apple','00:14:51':'Apple','00:16:CB':'Apple','00:17:F2':'Apple',
            '00:19:E3':'Apple','00:1B:63':'Apple','00:1C:B3':'Apple','00:1D:4F':'Apple',
            '00:1E:52':'Apple','00:1E:C2':'Apple','00:1F:5B':'Apple','00:1F:F3':'Apple',
            '00:21:E9':'Apple','00:22:41':'Apple','00:23:12':'Apple','00:23:32':'Apple',
            '00:23:6C':'Apple','00:24:36':'Apple','00:25:00':'Apple','00:25:4B':'Apple',
            '00:25:BC':'Apple','00:26:08':'Apple','00:26:4A':'Apple','00:26:B0':'Apple',
            '00:26:BB':'Apple','28:CF:E9':'Apple','3C:07:54':'Apple','3C:15:C2':'Apple',
            'A4:5E:60':'Apple','A8:66:7F':'Apple','AC:87:A3':'Apple','B8:17:C2':'Apple',
            'B8:8D:12':'Apple','BC:52:B7':'Apple','C8:2A:14':'Apple','C8:33:4B':'Apple',
            'D0:03:4B':'Apple','D0:23:DB':'Apple','D8:96:95':'Apple','DC:2B:2A':'Apple',
            'E0:5F:45':'Apple','E4:CE:8F':'Apple','F0:18:98':'Apple','F0:F6:1C':'Apple',
            'F4:F1:5A':'Apple','F8:1E:DF':'Apple','F8:27:93':'Apple','98:01:A7':'Apple',
            # Samsung
            '00:12:47':'Samsung','00:12:FB':'Samsung','00:13:77':'Samsung',
            '00:15:99':'Samsung','00:15:B9':'Samsung','00:16:32':'Samsung',
            '00:17:C9':'Samsung','00:17:D5':'Samsung','00:18:AF':'Samsung',
            '00:1A:8A':'Samsung','00:1B:98':'Samsung','00:1C:43':'Samsung',
            '00:1D:25':'Samsung','00:1E:7D':'Samsung','00:1F:CC':'Samsung',
            '00:21:19':'Samsung','00:23:39':'Samsung','00:23:99':'Samsung',
            '00:24:54':'Samsung','00:24:90':'Samsung','00:25:66':'Samsung',
            '00:26:37':'Samsung','34:AA:8B':'Samsung','38:AA:3C':'Samsung',
            '40:0E:85':'Samsung','44:4E:1A':'Samsung','50:32:37':'Samsung',
            '5C:0A:5B':'Samsung','60:6B:FF':'Samsung','6C:2F:2C':'Samsung',
            '70:F9:27':'Samsung','74:45:8A':'Samsung','78:25:AD':'Samsung',
            '84:25:DB':'Samsung','88:32:9B':'Samsung','8C:77:12':'Samsung',
            '90:18:7C':'Samsung','94:35:0A':'Samsung','98:39:8E':'Samsung',
            '9C:3A:AF':'Samsung','A0:0B:BA':'Samsung','A4:07:B6':'Samsung',
            'B4:79:A7':'Samsung','BC:20:A4':'Samsung','C4:42:02':'Samsung',
            'CC:07:AB':'Samsung','D0:17:6A':'Samsung','D0:22:BE':'Samsung',
            'E4:12:1D':'Samsung','E4:40:E2':'Samsung','F4:7B:5E':'Samsung',
            # Xiaomi
            '00:9E:C8':'Xiaomi','10:2A:B3':'Xiaomi','14:F6:5A':'Xiaomi',
            '18:31:BF':'Xiaomi','20:82:C0':'Xiaomi','28:6C:07':'Xiaomi',
            '34:80:B3':'Xiaomi','38:A4:ED':'Xiaomi','3C:BD:D8':'Xiaomi',
            '50:64:2B':'Xiaomi','58:44:98':'Xiaomi','64:09:80':'Xiaomi',
            '64:B4:73':'Xiaomi','68:DF:DD':'Xiaomi','74:23:44':'Xiaomi',
            '78:02:F8':'Xiaomi','7C:1D:D9':'Xiaomi','8C:BE:BE':'Xiaomi',
            'A0:86:C6':'Xiaomi','AC:F7:F3':'Xiaomi','B0:E2:35':'Xiaomi',
            'C4:0B:CB':'Xiaomi','D4:97:0B':'Xiaomi','F0:B4:29':'Xiaomi',
            'FC:64:BA':'Xiaomi',
            # OnePlus
            '00:14:A4':'OnePlus','04:D6:AA':'OnePlus','1C:77:F6':'OnePlus',
            '48:DB:50':'OnePlus','5E:91:1F':'OnePlus','8C:47:BE':'OnePlus',
            'AC:37:43':'OnePlus','C4:69:CD':'OnePlus','CC:1B:E0':'OnePlus',
            'E8:9F:80':'OnePlus',
            # Realme / OPPO
            '00:1E:42':'Realme/OPPO','04:92:26':'Realme/OPPO','1C:F1:CE':'Realme/OPPO',
            '20:C3:A1':'Realme/OPPO','2C:8A:72':'Realme/OPPO','38:37:8B':'Realme/OPPO',
            '44:45:53':'Realme/OPPO','48:4B:AA':'Realme/OPPO','58:A2:B5':'Realme/OPPO',
            '6C:5C:14':'Realme/OPPO','88:36:6C':'Realme/OPPO','9C:8E:CD':'Realme/OPPO',
            'A4:63:FC':'Realme/OPPO','B0:D0:9C':'Realme/OPPO','D4:F5:EF':'Realme/OPPO',
            'E4:B0:21':'Realme/OPPO','EC:BA:CA':'Realme/OPPO','F4:63:1F':'Realme/OPPO',
            # Vivo
            '00:25:96':'Vivo','00:A0:DE':'Vivo','1C:5C:F2':'Vivo','20:47:DA':'Vivo',
            '28:35:CD':'Vivo','30:3A:64':'Vivo','38:BC:1A':'Vivo','40:25:C2':'Vivo',
            '58:2A:F7':'Vivo','5C:E8:EB':'Vivo','7C:83:34':'Vivo','88:25:93':'Vivo',
            '9C:CC:B5':'Vivo','A4:50:46':'Vivo','B0:5C:DA':'Vivo','C4:AC:59':'Vivo',
            'D8:F2:CA':'Vivo','E4:4E:2D':'Vivo','F4:28:53':'Vivo',
            # Huawei
            '00:18:82':'Huawei','00:1E:10':'Huawei','00:25:9E':'Huawei',
            '00:46:4B':'Huawei','04:02:1F':'Huawei','04:75:03':'Huawei',
            '04:BD:70':'Huawei','04:C0:6F':'Huawei','04:F9:38':'Huawei',
            '08:19:A6':'Huawei','08:7A:4C':'Huawei','0C:37:DC':'Huawei',
            '0C:96:BF':'Huawei','10:1B:54':'Huawei','10:47:80':'Huawei',
            '14:9F:E8':'Huawei','18:C5:8A':'Huawei','1C:8E:5C':'Huawei',
            '20:08:ED':'Huawei','20:F1:7C':'Huawei','24:09:95':'Huawei',
            '28:31:52':'Huawei','28:6E:D4':'Huawei','2C:9D:1E':'Huawei',
            '30:D1:7E':'Huawei','34:6B:D3':'Huawei','38:37:8B':'Huawei',
            '3C:47:11':'Huawei','40:CB:A8':'Huawei','44:A1:91':'Huawei',
            '48:00:31':'Huawei','4C:8B:EF':'Huawei','50:01:D0':'Huawei',
            '54:51:1B':'Huawei','54:89:98':'Huawei','58:60:5F':'Huawei',
            '5C:4C:A9':'Huawei','60:DE:44':'Huawei','64:A6:51':'Huawei',
            '68:13:24':'Huawei','6C:8D:C1':'Huawei','70:72:3C':'Huawei',
            '74:04:F1':'Huawei','78:1D:BA':'Huawei','7C:11:CB':'Huawei',
            '80:38:BC':'Huawei','80:71:7A':'Huawei','84:74:2A':'Huawei',
            '88:E3:AB':'Huawei','8C:34:FD':'Huawei','90:17:AC':'Huawei',
            '94:04:9C':'Huawei','94:77:2B':'Huawei','98:E7:F4':'Huawei',
            '9C:28:EF':'Huawei','A0:08:6F':'Huawei','A4:99:47':'Huawei',
            'A8:CA:7B':'Huawei','AC:4E:91':'Huawei','B0:6E:BF':'Huawei',
            'B4:15:13':'Huawei','B8:08:D7':'Huawei','BC:25:E0':'Huawei',
            'C0:4A:00':'Huawei','C4:07:2F':'Huawei','C8:14:79':'Huawei',
            'CC:53:B5':'Huawei','D0:7A:B5':'Huawei','D4:6A:A8':'Huawei',
            'D8:49:2F':'Huawei','DC:D2:FC':'Huawei','E0:19:1D':'Huawei',
            'E4:A4:71':'Huawei','E8:CD:2D':'Huawei','EC:23:3D':'Huawei',
            'F0:79:59':'Huawei','F4:4C:7F':'Huawei','F8:01:13':'Huawei',
            'FC:48:EF':'Huawei',
            # TP-Link
            '00:27:19':'TP-Link','14:CC:20':'TP-Link','18:A6:F7':'TP-Link',
            '1C:61:B4':'TP-Link','20:DC:E6':'TP-Link','24:69:A5':'TP-Link',
            '2C:F0:5D':'TP-Link','30:DE:4B':'TP-Link','30:FC:68':'TP-Link',
            '38:94:ED':'TP-Link','40:16:9F':'TP-Link','44:33:4C':'TP-Link',
            '50:C7:BF':'TP-Link','54:AF:97':'TP-Link','54:E6:FC':'TP-Link',
            '5C:89:9A':'TP-Link','60:32:B1':'TP-Link','60:E3:27':'TP-Link',
            '64:70:02':'TP-Link','6C:5A:B0':'TP-Link','70:4F:57':'TP-Link',
            '74:DA:38':'TP-Link','78:8A:20':'TP-Link','7C:8B:CA':'TP-Link',
            '80:35:C1':'TP-Link','84:D6:D0':'TP-Link','90:F6:52':'TP-Link',
            '94:D9:B3':'TP-Link','98:DA:C4':'TP-Link','9C:A6:15':'TP-Link',
            'A0:F3:C1':'TP-Link','AC:84:C9':'TP-Link','B0:95:75':'TP-Link',
            'B4:B0:24':'TP-Link','C0:25:E9':'TP-Link','C4:6E:1F':'TP-Link',
            'CC:32:E5':'TP-Link','D8:0D:17':'TP-Link','E4:D3:32':'TP-Link',
            'E8:94:F6':'TP-Link','EC:08:6B':'TP-Link','F0:9F:C2':'TP-Link',
            'F4:EC:38':'TP-Link','FC:EC:DA':'TP-Link',
            # Cisco
            '00:00:0C':'Cisco','00:01:42':'Cisco','00:01:43':'Cisco',
            '00:01:63':'Cisco','00:01:64':'Cisco','00:01:96':'Cisco',
            '00:01:97':'Cisco','00:01:C7':'Cisco','00:02:16':'Cisco',
            '00:02:17':'Cisco','00:02:3D':'Cisco','00:02:3E':'Cisco',
            '00:02:4A':'Cisco','00:02:4B':'Cisco','00:03:31':'Cisco',
            '00:03:32':'Cisco','00:03:6B':'Cisco','00:03:6C':'Cisco',
            '00:03:FD':'Cisco','00:03:FE':'Cisco','00:04:27':'Cisco',
            '00:04:28':'Cisco','00:04:9A':'Cisco','00:04:9B':'Cisco',
            '00:04:C0':'Cisco','00:04:C1':'Cisco','00:04:DD':'Cisco',
            '00:05:00':'Cisco','00:05:01':'Cisco','00:05:31':'Cisco',
            '00:05:32':'Cisco','00:05:5E':'Cisco','00:05:5F':'Cisco',
            '00:05:74':'Cisco','00:05:75':'Cisco','00:05:9A':'Cisco',
            '00:06:28':'Cisco','00:06:52':'Cisco','00:06:53':'Cisco',
            '00:06:7C':'Cisco','00:07:0D':'Cisco','00:07:0E':'Cisco',
            '00:07:50':'Cisco','00:07:7D':'Cisco','00:07:85':'Cisco',
            '00:07:B3':'Cisco','00:08:20':'Cisco','00:08:21':'Cisco',
            '00:08:30':'Cisco','00:09:11':'Cisco','00:09:43':'Cisco',
            '00:09:44':'Cisco','00:09:7B':'Cisco','00:09:B7':'Cisco',
            '00:09:E8':'Cisco','00:0A:41':'Cisco','00:0A:42':'Cisco',
            '00:0A:8A':'Cisco','00:0A:B8':'Cisco','00:0A:F3':'Cisco',
            '00:0B:45':'Cisco','00:0B:46':'Cisco','00:0B:5F':'Cisco',
            '00:0B:60':'Cisco','00:0B:85':'Cisco','00:0B:BE':'Cisco',
            '00:0B:FC':'Cisco','00:0B:FD':'Cisco','00:0C:30':'Cisco',
            '00:1A:A1':'Cisco','00:1B:44':'Cisco','00:1C:57':'Cisco',
            '00:1D:45':'Cisco','00:1E:13':'Cisco','00:1E:14':'Cisco',
            '00:1E:49':'Cisco','00:1E:4A':'Cisco','00:1E:79':'Cisco',
            '00:1F:CA':'Cisco','00:1F:CB':'Cisco','00:21:1B':'Cisco',
            '00:22:0C':'Cisco','00:22:0D':'Cisco','00:22:55':'Cisco',
            '00:22:BD':'Cisco','00:22:BE':'Cisco','00:23:04':'Cisco',
            '00:23:33':'Cisco','00:23:34':'Cisco','00:23:5E':'Cisco',
            '00:23:EB':'Cisco','00:24:13':'Cisco','00:24:14':'Cisco',
            '00:24:97':'Cisco','00:25:45':'Cisco','00:25:46':'Cisco',
            '00:25:84':'Cisco','00:26:99':'Cisco','00:26:CB':'Cisco',
            # D-Link
            '00:05:5D':'D-Link','00:0D:88':'D-Link','00:0F:3D':'D-Link',
            '00:11:95':'D-Link','00:13:46':'D-Link','00:15:E9':'D-Link',
            '00:17:9A':'D-Link','00:19:5B':'D-Link','00:1B:11':'D-Link',
            '00:1C:F0':'D-Link','00:1E:58':'D-Link','00:21:91':'D-Link',
            '00:22:B0':'D-Link','00:24:01':'D-Link','00:26:5A':'D-Link',
            '00:17:C8':'D-Link','1C:7E:E5':'D-Link','28:10:7B':'D-Link',
            '2C:B0:5D':'D-Link','34:08:04':'D-Link','5C:D9:98':'D-Link',
            '84:C9:B2':'D-Link','90:94:E4':'D-Link','9C:D6:43':'D-Link',
            'C8:BE:19':'D-Link','CC:B2:55':'D-Link','F0:7D:68':'D-Link',
            # Microsoft
            '00:03:FF':'Microsoft','00:0D:3A':'Microsoft','00:12:5A':'Microsoft',
            '00:15:5D':'Microsoft','00:17:FA':'Microsoft','00:1D:D8':'Microsoft',
            '00:22:48':'Microsoft','00:50:F2':'Microsoft','28:18:78':'Microsoft',
            '28:F0:76':'Microsoft','48:50:73':'Microsoft','60:45:BD':'Microsoft',
            '7C:1E:52':'Microsoft','98:5F:D3':'Microsoft','B8:AC:6F':'Microsoft',
            'DC:53:60':'Microsoft',
            # Google
            '00:1A:11':'Google','3C:5A:B4':'Google','54:60:09':'Google',
            'F4:F5:D8':'Google','94:EB:2C':'Google','20:DF:B9':'Google',
            'A4:77:33':'Google','E4:F0:42':'Google',
            # Amazon
            '00:BB:3A':'Amazon','04:A2:22':'Amazon','0C:47:C9':'Amazon',
            '0C:D6:96':'Amazon','18:74:2E':'Amazon','1C:12:B0':'Amazon',
            '20:C9:D0':'Amazon','34:D2:70':'Amazon','40:B4:CD':'Amazon',
            '44:65:0D':'Amazon','50:DC:E7':'Amazon','68:37:E9':'Amazon',
            '74:C2:46':'Amazon','84:D6:D0':'Amazon','A0:02:DC':'Amazon',
            'B4:7C:9C':'Amazon','C4:46:E1':'Amazon','CC:9E:A2':'Amazon',
            'F0:27:2D':'Amazon','F0:A7:31':'Amazon','FC:A6:67':'Amazon',
            # Raspberry Pi
            'B8:27:EB':'Raspberry Pi','DC:A6:32':'Raspberry Pi','E4:5F:01':'Raspberry Pi',
            # VMware / Virtual
            '00:0C:29':'VMware','00:50:56':'VMware','00:05:69':'VMware',
            '08:00:27':'VirtualBox','52:54:00':'QEMU/KVM',
            # Intel
            '00:02:B3':'Intel','00:03:47':'Intel','00:04:23':'Intel',
            '00:07:E9':'Intel','00:08:74':'Intel','00:0C:F1':'Intel',
            '00:0D:60':'Intel','00:0E:0C':'Intel','00:0E:35':'Intel',
            '00:11:11':'Intel','00:12:F0':'Intel','00:13:02':'Intel',
            '00:13:20':'Intel','00:13:CE':'Intel','00:13:E8':'Intel',
            '00:15:00':'Intel','00:16:EA':'Intel','00:16:EB':'Intel',
            '00:16:76':'Intel','00:18:DE':'Intel','00:19:D1':'Intel',
            '00:19:D2':'Intel','00:1B:21':'Intel','00:1C:C0':'Intel',
            '00:1D:E0':'Intel','00:1D:E1':'Intel','00:1E:64':'Intel',
            '00:1E:65':'Intel','00:1F:3B':'Intel','00:1F:3C':'Intel',
            '00:21:5D':'Intel','00:21:5E':'Intel','00:21:6A':'Intel',
            '00:22:FA':'Intel','00:23:14':'Intel','00:24:D7':'Intel',
            '00:27:10':'Intel','2C:6E:85':'Intel','34:02:86':'Intel',
            '38:DE:AD':'Intel','3C:A9:F4':'Intel','40:25:C2':'Intel',
            '44:39:C4':'Intel','48:A4:72':'Intel','4C:34:88':'Intel',
            '54:27:1E':'Intel','58:FB:84':'Intel','5C:AC:4C':'Intel',
            '60:67:20':'Intel','68:05:CA':'Intel','6C:88:14':'Intel',
            '70:5A:B6':'Intel','78:92:9C':'Intel','7C:76:35':'Intel',
            '80:19:34':'Intel','84:8F:69':'Intel','88:78:73':'Intel',
            '8C:EC:7B':'Intel','90:48:9A':'Intel','94:65:9C':'Intel',
            '98:4F:EE':'Intel','9C:4E:36':'Intel','A0:36:9F':'Intel',
            'A4:34:D9':'Intel','A8:7E:EA':'Intel','AC:7B:A1':'Intel',
            'B0:6E:BF':'Intel','B4:B6:76':'Intel','B8:70:F4':'Intel',
            'BC:0F:9A':'Intel','C0:3F:D5':'Intel','C4:85:08':'Intel',
            'C8:F7:50':'Intel','D0:50:99':'Intel','D4:BE:D9':'Intel',
            'D8:FC:93':'Intel','DC:53:60':'Intel','E0:94:67':'Intel',
            'E4:B3:18':'Intel','E8:11:32':'Intel','EC:F4:BB':'Intel',
            'F0:DE:F1':'Intel','F4:06:69':'Intel','F4:8C:50':'Intel',
            'F8:16:54':'Intel','FC:F8:AE':'Intel',
            # Qualcomm Atheros
            '00:03:7F':'Atheros','00:13:74':'Atheros','00:1A:EF':'Atheros',
            '08:EA:44':'Qualcomm','30:14:4A':'Qualcomm','40:01:7A':'Qualcomm',
            '58:8B:F3':'Qualcomm','64:A2:F9':'Qualcomm','7C:B0:C2':'Qualcomm',
            'A0:86:C6':'Qualcomm','D4:21:22':'Qualcomm',
            # Broadcom
            '00:10:18':'Broadcom','00:90:4C':'Broadcom','00:E0:21':'Broadcom',
            '98:DE:D0':'Broadcom','B8:47:AD':'Broadcom',
        }
        mac_upper = mac.upper().replace('-', ':')
        prefix = ':'.join(mac_upper.split(':')[:3])
        local_result = oui.get(prefix, None)
        if local_result:
            return local_result
        live = self._get_vendor_live(mac)
        return live if live else 'Unknown Vendor'

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            pass
        try:
            if OS == 'Windows':
                result = subprocess.check_output(
                    ['nbtstat', '-A', ip],
                    encoding='utf-8', errors='ignore',
                    timeout=2, stderr=subprocess.DEVNULL
                )
                for line in result.split('\n'):
                    m = re.search(r'^\s+(\S+)\s+<00>\s+UNIQUE', line)
                    if m:
                        name = m.group(1).strip()
                        if name and name != '__MSBROWSE__':
                            return name
        except:
            pass
        try:
            if OS == 'Linux':
                r = subprocess.check_output(
                    ['avahi-resolve', '-a', ip],
                    encoding='utf-8', errors='ignore', timeout=2,
                    stderr=subprocess.DEVNULL
                )
                parts = r.strip().split()
                if len(parts) >= 2:
                    return parts[-1].rstrip('.')
            elif OS == 'Darwin':
                r = subprocess.check_output(
                    ['dns-sd', '-Q', ip, 'PTR'],
                    encoding='utf-8', errors='ignore', timeout=2,
                    stderr=subprocess.DEVNULL
                )
                for line in r.split('\n'):
                    if '.local' in line:
                        m = re.search(r'(\S+\.local)', line)
                        if m:
                            return m.group(1).rstrip('.')
        except:
            pass
        try:
            host, _ = socket.getnameinfo((ip, 0), 0)
            if host and host != ip:
                return host
        except OSError:
            pass
        return None

    def get_connected_devices(self, max_devices=300):
        network_range = self.get_network_range()
        if not network_range:
            return [], 0, 'unknown'
        try:
            net_size = self.detect_network_size(network_range)
            network = ipaddress.IPv4Network(network_range, strict=False)
            ip_list = [str(ip) for ip in network.hosts()]
            local_ip = self.get_local_ip()
            gateway_ip = self.get_gateway()

            if net_size == 'enterprise':
                ping_timeout = 0.12
                cap = 512
                arp_wait = 0
                skip_ping = True
                logger.info("[SCAN] Enterprise network (%s hosts) — ARP-only mode", len(ip_list))
            elif net_size == 'large':
                ping_timeout = 0.18
                cap = 420
                arp_wait = 0
                skip_ping = True
                logger.info("[SCAN] Large network (%s hosts) — ARP-only mode", len(ip_list))
            else:
                ping_timeout = 0.4
                cap = 200
                arp_wait = 2.0
                skip_ping = False
                logger.info("[SCAN] Home network (%s hosts) — full scan mode", len(ip_list))

            workers = _workers_for_host_count(len(ip_list), cap=cap, floor=32)

            active_ips = set()
            ip_metrics = {}

            if skip_ping:
                network_obj = ipaddress.IPv4Network(network_range, strict=False)
                subnets_24 = list(network_obj.subnets(new_prefix=24)) if network_obj.prefixlen < 24 else [network_obj]
                logger.info("[SCAN] Refreshing ARP for %s subnet(s)...", len(subnets_24))
                refresh_workers = _workers_for_host_count(254 * len(subnets_24), cap=512, floor=64)
                for sn in subnets_24:
                    prefix = '.'.join(str(sn.network_address).split('.')[:3])
                    self._arp_refresh_subnet(prefix, workers=refresh_workers)
                time.sleep(1.0)
            else:
                arp_preview = self.get_arp_table()
                for ip in ip_list:
                    mac = arp_preview.get(ip)
                    if mac and mac not in ('Unknown', '<INCOMPLETE>') and not mac.startswith('01:00:5E'):
                        active_ips.add(ip)
                to_ping = [ip for ip in ip_list if ip not in active_ips]

                def _ping_one(ip_):
                    return ip_, *self._ping_ip_metrics(ip_, ping_timeout)

                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                    future_to_ip = {ex.submit(_ping_one, ip): ip for ip in to_ping}
                    for future in concurrent.futures.as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            _, ok, rtt, ttl = future.result()
                            if ok:
                                active_ips.add(ip)
                            ip_metrics[ip] = (rtt, ttl)
                        except Exception:
                            ip_metrics[ip] = (None, None)
                remaining = [ip for ip in ip_list if ip not in active_ips]

                def _ping_one_short(ip_):
                    return ip_, *self._ping_ip_metrics(ip_, 0.3)

                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
                    for ip_, ok, rtt, ttl in ex.map(_ping_one_short, remaining):
                        if ok:
                            active_ips.add(ip_)
                        if ip_ not in ip_metrics or ip_metrics[ip_][0] is None:
                            ip_metrics[ip_] = (rtt, ttl)
                time.sleep(arp_wait)

            arp = self.get_arp_table()
            all_ips = active_ips.union(set(arp.keys()))

            priority_ips = {gateway_ip, local_ip}
            other_ips = sorted(
                [ip for ip in all_ips if ip not in priority_ips
                 and not ip.endswith('.255') and not ip.endswith('.0')],
                key=lambda x: list(map(int, x.split('.')))
            )

            capped = list(priority_ips.intersection(all_ips)) + other_ips
            total_found = len(capped)
            exceeded_cap = total_found > max_devices
            capped = capped[:max_devices]

            if exceeded_cap:
                logger.warning("[SCAN] WARNING: %s found — cap %s. Use ?max_devices=N to increase.", total_found, max_devices)

            hostname_map = {}
            if capped:
                def resolve_hostname_fast(ip):
                    try:
                        return ip, socket.gethostbyaddr(ip)[0]
                    except:
                        return ip, None

                valid_ips = [ip for ip in capped if not ip.endswith('.255') and not ip.endswith('.0')]
                hn_workers = max(8, min(60, workers))
                with concurrent.futures.ThreadPoolExecutor(max_workers=hn_workers) as ex:
                    for ip, hn in ex.map(resolve_hostname_fast, valid_ips):
                        if hn:
                            hostname_map[ip] = hn

                if net_size != 'enterprise':
                    no_hostname = [ip for ip in valid_ips if ip not in hostname_map]
                    hn2 = max(4, min(24, workers // 4 or 12))
                    with concurrent.futures.ThreadPoolExecutor(max_workers=hn2) as ex:
                        futures = {ex.submit(self.get_hostname, ip): ip for ip in no_hostname}
                        for future in concurrent.futures.as_completed(futures):
                            ip = futures[future]
                            try:
                                hn = future.result()
                                if hn:
                                    hostname_map[ip] = hn
                            except:
                                pass

            devices = []
            for ip in capped:
                if ip.endswith('.255') or ip.endswith('.0'):
                    continue
                mac = arp.get(ip, 'Unknown')
                vendor = self._get_vendor(mac)
                hostname = hostname_map.get(ip)
                display = hostname or (vendor if vendor not in ('Unknown Vendor', 'Randomized MAC') else None) or mac
                rtt_m, ttl_v = ip_metrics.get(ip, (None, None))
                devices.append({
                    'ip': ip,
                    'mac': mac,
                    'vendor': vendor,
                    'hostname': hostname,
                    'display_name': display,
                    'status': 'ACTIVE' if ip in active_ips else 'DETECTED',
                    'detection_method': 'PING+ARP' if ip in active_ips else 'ARP_ONLY',
                    'ping_rtt_ms': rtt_m,
                    'icmp_ttl': ttl_v,
                })

            logger.info("[SCAN] Found %s devices — showing %s (cap: %s)", total_found, len(devices), max_devices)
            return devices, total_found, net_size

        except Exception as e:
            logger.exception("Scan error: %s", e)
            return [], 0, 'unknown'

    def get_interface_stats(self):
        try:
            stats = {}
            io = psutil.net_io_counters(pernic=True)
            addrs = psutil.net_if_addrs()
            for iface, counters in io.items():
                ip = None
                for addr in addrs.get(iface, []):
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                if ip and not ip.startswith('127.'):
                    stats[iface] = {
                        'ip': ip,
                        'bytes_sent': counters.bytes_sent,
                        'bytes_recv': counters.bytes_recv,
                        'packets_sent': counters.packets_sent,
                        'packets_recv': counters.packets_recv,
                    }
            return stats
        except:
            return {}


# ─────────────────────────────────────────────
#  ATTACK PREDICTOR
# ─────────────────────────────────────────────
class AttackPredictor:
    WEIGHTS = {
        'encryption': 0.28,
        'unknown_devices': 0.18,
        'arp_anomalies': 0.15,
        'open_ports': 0.15,
        'device_density': 0.12,
        'traffic_anomaly': 0.12,
    }

    def predict(self, scan_data):
        enc = scan_data.get('connected_network', {}).get('encryption', '').lower()
        devices = scan_data.get('connected_devices', [])
        traffic = scan_data.get('network_traffic', {})
        port_data = scan_data.get('port_scan', {})
        scores = {}

        if any(x in enc for x in ['open', 'none', 'wep']):
            scores['encryption'] = 1.0
        elif 'wpa3' in enc:
            scores['encryption'] = 0.05
        elif 'wpa2' in enc and 'enterprise' in enc:
            scores['encryption'] = 0.12
        elif 'wpa2' in enc:
            scores['encryption'] = 0.45
        elif 'wpa' in enc:
            scores['encryption'] = 0.82
        else:
            scores['encryption'] = 0.55

        total = max(len(devices), 1)
        unknown = [d for d in devices if d.get('vendor', 'Unknown') in ('Unknown', 'Unknown Vendor')]
        scores['unknown_devices'] = min(len(unknown) / total, 1.0)

        arp_only = [d for d in devices if d.get('detection_method') == 'ARP_ONLY']
        scores['arp_anomalies'] = min(len(arp_only) / total * 1.3, 1.0)

        total_open = sum(len(v) for v in port_data.values())
        risky_ports_set = set(RISKY_PORT_META.keys())
        risky_open = sum(1 for ports in port_data.values() for p in ports if p in risky_ports_set)
        weighted = 0.0
        for ports in port_data.values():
            for p in ports:
                if p in RISKY_PORT_META:
                    sev = RISKY_PORT_META[p][1]
                    weighted += SEVERITY_RANK.get(sev, 1) * 0.15
        scores['open_ports'] = min((total_open / 10 + weighted * 0.25 + risky_open * 0.12), 1.0)

        scores['device_density'] = min(total / 300, 1.0)

        errin = traffic.get('errin', 0) or 0
        dropin = traffic.get('dropin', 0) or 0
        pkts = max(traffic.get('packets_recv_raw', 1) or 1, 1)
        scores['traffic_anomaly'] = min((errin + dropin) / pkts * 100, 1.0)

        total_risk = sum(scores[k] * self.WEIGHTS[k] for k in scores)
        risk_pct = round(total_risk * 100, 1)

        if risk_pct >= 70: label, color = 'CRITICAL', '#ef4444'
        elif risk_pct >= 45: label, color = 'HIGH', '#f97316'
        elif risk_pct >= 25: label, color = 'MEDIUM', '#f59e0b'
        else: label, color = 'LOW', '#10b981'

        return {
            'risk_score': risk_pct,
            'risk_label': label,
            'risk_color': color,
            'component_scores': {k: round(v*100, 1) for k, v in scores.items()},
            'attack_predictions': self._attacks(scores, enc, devices, port_data),
            'scan_timestamp': datetime.now().isoformat()
        }

    def _attacks(self, scores, enc, devices, port_data):
        attacks = []
        if scores['encryption'] > 0.6:
            attacks.append({'type':'Man-in-the-Middle (MITM)','probability':round(scores['encryption']*85,1),'severity':'Critical','description':'Weak/no encryption allows full traffic interception'})
        if scores['unknown_devices'] > 0.3:
            cnt = round(scores['unknown_devices']*len(devices))
            attacks.append({'type':'Rogue Device / Unauthorized Access','probability':round(scores['unknown_devices']*78,1),'severity':'High','description':f'{cnt} unidentified devices on network'})
        if scores['arp_anomalies'] > 0.25:
            attacks.append({'type':'ARP Spoofing / Cache Poisoning','probability':round(scores['arp_anomalies']*82,1),'severity':'High','description':'ARP-only devices detected — possible cache poisoning'})

        found_risky = {}
        for ip, ports in port_data.items():
            for p in ports:
                if p in RISKY_PORT_META:
                    name, sev = RISKY_PORT_META[p]
                    if name not in found_risky:
                        found_risky[name] = {'ips': [], 'severity': sev}
                    found_risky[name]['ips'].append(ip)
                    cur = found_risky[name]['severity']
                    if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(cur, 0):
                        found_risky[name]['severity'] = sev
        for svc, meta in found_risky.items():
            ips = meta.get('ips', [])
            sev = meta.get('severity', 'MEDIUM')
            sev_label = sev.capitalize() if isinstance(sev, str) else 'Medium'
            prob = min(95.0, 55.0 + len(ips) * 6.0 + SEVERITY_RANK.get(sev, 2) * 5.0)
            attacks.append({
                'type': f'{svc} Service Exposure',
                'probability': round(prob, 1),
                'severity': sev_label,
                'description': f'{svc} open on {len(ips)} device(s) — commonly exploited',
                'affected_devices': ', '.join(ips[:8]) + ('…' if len(ips) > 8 else ''),
            })

        if 'wpa2' in enc and 'enterprise' not in enc:
            attacks.append({'type':'WPA2 KRACK / Handshake Capture','probability':45.2,'severity':'Medium','description':'WPA2-PSK susceptible to 4-way handshake capture (CVE-2017-13077)'})

        attacks.sort(key=lambda x: x['probability'], reverse=True)
        return attacks[:5]


# ─────────────────────────────────────────────
#  INIT
# ─────────────────────────────────────────────
wifi_sc = WiFiScanner()
net_sc = NetworkScanner()
predictor = AttackPredictor()


# ─────────────────────────────────────────────
#  STATIC FILE SERVING
# ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))


from flask_limiter.errors import RateLimitExceeded


@app.errorhandler(RateLimitExceeded)
def _rate_limit_exceeded(_exc):
    return _api_envelope(False, error="Too many requests. Please wait before retrying.", status=429)


@app.after_request
def _security_headers(response):
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Content-Security-Policy", app.config.get("GARUDA_CSP", ""))
    return response


@app.errorhandler(Exception)
def _handle_exception(exc):
    if isinstance(exc, HTTPException):
        code = exc.code or 500
        msg = exc.description or exc.name
        return _api_envelope(False, error=msg, status=code)
    logger.exception("Unhandled server error: %s", exc)
    return _api_envelope(False, error="Internal server error", status=500)


def _parse_int_arg(name: str, default: int, min_v: int, max_v: int):
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default, None
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return None, f"Invalid {name}: expected integer"
    if v < min_v or v > max_v:
        return None, f"{name} must be between {min_v} and {max_v}"
    return v, None


@app.route('/')
def serve_landing():
    return send_from_directory(BASE_DIR, 'garuda-landing.html')

@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory(BASE_DIR, filename)


# ─────────────────────────────────────────────
#  API ENDPOINTS
# ─────────────────────────────────────────────
@app.route('/api/health', methods=['GET'])
def health():
    payload = {
        'status': 'OPERATIONAL',
        'system': OS,
        'version': '4.1',
        'db_available': DB_AVAILABLE,
        'features': ['real-traffic-psutil', 'real-port-scan', 'real-arp-ping',
                     'attack-prediction', 'history-db', '300-device-support',
                     'live-vendor-api', 'mdns-lookup', 'chunked-arp-refresh',
                     'api-envelope', 'rate-limits', 'security-headers', 'sse-alert-stream'],
        'ui_poll_interval': config.UI_POLL_INTERVAL_SEC
    }
    return _api_envelope(True, data=payload)


@app.route("/api/stream/alerts", methods=["GET"])
@limiter.exempt
def stream_alerts():
    from alert_bus import register_client, unregister_client

    def gen():
        q = register_client()
        try:
            yield "event: ping\ndata: {}\n\n"
            while True:
                try:
                    line = q.get(timeout=25)
                    yield f"data: {line}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            unregister_client(q)

    return Response(
        stream_with_context(gen()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _execute_full_scan():
    t_start = time.time()
    max_dev, err = _parse_int_arg('max_devices', 300, 1, 1000)
    if err:
        return _api_envelope(False, error=err, status=400)

    connected = wifi_sc.get_connected_network()
    if 'error' in connected:
        return _api_envelope(False, error=connected['error'], status=400)

    security = wifi_sc.assess_security(connected.get('encryption', ''))
    connected['security_assessment'] = security

    traffic = get_real_traffic()
    if traffic.get('error'):
        logger.warning("Traffic counters unavailable: %s", traffic.get('error'))

    local_ip = net_sc.get_local_ip()
    gateway_ip = net_sc.get_gateway()

    scan_result = net_sc.get_connected_devices(max_devices=max_dev)
    all_devices, total_found, net_size = scan_result if isinstance(scan_result, tuple) else (scan_result, len(scan_result), 'small')

    scan_targets = [gateway_ip, local_ip] + \
                   [d['ip'] for d in all_devices if d['ip'] not in (gateway_ip, local_ip)][:8]
    port_workers = max(1, min(32, len(scan_targets)))
    port_data = {}
    rtt_by_ip = {d.get('ip'): d.get('ping_rtt_ms') for d in all_devices if d.get('ip')}
    with concurrent.futures.ThreadPoolExecutor(max_workers=port_workers) as ex:
        fm = {
            ex.submit(scan_device_ports, ip, None, net_size, rtt_by_ip.get(ip)): ip
            for ip in scan_targets
        }
        for future in concurrent.futures.as_completed(fm):
            ip = fm[future]
            try:
                ports = future.result()
                if ports:
                    port_data[ip] = ports
            except Exception:
                logger.debug("Port scan worker failed for %s", ip, exc_info=True)

    for d in all_devices:
        d['os_guess'] = guess_os_from_ports_and_ttl(
            port_data.get(d.get('ip'), []),
            d.get('icmp_ttl'),
        )

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
        'total_found': total_found,
        'showing': len(devices),
        'capped': total_found > len(devices),
        'cap_warning': f"Only showing {len(devices)} of {total_found} devices. Use ?max_devices=N to increase." if total_found > len(devices) else None,
        'network_size': net_size,
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

    result = {
        'scan_duration': f'{round(time.time()-t_start, 1)}s',
        'connected_network': connected,
        'local_ip': local_ip,
        'gateway': gateway_ip,
        'nodes_detected': len(devices),
        'addresses_scanned': 254,
        'devices': devices,
        'network_traffic': traffic,
        'interface_stats': net_sc.get_interface_stats(),
        'port_scan': port_data,
        'connected_devices': all_devices,
        'security_summary': summary,
        'attack_prediction': prediction,
    }

    if DB_AVAILABLE:
        try:
            save_scan(result)
            result['db_persisted'] = True
        except Exception as e:
            logger.error("[DB] Save error: %s", e, exc_info=True)
            result['db_persisted'] = False
            result['db_error'] = "Scan completed but could not be saved to the database."

    return _api_envelope(True, data=result)


@app.route('/api/scan/full', methods=['GET', 'POST'])
@limiter.limit(SCAN_FULL_RATE)
def full_scan():
    global _scan_in_progress
    with _scan_state_lock:
        if _scan_in_progress:
            return _api_envelope(False, error="A scan is already in progress. Try again shortly.", status=409)
        _scan_in_progress = True
    try:
        return _execute_full_scan()
    finally:
        with _scan_state_lock:
            _scan_in_progress = False


@app.route('/api/scan/connected', methods=['GET'])
@limiter.limit(SCAN_CONNECTED_RATE)
def scan_connected():
    connected = wifi_sc.get_connected_network()
    if 'error' in connected:
        return _api_envelope(False, error=connected['error'], status=400)
    if 'encryption' in connected:
        connected['security_assessment'] = wifi_sc.assess_security(connected['encryption'])
    data = {
        'connected_network': connected,
        'local_ip': net_sc.get_local_ip(),
        'gateway': net_sc.get_gateway(),
    }
    return _api_envelope(True, data=data)


@app.route('/api/traffic/live', methods=['GET'])
def live_traffic():
    t1 = get_real_traffic()
    time.sleep(1)
    t2 = get_real_traffic()
    if t2.get('error'):
        return _api_envelope(False, error=t2['error'], status=500)
    payload = {
        'current': t2,
        'rate': {
            'bytes_sent_per_sec': max(0, (t2.get('bytes_sent_raw', 0) or 0) - (t1.get('bytes_sent_raw', 0) or 0)),
            'bytes_recv_per_sec': max(0, (t2.get('bytes_recv_raw', 0) or 0) - (t1.get('bytes_recv_raw', 0) or 0)),
        },
        'interfaces': net_sc.get_interface_stats()
    }
    return _api_envelope(True, data=payload)


@app.route('/api/dashboard', methods=['GET'])
def dashboard():
    if not DB_AVAILABLE:
        return _api_envelope(False, error='Database not available — run database.py first', status=503)
    return _api_envelope(True, data=get_dashboard_summary())


@app.route('/api/history/scans', methods=['GET'])
def scan_history():
    if not DB_AVAILABLE:
        return _api_envelope(False, error='Database not available', status=503)
    limit, err = _parse_int_arg('limit', 50, 1, 500)
    if err:
        return _api_envelope(False, error=err, status=400)
    return _api_envelope(True, data=get_scan_history(limit))


@app.route('/api/history/alerts', methods=['GET'])
def alert_history():
    if not DB_AVAILABLE:
        return _api_envelope(False, error='Database not available', status=503)
    limit, err = _parse_int_arg('limit', 50, 1, 500)
    if err:
        return _api_envelope(False, error=err, status=400)
    unacked = request.args.get('unacked', 'false').lower() == 'true'
    return _api_envelope(True, data=get_recent_alerts(limit, unacked))


@app.route('/api/history/traffic', methods=['GET'])
def traffic_history():
    if not DB_AVAILABLE:
        return _api_envelope(False, error='Database not available', status=503)
    hours, err = _parse_int_arg('hours', 24, 1, 720)
    if err:
        return _api_envelope(False, error=err, status=400)
    return _api_envelope(True, data=get_traffic_history(hours))


@app.route('/api/history/devices', methods=['GET'])
def device_history():
    if not DB_AVAILABLE:
        return _api_envelope(False, error='Database not available', status=503)
    return _api_envelope(True, data=get_known_devices())


@app.route('/api/alerts/acknowledge/<int:alert_id>', methods=['POST'])
def acknowledge_alert_route(alert_id):
    if not DB_AVAILABLE:
        return _api_envelope(False, error='Database not available', status=503)
    try:
        acknowledge_alert(alert_id)
    except Exception as e:
        logger.exception("Acknowledge failed")
        return _api_envelope(False, error=str(e), status=500)
    return _api_envelope(True, data={'acknowledged': alert_id})


@app.route('/api/arp/status', methods=['GET'])
def arp_status():
    def _norm_mac(m):
        if not m:
            return ''
        return m.upper().replace('-', ':')

    gateway_ip = net_sc.get_gateway()
    current_arp = net_sc.get_arp_table()
    gateway_mac = current_arp.get(gateway_ip, 'Unknown')
    spoofing_detected = False
    suspicious_detail = []
    if DB_AVAILABLE:
        try:
            from database import get_arp_history, get_dominant_mac_for_ip, get_known_mac_for_ip
            for ip, mac in current_arp.items():
                nm = _norm_mac(mac)
                if not nm or nm == '<INCOMPLETE>':
                    continue
                history = get_arp_history(ip, hours=24)
                past_norm = {_norm_mac(h['mac']) for h in history if h.get('mac')}
                dom_mac, dom_cnt = get_dominant_mac_for_ip(ip, hours=168)
                known_mac = get_known_mac_for_ip(ip)
                ref = None
                if dom_mac and dom_cnt >= 2:
                    ref = _norm_mac(dom_mac)
                elif known_mac:
                    ref = _norm_mac(known_mac)
                elif dom_mac:
                    ref = _norm_mac(dom_mac)

                entry = None
                if ref and nm != ref:
                    entry = {
                        'ip': ip,
                        'current_mac': mac,
                        'expected_mac': ref,
                        'reason': 'history_or_binding_mismatch',
                        'history_samples': dom_cnt,
                    }
                elif len(past_norm) > 1 and nm not in past_norm:
                    entry = {
                        'ip': ip,
                        'current_mac': mac,
                        'expected_mac': None,
                        'reason': 'recent_mac_rotation',
                        'history_samples': len(history),
                    }
                if entry:
                    suspicious_detail.append(entry)
                    if ip == gateway_ip:
                        spoofing_detected = True
        except Exception as e:
            logger.warning("[ARP] History check error: %s", e)
    flat_suspicious = [x['ip'] for x in suspicious_detail]
    payload = {
        'current_arp': current_arp,
        'gateway_ip': gateway_ip,
        'gateway_mac': gateway_mac,
        'spoofing_detected': spoofing_detected,
        'suspicious_ips': flat_suspicious,
        'suspicious_detail': suspicious_detail,
        'total_entries': len(current_arp),
        'last_checked': datetime.now().isoformat(),
    }
    return _api_envelope(True, data=payload)


if __name__ == '__main__':
    logger.info("GARUDA v4.1 | OS=%s | DB=%s | http://%s:%s", OS, DB_AVAILABLE, HOST, PORT)
    app.run(debug=FLASK_DEBUG, host=HOST, port=PORT, threaded=FLASK_THREADED)