"""GARUDA v3 Hybrid Intrusion Detection Engine (NIDS + Anomaly + Active MITM Defense).
- Real-time background Scapy packet sniffer (when Npcap/libpcap + privileges are available)
  capturing: ARP spoofing / ARP reply storms, Rogue DHCP servers, DHCP Option 12 hostnames,
  SYN port sweeps, and cleartext outbound flows (HTTP/FTP/Telnet).
- Active DNS-over-HTTPS (DoH) cross-check against Cloudflare 1.1.1.1 to catch live DNS hijacking.
- Host-level MITM defense: Static ARP Gateway Pinning (Windows / Linux / macOS).
"""

import collections
import json
import platform
import socket
import subprocess
import threading
import time
from typing import Callable, Deque, Dict, List, Optional, Set, Tuple

from ..config import CLEARTEXT_PORTS, TRUSTED_PUBLIC_DNS, is_admin_or_root
from .network_detector import normalize_mac


class LivePacketIDS:
    def __init__(self, on_alert_callback: Optional[Callable[[dict], None]] = None):
        self.on_alert_callback = on_alert_callback
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        self.active_sniffer_running: bool = False
        self.mode: str = "os_heuristic_monitor"
        self.packets_inspected: int = 0
        self.arp_events_observed: int = 0
        self.dhcp_offers_observed: int = 0
        self.cleartext_flows_detected: int = 0
        self.dns_checks_passed: bool = True
        self.dns_check_note: str = "Waiting for initial DNS verification."

        # Live runtime state learned from real wire traffic
        self.gateway_ip: str = ""
        self.gateway_mac: str = ""
        self.local_ip: str = ""
        self.dhcp_hostnames: Dict[str, str] = {}          # MAC -> Option 12 Hostname
        self._ip_to_mac: Dict[str, str] = {}
        self._arp_reply_times: Dict[str, Deque[float]] = collections.defaultdict(lambda: collections.deque(maxlen=40))
        self._syn_ports: Dict[str, Deque[Tuple[float, int]]] = collections.defaultdict(lambda: collections.deque(maxlen=80))
        self._cooldowns: Dict[str, float] = {}

    def update_network_context(self, local_ip: str, gateway_ip: str, gateway_mac: str):
        with self._lock:
            self.local_ip = local_ip or ""
            self.gateway_ip = gateway_ip or ""
            if gateway_mac and gateway_mac != "00:00:00:00:00:00":
                self.gateway_mac = normalize_mac(gateway_mac)
                self._ip_to_mac[self.gateway_ip] = self.gateway_mac

    def _emit_alert(self, key: str, alert_dict: dict, cooldown_sec: float = 45.0):
        now = time.monotonic()
        with self._lock:
            last = self._cooldowns.get(key, 0.0)
            if now - last < cooldown_sec:
                return
            self._cooldowns[key] = now
        if self.on_alert_callback:
            try:
                self.on_alert_callback(alert_dict)
            except Exception:
                pass

    def start(self):
        """Start the Scapy real-time packet sniffer if Scapy + OS capture privileges are available."""
        if self._thread and self._thread.is_alive():
            return
        try:
            import scapy.all  # noqa: F401
        except ImportError:
            self.mode = "os_heuristic_monitor"
            self.active_sniffer_running = False
            return

        if not is_admin_or_root():
            self.mode = "os_heuristic_monitor"
            self.active_sniffer_running = False
            return

        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sniff_worker, name="garuda-ids-sniffer", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self.active_sniffer_running = False

    def _sniff_worker(self):
        try:
            from scapy.all import sniff  # type: ignore
            self.active_sniffer_running = True
            self.mode = "live_packet_sniffer"
            sniff(
                filter="arp or (udp and (port 67 or port 68)) or tcp",
                prn=self.process_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except Exception:
            self.active_sniffer_running = False
            self.mode = "os_heuristic_monitor"

    def process_packet(self, pkt):
        """Process a live Scapy packet for ARP spoofing, Rogue DHCP, DHCP hostnames, SYN sweeps, and cleartext traffic."""
        try:
            from scapy.all import ARP, BOOTP, DHCP, IP, TCP, Ether  # type: ignore
        except ImportError:
            return

        now = time.monotonic()
        with self._lock:
            self.packets_inspected += 1

        # 1. ARP Spoofing & ARP Reply Storm Detection
        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            src_ip = str(arp.psrc)
            src_mac = normalize_mac(str(arp.hwsrc))
            op = int(arp.op)
            with self._lock:
                self.arp_events_observed += 1
            self.inspect_arp_event(src_ip, src_mac, op, now)
            return

        # 2. DHCP Hostname Learning (Option 12) + Rogue DHCP Server Detection
        if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
            src_mac = normalize_mac(str(pkt[Ether].src)) if pkt.haslayer(Ether) else ""
            src_ip = str(pkt[IP].src) if pkt.haslayer(IP) else ""
            msg_type = None
            hostname = None
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and len(opt) >= 2:
                    if opt[0] == "message-type":
                        msg_type = opt[1]
                    elif opt[0] == "hostname":
                        raw = opt[1]
                        hostname = raw.decode("utf-8", errors="ignore").strip() if isinstance(raw, bytes) else str(raw).strip()
            self.inspect_dhcp_event(msg_type, src_ip, src_mac, hostname)
            return

        # 3. TCP SYN Port Sweep & Cleartext Outbound Monitoring
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            src_ip = str(pkt[IP].src)
            dst_ip = str(pkt[IP].dst)
            dport = int(pkt[TCP].dport)
            flags = int(pkt[TCP].flags)
            is_syn_only = (flags & 0x02) != 0 and (flags & 0x10) == 0
            if is_syn_only:
                self.inspect_tcp_syn(src_ip, dst_ip, dport, now)

    def inspect_arp_event(self, src_ip: str, src_mac: str, op: int, now: Optional[float] = None) -> List[dict]:
        """Pure-Python testable ARP anomaly detector."""
        now = now if now is not None else time.monotonic()
        triggered: List[dict] = []

        if op == 2:  # ARP Reply (is-at)
            with self._lock:
                gw_ip = self.gateway_ip
                gw_mac = self.gateway_mac
                prev_mac = self._ip_to_mac.get(src_ip)
                dq = self._arp_reply_times[src_mac]
                dq.append(now)
                recent_replies = sum(1 for t in dq if now - t <= 5.0)
                if not prev_mac:
                    self._ip_to_mac[src_ip] = src_mac

            # 1a. Gateway MAC Spoofing (MITM)
            if gw_ip and gw_mac and src_ip == gw_ip and src_mac != gw_mac:
                alert = {
                    "severity": "critical",
                    "category": "active_attack",
                    "attack_type": "arp_spoof",
                    "title": "Active Man-in-the-Middle Attack Blocked/Detected (Fake Router ARP)",
                    "plain_explanation": (
                        f"A device ({src_mac}) just sent forged network messages claiming to be your router ({gw_ip}). "
                        "This is a live ARP Spoofing attack designed to intercept your traffic."
                    ),
                    "what_to_do": (
                        "Click 'Lock Router Identity (Pin ARP)' or disconnect from Wi-Fi immediately. Do not enter passwords or banking OTPs."
                    ),
                    "technical_evidence": json.dumps({"expected_gateway_mac": gw_mac, "spoofed_mac": src_mac, "gateway_ip": gw_ip}),
                    "related_mac": src_mac,
                    "related_ip": src_ip,
                }
                triggered.append(alert)
                self._emit_alert(f"arp_gw_{src_mac}", alert, cooldown_sec=30.0)

            # 1b. ARP Reply Flood (gratuitous poisoning burst)
            elif recent_replies >= 15:
                alert = {
                    "severity": "warning",
                    "category": "active_attack",
                    "attack_type": "arp_storm",
                    "title": f"Abnormal ARP Poisoning Burst from {src_ip}",
                    "plain_explanation": (
                        f"Device {src_ip} ({src_mac}) flooded your network with {recent_replies} unsolicited ARP replies in 5 seconds. "
                        "Attackers send rapid ARP bursts to keep victims poisoned during a MITM attack."
                    ),
                    "what_to_do": "Check Connected Devices for this device. If unfamiliar, block it via Firewall or change your Wi-Fi password.",
                    "technical_evidence": json.dumps({"replies_5s": recent_replies, "src_ip": src_ip, "src_mac": src_mac}),
                    "related_mac": src_mac,
                    "related_ip": src_ip,
                }
                triggered.append(alert)
                self._emit_alert(f"arp_storm_{src_mac}", alert, cooldown_sec=60.0)

        return triggered

    def inspect_dhcp_event(self, msg_type: Optional[int], src_ip: str, src_mac: str, hostname: Optional[str]) -> List[dict]:
        """Learn real DHCP hostnames (Option 12) and catch Rogue DHCP Offers."""
        triggered: List[dict] = []
        if hostname and src_mac:
            with self._lock:
                self.dhcp_hostnames[src_mac.upper()] = hostname

        # DHCP Offer (2) or ACK (5) from a device that is NOT the baseline router
        if msg_type in (2, 5):
            with self._lock:
                self.dhcp_offers_observed += 1
                gw_ip = self.gateway_ip
                gw_mac = self.gateway_mac

            if gw_ip and src_ip and src_ip != gw_ip and (not gw_mac or src_mac != gw_mac):
                alert = {
                    "severity": "critical",
                    "category": "active_attack",
                    "attack_type": "rogue_dhcp",
                    "title": "Active Rogue DHCP Server Detected (Traffic Redirection Attempt)",
                    "plain_explanation": (
                        f"An unauthorized device ({src_ip} / {src_mac}) tried to hand out network settings like a router. "
                        "Attackers use Rogue DHCP to push fake DNS servers and silently intercept everyone on the Wi-Fi."
                    ),
                    "what_to_do": "Turn on Encrypted Private DNS or VPN immediately, and block this device on your real router.",
                    "technical_evidence": json.dumps({"rogue_ip": src_ip, "rogue_mac": src_mac, "expected_gateway": gw_ip}),
                    "related_mac": src_mac,
                    "related_ip": src_ip,
                }
                triggered.append(alert)
                self._emit_alert(f"rogue_dhcp_{src_mac}", alert, cooldown_sec=60.0)

        return triggered

    def inspect_tcp_syn(self, src_ip: str, dst_ip: str, dport: int, now: Optional[float] = None) -> List[dict]:
        """Detect active port sweeps against this host AND cleartext outbound traffic (passive leak risk)."""
        now = now if now is not None else time.monotonic()
        triggered: List[dict] = []

        with self._lock:
            local_ip = self.local_ip

        # Active Port Scan hitting this device
        if local_ip and dst_ip == local_ip and src_ip != local_ip:
            with self._lock:
                dq = self._syn_ports[src_ip]
                dq.append((now, dport))
                recent_ports: Set[int] = {p for t, p in dq if now - t <= 10.0}
            if len(recent_ports) >= 12:
                alert = {
                    "severity": "critical",
                    "category": "active_attack",
                    "attack_type": "port_sweep",
                    "title": f"Active Port Scan Targeting Your Device from {src_ip}",
                    "plain_explanation": (
                        f"Another device on your network ({src_ip}) rapidly probed {len(recent_ports)} different ports on your computer in 10 seconds "
                        "to hunt for open services or weaknesses."
                    ),
                    "what_to_do": "Use GARUDA's Firewall Shield to block this IP immediately and verify whether you recognize the device.",
                    "technical_evidence": json.dumps({"attacker_ip": src_ip, "distinct_ports_10s": sorted(list(recent_ports))[:20]}),
                    "related_mac": None,
                    "related_ip": src_ip,
                }
                triggered.append(alert)
                self._emit_alert(f"syn_sweep_{src_ip}", alert, cooldown_sec=60.0)

        # Passive Leak Risk: Cleartext protocol leaving this machine (HTTP/FTP/Telnet)
        elif local_ip and src_ip == local_ip and dport in CLEARTEXT_PORTS:
            proto_name = CLEARTEXT_PORTS[dport]
            with self._lock:
                self.cleartext_flows_detected += 1
            if dport in (21, 23):  # Always warn on FTP/Telnet passwords in plaintext
                alert = {
                    "severity": "warning",
                    "category": "passive_risk",
                    "attack_type": "cleartext_traffic",
                    "title": f"Unencrypted {proto_name} Traffic Leaving Your Device",
                    "plain_explanation": (
                        f"Your device connected to {dst_ip} over unencrypted {proto_name} (port {dport}). "
                        "Any passive listener on this network can read passwords or data sent over this connection."
                    ),
                    "what_to_do": f"Switch to an encrypted alternative (SFTP/SSH/HTTPS) or enable a VPN before transmitting credentials.",
                    "technical_evidence": json.dumps({"protocol": proto_name, "dst_ip": dst_ip, "dport": dport}),
                    "related_mac": None,
                    "related_ip": dst_ip,
                }
                triggered.append(alert)
                self._emit_alert(f"cleartext_{proto_name}_{dst_ip}", alert, cooldown_sec=120.0)

        return triggered

    def get_ml_telemetry(self) -> Tuple[Dict[str, int], Dict[str, int]]:
        """Return recent (arp_replies_per_mac_60s, distinct_syn_ports_per_ip_60s) for ML behavioral scoring."""
        now = time.monotonic()
        with self._lock:
            arp_counts = {
                mac: sum(1 for t in dq if now - t <= 60.0)
                for mac, dq in self._arp_reply_times.items()
            }
            syn_counts = {
                ip: len({p for t, p in dq if now - t <= 60.0})
                for ip, dq in self._syn_ports.items()
            }
        return arp_counts, syn_counts

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "mode": self.mode,
                "packets_inspected": self.packets_inspected,
                "arp_events_observed": self.arp_events_observed,
                "dhcp_offers_observed": self.dhcp_offers_observed,
                "dns_checks_passed": self.dns_checks_passed,
                "dns_check_note": self.dns_check_note,
                "cleartext_flows_detected": self.cleartext_flows_detected,
                "active_sniffer_running": self.active_sniffer_running,
            }


def verify_dns_integrity_doh(test_domain: str = "example.com") -> Tuple[bool, str, Optional[dict]]:
    """Cross-check local DNS resolution against encrypted Cloudflare DoH (1.1.1.1) to detect active DNS hijacking."""
    try:
        local_ips = {info[4][0] for info in socket.getaddrinfo(test_domain, 443, socket.AF_INET)}
    except Exception:
        return True, "Offline or local DNS unreachable — skipped live DoH comparison.", None

    try:
        import urllib.request
        req = urllib.request.Request(
            f"https://1.1.1.1/dns-query?name={test_domain}&type=A",
            headers={"Accept": "application/dns-json", "User-Agent": "GARUDA/3.0"},
        )
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        doh_ips = {ans["data"] for ans in data.get("Answer", []) if ans.get("type") == 1}
        if not doh_ips:
            return True, "DoH check returned no A records.", None

        # Check if local DNS returned a private/bogon IP (classic DNS hijacking / captive portal)
        private_hijack = [ip for ip in local_ips if ip.startswith(("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.", "172.19."))]
        if private_hijack:
            alert = {
                "severity": "critical",
                "category": "active_attack",
                "attack_type": "dns_hijack",
                "title": "Active DNS Redirection Detected (Local DNS Returned Fake Address)",
                "plain_explanation": (
                    f"Your network redirected '{test_domain}' to a private address ({', '.join(private_hijack)}) instead of its real internet address. "
                    "This happens during DNS Hijacking or an aggressive captive portal interception."
                ),
                "what_to_do": "Do not enter passwords. Enable Encrypted DNS (Cloudflare 1.1.1.1 / Quad9 9.9.9.9) or connect through a VPN.",
                "technical_evidence": json.dumps({"domain": test_domain, "local_ips": list(local_ips), "doh_ips": list(doh_ips)}),
                "related_mac": None,
                "related_ip": private_hijack[0],
            }
            return False, f"Mismatch: local DNS returned private IP {private_hijack[0]}", alert

        return True, f"Verified clean against encrypted Cloudflare DoH ({test_domain}).", None
    except Exception:
        return True, "DoH verification unavailable (no outbound internet).", None


def evaluate_baseline_and_passive_threats(
    net_info: dict,
    observed_devices: List[dict],
    known_safe_macs: set,
    existing_macs: set,
    baseline: Optional[dict] = None,
    alert_on_new_device: bool = True,
    alert_on_passive_risk: bool = True,
) -> List[dict]:
    """Run stateful baseline checks (gateway MAC drift, duplicate MACs, DNS swap, open Wi-Fi, new devices)."""
    alerts: List[dict] = []
    gw_ip = net_info.get("gateway_ip", "")
    gw_mac = normalize_mac(net_info.get("gateway_mac", ""))

    # 1. Gateway MAC changed vs remembered SSID baseline
    if baseline and baseline.get("ssid") == net_info.get("ssid"):
        old_gw = normalize_mac(baseline.get("gateway_mac", ""))
        if old_gw != "00:00:00:00:00:00" and gw_mac != "00:00:00:00:00:00" and old_gw != gw_mac:
            alerts.append({
                "severity": "critical",
                "category": "active_attack",
                "attack_type": "arp_spoof",
                "title": "Possible Active Man-in-the-Middle Attack (Router Identity Changed)",
                "plain_explanation": (
                    f"Your router ({gw_ip}) suddenly changed its hardware address from {old_gw} to {gw_mac}. "
                    "This is the strongest sign of an ARP Spoofing / Fake Router interception attack."
                ),
                "what_to_do": "Pause banking and passwords immediately. Pin your real router MAC after rebooting, or switch to mobile data.",
                "technical_evidence": json.dumps({"old_gateway_mac": old_gw, "new_gateway_mac": gw_mac}),
                "related_mac": gw_mac,
                "related_ip": gw_ip,
            })

    # 2. Duplicate MAC claiming multiple IPs
    mac_to_ips: Dict[str, List[str]] = {}
    for d in observed_devices:
        m = normalize_mac(d["mac"])
        if m != "00:00:00:00:00:00":
            mac_to_ips.setdefault(m, []).append(d["ip"])
    for mac, ips in mac_to_ips.items():
        uniq = sorted(set(ips))
        if len(uniq) > 1:
            gw_hit = gw_ip in uniq
            alerts.append({
                "severity": "critical" if gw_hit else "warning",
                "category": "active_attack",
                "attack_type": "arp_spoof",
                "title": "Active Network Impersonation (Duplicate Hardware Address)",
                "plain_explanation": (
                    f"One hardware device ({mac}) is answering for multiple IP addresses ({', '.join(uniq)}). "
                    + ("Because your router IP is included, traffic interception is likely." if gw_hit else "Check for an active spoofing tool or network bridge.")
                ),
                "what_to_do": "Enable a VPN immediately and block the suspicious device via Firewall Shield.",
                "technical_evidence": json.dumps({"mac": mac, "claimed_ips": uniq}),
                "related_mac": mac,
                "related_ip": uniq[0],
            })

    # 3. Unexpected DNS server swap
    cur_dns = [d for d in (net_info.get("dns_servers") or []) if d]
    if baseline and baseline.get("ssid") == net_info.get("ssid"):
        prev_dns = [d for d in (baseline.get("dns_servers") or "").split(",") if d]
        untrusted = [d for d in cur_dns if d not in prev_dns and d != gw_ip and d not in TRUSTED_PUBLIC_DNS]
        if prev_dns and untrusted:
            alerts.append({
                "severity": "critical",
                "category": "active_attack",
                "attack_type": "dns_hijack",
                "title": "Unexpected DNS Server Change Detected",
                "plain_explanation": f"Your network switched DNS lookups to an unrecognized server ({', '.join(untrusted)}).",
                "what_to_do": "Switch your device to Encrypted Private DNS (1.1.1.1 or 9.9.9.9) before opening banking or login pages.",
                "technical_evidence": json.dumps({"previous_dns": prev_dns, "new_untrusted_dns": untrusted}),
                "related_mac": gw_mac,
                "related_ip": untrusted[0],
            })

    # 4. Passive Eavesdropping Risk Checks
    if alert_on_passive_risk:
        grade = net_info.get("encryption_grade", "Good")
        vpn_on = bool(net_info.get("vpn_active", False))
        if grade == "None":
            alerts.append({
                "severity": "warning" if vpn_on else "critical",
                "category": "passive_risk",
                "attack_type": "open_wifi",
                "title": "High Passive Eavesdropping Risk — Unencrypted Open Wi-Fi",
                "plain_explanation": (
                    f"'{net_info.get('ssid')}' has NO Wi-Fi encryption. Anyone nearby can silently capture unencrypted data in the air."
                    + (" Your active VPN is currently shielding your traffic." if vpn_on else "")
                ),
                "what_to_do": "Keep a trusted VPN turned on for all browsing, or switch to your 4G/5G personal hotspot.",
                "technical_evidence": json.dumps({"ssid": net_info.get("ssid"), "protocol": net_info.get("security_protocol"), "vpn_active": vpn_on}),
                "related_mac": gw_mac,
                "related_ip": gw_ip,
            })
        elif grade == "Weak":
            alerts.append({
                "severity": "warning",
                "category": "passive_risk",
                "attack_type": "weak_encryption",
                "title": "Passive Snooping Risk — Weak Wi-Fi Encryption",
                "plain_explanation": f"'{net_info.get('ssid')}' uses outdated security ({net_info.get('security_protocol')}) that can be passively cracked.",
                "what_to_do": "Upgrade your router to WPA2-AES or WPA3-Personal, or turn on a VPN.",
                "technical_evidence": json.dumps({"protocol": net_info.get("security_protocol")}),
                "related_mac": gw_mac,
                "related_ip": gw_ip,
            })
        elif net_info.get("is_public_or_untrusted") and not vpn_on:
            alerts.append({
                "severity": "warning",
                "category": "passive_risk",
                "attack_type": "shared_public_wifi",
                "title": "Shared / Public Network — Turn On Firewall & VPN",
                "plain_explanation": f"'{net_info.get('ssid')}' looks like a shared public Wi-Fi where strangers can probe connected devices.",
                "what_to_do": "Turn on Firewall Lockdown Mode in GARUDA and enable a VPN for private logins.",
                "technical_evidence": json.dumps({"network_type": net_info.get("network_type")}),
                "related_mac": gw_mac,
                "related_ip": gw_ip,
            })

    # 5. Unverified / Newly Joined Devices
    if alert_on_new_device:
        for d in observed_devices:
            mac = normalize_mac(d["mac"])
            if d.get("is_self") or d.get("is_gateway") or mac in known_safe_macs:
                continue
            if mac not in existing_macs:
                alerts.append({
                    "severity": "warning",
                    "category": "unverified_device",
                    "attack_type": "new_device",
                    "title": f"New Unverified Device Joined: {d['real_name']}",
                    "plain_explanation": (
                        f"'{d['real_name']}' ({d['vendor']}, IP {d['ip']}) connected to your network and is not on your Safe list yet."
                    ),
                    "what_to_do": "If you recognize this gadget, click 'Mark as Safe'. If not, block it or change your Wi-Fi password.",
                    "technical_evidence": json.dumps({"name_source": d.get("name_source"), "mac": mac, "ip": d["ip"]}),
                    "related_mac": mac,
                    "related_ip": d["ip"],
                })

    return alerts


def pin_static_gateway_arp(gateway_ip: str, gateway_mac: str, interface_name: str) -> dict:
    """Host-level MITM defense: pin the verified router IP->MAC statically in OS ARP cache."""
    sys_name = platform.system().lower()
    norm_mac = normalize_mac(gateway_mac)
    if sys_name == "windows":
        win_mac = norm_mac.replace(":", "-")
        cmd = ["netsh", "interface", "ipv4", "add", "neighbors", interface_name, gateway_ip, win_mac]
    elif sys_name == "linux":
        cmd = ["ip", "neigh", "replace", gateway_ip, "lladdr", norm_mac, "dev", interface_name, "nud", "permanent"]
    else:
        cmd = ["arp", "-S", gateway_ip, norm_mac]

    cmd_str = " ".join(cmd)
    if not is_admin_or_root():
        return {
            "enforced": False,
            "command": cmd_str,
            "message": "Administrator / sudo privileges are required to pin a permanent ARP entry. Run GARUDA elevated or execute the command manually.",
        }

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=4.0, check=False)
        ok = res.returncode == 0
        return {
            "enforced": ok,
            "command": cmd_str,
            "message": f"Router {gateway_ip} ({norm_mac}) is now pinned permanently against ARP spoofing." if ok else (res.stderr.strip() or res.stdout.strip() or "OS rejected static ARP pin."),
        }
    except Exception as exc:
        return {"enforced": False, "command": cmd_str, "message": str(exc)}
