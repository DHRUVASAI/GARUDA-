"""
GARUDA v10 Network Doctor
-------------------------
Upgrades over v9:
  - Concurrent non-blocking port scanning via asyncio.gather (~0.2s total instead of 1.0s+ blocking).
  - Expanded 8-port high-risk profile: 21 (FTP), 23 (Telnet), 445 (SMB), 3389 (RDP),
    5555 (Android ADB), 5900 (VNC), 8080 (Unauth Proxy), 27017 (Unauth MongoDB).
"""
import asyncio
import platform
import socket
import subprocess
import time
from typing import Any, Dict, List

import psutil

RISKY_PORTS = {
    21: "FTP (cleartext)",
    23: "Telnet (cleartext)",
    445: "SMB (lateral movement risk)",
    3389: "RDP (brute-force target)",
    5555: "Android ADB (unauthenticated debug)",
    5900: "VNC (remote desktop)",
    8080: "HTTP Proxy / Alt-Web",
    27017: "MongoDB (unauthenticated DB)",
}


class NetworkDoctor:
    def _check_dns(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        try:
            ip = socket.gethostbyname("cloudflare.com")
            ms = round((time.perf_counter() - t0) * 1000, 1)
            return {
                "status": "warning" if ms > 150 else "ok",
                "resolved_ip": ip,
                "latency_ms": ms,
                "recommendation": "Switch to 1.1.1.1 or 9.9.9.9 DNS-over-HTTPS" if ms > 150 else "DNS resolution healthy",
            }
        except Exception as exc:
            return {
                "status": "fail",
                "error": str(exc),
                "latency_ms": -1,
                "recommendation": "Check upstream DNS settings or router internet link",
            }

    def _check_outbound_tls(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        try:
            with socket.create_connection(("1.1.1.1", 443), timeout=2.0):
                ms = round((time.perf_counter() - t0) * 1000, 1)
                rec = "Outbound HTTPS latency healthy" if ms < 100 else f"Slightly elevated HTTPS latency ({ms} ms)"
                return {
                    "status": "warning" if ms > 150 else "ok",
                    "endpoint": "1.1.1.1:443",
                    "latency_ms": ms,
                    "summary": f"Clean outbound HTTPS handshake to 1.1.1.1:443 ({ms} ms)",
                    "recommendation": rec,
                }
        except Exception as exc:
            return {
                "status": "fail",
                "endpoint": "1.1.1.1:443",
                "error": str(exc),
                "summary": "Outbound HTTPS connectivity blocked or offline",
                "recommendation": "Check gateway routing, firewall egress rules, or ISP upstream link",
            }

    def _check_arp_spoofing(self) -> Dict[str, Any]:
        try:
            cmd = ["arp", "-a"] if platform.system().lower() == "windows" else ["arp", "-an"]
            out = subprocess.check_output(cmd, text=True, timeout=4, stderr=subprocess.DEVNULL)
            mac_to_ips: Dict[str, List[str]] = {}
            for line in out.splitlines():
                parts = line.split()
                for part in parts:
                    cleaned = part.strip("()")
                    if ("-" in cleaned or ":" in cleaned) and len(cleaned) == 17:
                        mac = cleaned.lower().replace("-", ":")
                        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                            continue
                        ip_candidate = next((p.strip("()") for p in parts if p.strip("()").count(".") == 3), "unknown")
                        mac_to_ips.setdefault(mac, []).append(ip_candidate)
            dupes = {m: sorted(set(ips)) for m, ips in mac_to_ips.items() if len(set(ips)) > 1}
            return {
                "status": "warning" if dupes else "ok",
                "duplicate_macs": dupes,
                "entries_scanned": sum(len(v) for v in mac_to_ips.values()),
                "recommendation": "Duplicate MAC detected — pin gateway ARP & isolate offending host" if dupes else "ARP table clean (no duplicate MACs)",
            }
        except Exception as exc:
            return {
                "status": "info",
                "entries_scanned": 0,
                "duplicate_macs": {},
                "recommendation": f"ARP table unavailable in this environment ({exc})",
            }

    async def _probe_port_async(self, port: int, label: str) -> Any:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout=0.2)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return {"port": port, "service": label}
        except Exception:
            return None

    async def _check_risky_ports_async(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        results = await asyncio.gather(
            *(self._probe_port_async(p, lbl) for p, lbl in RISKY_PORTS.items())
        )
        exposed = [r for r in results if r is not None]
        return {
            "status": "warning" if exposed else "ok",
            "ports_checked": len(RISKY_PORTS),
            "scan_ms": round((time.perf_counter() - t0) * 1000, 1),
            "exposed_ports": exposed,
            "recommendation": f"Close or firewall ports {[p['port'] for p in exposed]}" if exposed else "No risky local service ports exposed",
        }

    def _check_risky_ports(self) -> Dict[str, Any]:
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                # Fallback thread-safe sync probe if called inside an already-running loop
                exposed = []
                for port, label in RISKY_PORTS.items():
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.15)
                        if s.connect_ex(("127.0.0.1", port)) == 0:
                            exposed.append({"port": port, "service": label})
                return {
                    "status": "warning" if exposed else "ok",
                    "ports_checked": len(RISKY_PORTS),
                    "exposed_ports": exposed,
                    "recommendation": f"Close or firewall ports {[p['port'] for p in exposed]}" if exposed else "No risky local service ports exposed",
                }
        except RuntimeError:
            pass
        return asyncio.run(self._check_risky_ports_async())

    def _check_system_vitals(self) -> Dict[str, Any]:
        cpu = psutil.cpu_percent(interval=0.05)
        mem = psutil.virtual_memory().percent
        status = "warning" if (cpu > 85 or mem > 90) else "ok"
        return {
            "status": status,
            "cpu_percent": cpu,
            "memory_percent": mem,
            "recommendation": "High resource load may drop packet capture frames" if status == "warning" else "System telemetry nominal",
        }

    def run_diagnostics(self) -> Dict[str, Any]:
        dns = self._check_dns()
        tls = self._check_outbound_tls()
        arp = self._check_arp_spoofing()
        ports = self._check_risky_ports()
        vitals = self._check_system_vitals()

        score = 100
        issues: List[str] = []

        if dns["status"] == "fail":
            score -= 30
            issues.append("DNS resolution failed")
        elif dns["status"] == "warning":
            score -= 10
            issues.append(f"Elevated DNS latency ({dns['latency_ms']} ms)")

        if tls["status"] == "fail":
            score -= 20
            issues.append("Outbound HTTPS (443) unreachable")

        if arp["status"] == "warning":
            score -= 35
            issues.append("Potential ARP spoofing / duplicate MAC detected")

        if ports["status"] == "warning":
            score -= min(30, 15 * len(ports["exposed_ports"]))
            issues.append(f"Risky local ports open: {[p['port'] for p in ports['exposed_ports']]}")

        if vitals["status"] == "warning":
            score -= 10
            issues.append(f"High host load (CPU {vitals['cpu_percent']}%, RAM {vitals['memory_percent']}%)")

        score = max(0, score)
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 55 else "CRITICAL"

        return {
            "health_score": score,
            "grade": grade,
            "issues": issues,
            "checks": {
                "dns": dns,
                "outbound_tls": tls,
                "arp_integrity": arp,
                "risky_ports": ports,
                "system_vitals": vitals,
            },
        }
