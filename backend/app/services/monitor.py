"""GARUDA v4 Master Guardian Engine.
Coordinates native network detection, 5-layer real device naming, live Scapy packet IDS,
DoH DNS verification, IsolationForest + Welford ML behavioral scoring, Ed25519 + Merkle
Web3 attestation ledger, ClamAV/YARA/psutil malware scanning, OS firewall control, and WS push.
"""

import asyncio
import json
import platform
from datetime import datetime, timezone
from typing import Dict, List, Optional
from sqlalchemy.orm import Session

from ..config import DEFAULT_SIMULATION_MODE, WEB3_CONTRACT_ADDRESS, WEB3_PRIVATE_KEY, WEB3_RPC_URL, is_admin_or_root
from ..database import SessionLocal
from ..models import Alert, AlertSettings, Device, FirewallRuleLog, MalwareScanRun, NetworkBaseline
from .advisor import build_security_advice
from .attestation_ledger import append_attestation_block, ensure_genesis_block, get_ledger_summary, signer
from .device_scanner import discover_lan_devices
from .firewall_manager import detect_firewall_backend, enforce_block_ip, get_firewall_status
from .ids_engine import LivePacketIDS, evaluate_baseline_and_passive_threats, verify_dns_integrity_doh
from .malware_scanner import detect_available_engines, get_threat_feed_count
from .ml_engine import ml_engine
from .network_detector import detect_network_environment, normalize_mac
from .notifier import dispatch_external_alert, ws_manager
from .oui_db import get_oui_count


def _get_or_create_settings(db: Session) -> AlertSettings:
    s = db.query(AlertSettings).filter(AlertSettings.id == 1).first()
    if not s:
        s = AlertSettings(id=1, simulation_mode=DEFAULT_SIMULATION_MODE)
        db.add(s)
        db.commit()
        db.refresh(s)
    return s


def _serialize_device(d: Device) -> dict:
    return {
        "id": d.id,
        "mac": d.mac,
        "ip": d.ip,
        "real_name": d.real_name,
        "name_source": d.name_source,
        "custom_name": d.custom_name,
        "display_name": d.custom_name or d.real_name,
        "vendor": d.vendor,
        "device_type": d.device_type,
        "os_hint": d.os_hint,
        "is_gateway": d.is_gateway,
        "is_self": d.is_self,
        "is_safe": d.is_safe,
        "is_online": d.is_online,
        "is_randomized_mac": d.is_randomized_mac,
        "latency_ms": d.latency_ms,
        "first_seen": d.first_seen.isoformat() if hasattr(d.first_seen, "isoformat") else (str(d.first_seen) if d.first_seen else None),
        "last_seen": d.last_seen.isoformat() if hasattr(d.last_seen, "isoformat") else (str(d.last_seen) if d.last_seen else None),
    }


def _serialize_alert(a: Alert) -> dict:
    return {
        "id": a.id,
        "severity": a.severity,
        "category": a.category,
        "attack_type": a.attack_type,
        "title": a.title,
        "plain_explanation": a.plain_explanation,
        "what_to_do": a.what_to_do,
        "technical_evidence": a.technical_evidence,
        "related_mac": a.related_mac,
        "related_ip": a.related_ip,
        "resolved": a.resolved,
        "created_at": a.created_at.isoformat() if hasattr(a.created_at, "isoformat") else (str(a.created_at) if a.created_at else None),
    }


def _serialize_settings(s: AlertSettings) -> dict:
    return {
        "sound_enabled": s.sound_enabled,
        "desktop_notifications": s.desktop_notifications,
        "alert_on_new_device": s.alert_on_new_device,
        "alert_on_passive_risk": s.alert_on_passive_risk,
        "auto_block_active_attackers": s.auto_block_active_attackers,
        "webhook_url": s.webhook_url,
        "telegram_configured": bool(s.telegram_bot_token and s.telegram_chat_id),
        "simulation_mode": s.simulation_mode,
        "scan_interval_sec": s.scan_interval_sec,
    }


class GarudaV4Monitor:
    def __init__(self):
        self.last_network: Optional[dict] = None
        self.last_scan_at: datetime = datetime.now(timezone.utc)
        self.lockdown_active: bool = False
        self.arp_pinned_ssids: set = set()
        self._sim_network_override: Optional[dict] = None
        self._sim_extra_devices: List[dict] = []
        self._bg_task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self.ids = LivePacketIDS(on_alert_callback=self._on_realtime_ids_alert)

    def bind_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    def _on_realtime_ids_alert(self, alert_dict: dict):
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self._persist_and_broadcast_alert(alert_dict), self._loop)

    async def _persist_and_broadcast_alert(self, item: dict):
        db = SessionLocal()
        try:
            settings = _get_or_create_settings(db)
            existing = db.query(Alert).filter(
                Alert.resolved == False,  # noqa: E712
                Alert.attack_type == item["attack_type"],
                Alert.title == item["title"],
            ).first()
            if existing:
                return
            a = Alert(
                severity=item["severity"],
                category=item["category"],
                attack_type=item["attack_type"],
                title=item["title"],
                plain_explanation=item["plain_explanation"],
                what_to_do=item["what_to_do"],
                technical_evidence=item.get("technical_evidence"),
                related_mac=item.get("related_mac"),
                related_ip=item.get("related_ip"),
                resolved=False,
                created_at=datetime.now(timezone.utc),
            )
            db.add(a)

            if settings.auto_block_active_attackers and item["category"] == "active_attack" and item.get("related_ip"):
                res = await asyncio.to_thread(enforce_block_ip, item["related_ip"], False)
                db.add(FirewallRuleLog(
                    target_ip=item["related_ip"],
                    rule_name=res["rule_name"],
                    action="block",
                    reason=f"Auto-blocked due to {item['attack_type']}",
                    enforced=res["enforced"],
                    command_used=res["command"],
                ))

            db.commit()
            db.refresh(a)

            # Seal critical realtime IDS alerts automatically into the Ed25519 Merkle ledger
            if a.severity == "critical":
                append_attestation_block(
                    db,
                    event_type=f"ids_{a.attack_type}",
                    summary=a.title,
                    payload={"alert_id": a.id, "attack_type": a.attack_type, "ip": a.related_ip, "mac": a.related_mac},
                )

            ser = _serialize_alert(a)
            snap = self.get_snapshot(db)
            await ws_manager.broadcast("alert", ser)
            await ws_manager.broadcast("snapshot", snap)
            asyncio.create_task(dispatch_external_alert(ser, settings))
        finally:
            db.close()

    def get_capabilities(self) -> dict:
        eng = detect_available_engines()
        try:
            import scapy.all  # noqa: F401
            has_scapy = True
        except ImportError:
            has_scapy = False
        try:
            import zeroconf  # noqa: F401
            has_zc = True
        except ImportError:
            has_zc = False
        return {
            "os_name": f"{platform.system()} {platform.release()}",
            "is_admin": is_admin_or_root(),
            "ids_mode": self.ids.mode,
            "scapy_available": has_scapy,
            "zeroconf_available": has_zc,
            "psutil_available": eng["process_hids"],
            "clamav_available": eng["clamav"],
            "yara_available": eng["yara"],
            "sklearn_available": ml_engine._sklearn_available,
            "crypto_signature_alg": signer.algorithm,
            "web3_configured": bool(WEB3_RPC_URL and WEB3_CONTRACT_ADDRESS and WEB3_PRIVATE_KEY),
            "firewall_backend": detect_firewall_backend(),
            "ieee_oui_entries": get_oui_count(),
            "threat_feed_ips": get_threat_feed_count(),
        }

    def _default_sim_network(self) -> dict:
        return {
            "ssid": "Airtel_Fiber_5G (Simulated)",
            "bssid": "70:85:C2:44:10:01",
            "ssid_permission_warning": None,
            "connection_medium": "Wi-Fi",
            "network_type": "Home / Private Wi-Fi",
            "security_protocol": "WPA3-Personal",
            "cipher": "GCMP-256",
            "signal_percent": 94,
            "encryption_grade": "Strong",
            "local_ip": "192.168.1.14",
            "gateway_ip": "192.168.1.1",
            "gateway_mac": "70:85:C2:44:10:01",
            "subnet_cidr": "192.168.1.0/24",
            "dns_servers": ["1.1.1.1", "192.168.1.1"],
            "interface_name": "Wi-Fi",
            "vpn_active": False,
            "vpn_interface": None,
            "is_public_or_untrusted": False,
            "arp_pinned": "Airtel_Fiber_5G (Simulated)" in self.arp_pinned_ssids,
            "plain_summary": "Simulation Mode active — switch off Simulation Mode in Threats & Alerts to inspect your real local Wi-Fi.",
        }

    def _default_sim_devices(self) -> List[dict]:
        return [
            {"ip": "192.168.1.1", "mac": "70:85:C2:44:10:01", "real_name": "Airtel Xstream Fiber Router", "name_source": "ssdp", "vendor": "Nokia / Airtel Fiber", "device_type": "router", "os_hint": "Nokia G-2425G-A", "is_gateway": True, "is_self": False, "is_randomized_mac": False, "latency_ms": 2},
            {"ip": "192.168.1.14", "mac": "A4:83:E7:21:9B:04", "real_name": "Workstation Laptop (This Computer)", "name_source": "host", "vendor": "Apple", "device_type": "laptop", "os_hint": "Windows 11", "is_gateway": False, "is_self": True, "is_randomized_mac": False, "latency_ms": 1},
            {"ip": "192.168.1.22", "mac": "F0:18:98:77:3A:11", "real_name": "iPhone 15 Pro", "name_source": "mdns", "vendor": "Apple", "device_type": "phone", "os_hint": "iOS Bonjour", "is_gateway": False, "is_self": False, "is_randomized_mac": False, "latency_ms": 8},
            {"ip": "192.168.1.31", "mac": "34:23:BA:50:12:88", "real_name": "Living Room Samsung QLED TV", "name_source": "ssdp", "vendor": "Samsung", "device_type": "tv", "os_hint": "Samsung UPnP", "is_gateway": False, "is_self": False, "is_randomized_mac": False, "latency_ms": 12},
            {"ip": "192.168.1.45", "mac": "3C:D9:2B:99:40:12", "real_name": "HP LaserJet Office Printer", "name_source": "mdns", "vendor": "HP", "device_type": "printer", "os_hint": "IPP Printer", "is_gateway": False, "is_self": False, "is_randomized_mac": False, "latency_ms": 16},
        ]

    async def run_scan(self, db: Session, active_sweep: bool = True, check_doh: bool = True) -> dict:
        settings = _get_or_create_settings(db)
        now = datetime.now(timezone.utc)

        if settings.simulation_mode:
            net_info = dict(self._sim_network_override or self._default_sim_network())
            observed = list(self._default_sim_devices()) + list(self._sim_extra_devices)
        else:
            net_info = await asyncio.to_thread(detect_network_environment)
            observed = await asyncio.to_thread(discover_lan_devices, net_info, self.ids.dhcp_hostnames, active_sweep)

        ensure_genesis_block(db, net_info["ssid"])
        net_info["arp_pinned"] = net_info["ssid"] in self.arp_pinned_ssids
        self.last_network = net_info
        self.last_scan_at = now
        self.ids.update_network_context(net_info["local_ip"], net_info["gateway_ip"], net_info["gateway_mac"])

        existing_rows = db.query(Device).all()
        existing_by_mac = {r.mac.upper(): r for r in existing_rows}
        known_safe_macs = {r.mac.upper() for r in existing_rows if r.is_safe}
        existing_macs = set(existing_by_mac.keys())

        baseline_row = db.query(NetworkBaseline).filter(NetworkBaseline.ssid == net_info["ssid"]).first()
        baseline_dict = None
        if baseline_row:
            baseline_dict = {
                "ssid": baseline_row.ssid,
                "gateway_ip": baseline_row.gateway_ip,
                "gateway_mac": baseline_row.gateway_mac,
                "dns_servers": baseline_row.dns_servers,
            }

        new_alerts = evaluate_baseline_and_passive_threats(
            net_info=net_info,
            observed_devices=observed,
            known_safe_macs=known_safe_macs,
            existing_macs=existing_macs,
            baseline=baseline_dict,
            alert_on_new_device=settings.alert_on_new_device,
            alert_on_passive_risk=settings.alert_on_passive_risk,
        )

        if check_doh and not settings.simulation_mode:
            ok_dns, dns_note, dns_alert = await asyncio.to_thread(verify_dns_integrity_doh)
            self.ids.dns_checks_passed = ok_dns
            self.ids.dns_check_note = dns_note
            if dns_alert:
                new_alerts.append(dns_alert)

        if not baseline_row and net_info.get("gateway_mac"):
            db.add(NetworkBaseline(
                ssid=net_info["ssid"],
                bssid=net_info.get("bssid"),
                gateway_ip=net_info["gateway_ip"],
                gateway_mac=net_info["gateway_mac"],
                dns_servers=",".join(net_info.get("dns_servers", [])),
                security_protocol=net_info["security_protocol"],
                network_type=net_info["network_type"],
            ))

        seen_macs = set()
        first_bootstrap = len(existing_rows) == 0
        for d in observed:
            mac = normalize_mac(d["mac"])
            seen_macs.add(mac)
            row = existing_by_mac.get(mac)
            if row:
                row.ip = d["ip"]
                row.real_name = d["real_name"]
                row.name_source = d.get("name_source", "oui")
                row.vendor = d["vendor"]
                row.device_type = d["device_type"]
                row.os_hint = d.get("os_hint")
                row.is_gateway = d["is_gateway"]
                row.is_self = d["is_self"]
                row.is_online = True
                row.is_randomized_mac = d.get("is_randomized_mac", False)
                row.latency_ms = d["latency_ms"]
                row.last_seen = now
            else:
                auto_safe = bool(d["is_self"] or (first_bootstrap and d["is_gateway"]))
                db.add(Device(
                    mac=mac,
                    ip=d["ip"],
                    real_name=d["real_name"],
                    name_source=d.get("name_source", "oui"),
                    vendor=d["vendor"],
                    device_type=d["device_type"],
                    os_hint=d.get("os_hint"),
                    is_gateway=d["is_gateway"],
                    is_self=d["is_self"],
                    is_safe=auto_safe,
                    is_online=True,
                    is_randomized_mac=d.get("is_randomized_mac", False),
                    latency_ms=d["latency_ms"],
                    first_seen=now,
                    last_seen=now,
                ))

        for mac, row in existing_by_mac.items():
            if mac not in seen_macs:
                row.is_online = False

        created_alerts = []
        unresolved = db.query(Alert).filter(Alert.resolved == False).all()  # noqa: E712
        unresolved_keys = {(a.attack_type, a.related_mac or "", a.title) for a in unresolved}

        for item in new_alerts:
            key = (item["attack_type"], item.get("related_mac") or "", item["title"])
            if key not in unresolved_keys:
                a = Alert(
                    severity=item["severity"],
                    category=item["category"],
                    attack_type=item["attack_type"],
                    title=item["title"],
                    plain_explanation=item["plain_explanation"],
                    what_to_do=item["what_to_do"],
                    technical_evidence=item.get("technical_evidence"),
                    related_mac=item.get("related_mac"),
                    related_ip=item.get("related_ip"),
                    resolved=False,
                    created_at=now,
                )
                db.add(a)
                db.flush()
                created_alerts.append(_serialize_alert(a))
                unresolved_keys.add(key)

        db.commit()

        # Seal critical alerts into the cryptographic attestation ledger
        for ca in created_alerts:
            if ca["severity"] == "critical":
                append_attestation_block(
                    db,
                    event_type=f"alert_{ca['attack_type']}",
                    summary=ca["title"],
                    payload={"alert_id": ca["id"], "category": ca["category"], "ip": ca["related_ip"], "mac": ca["related_mac"]},
                )

        snapshot = self.get_snapshot(db)
        await ws_manager.broadcast("snapshot", snapshot)
        for ca in created_alerts:
            await ws_manager.broadcast("alert", ca)
            asyncio.create_task(dispatch_external_alert(ca, settings))
        return snapshot

    def _get_malware_summary(self, db: Session) -> dict:
        avail = [k for k, v in detect_available_engines().items() if v]
        last_run = db.query(MalwareScanRun).order_by(MalwareScanRun.completed_at.desc()).first()
        if not last_run:
            return {
                "last_scan_at": None,
                "engines_available": avail,
                "files_scanned": 0,
                "processes_scanned": 0,
                "threats_found": 0,
                "findings": [],
            }
        try:
            findings = json.loads(last_run.findings_json or "[]")
        except Exception:
            findings = []
        return {
            "last_scan_at": last_run.completed_at.isoformat() if hasattr(last_run.completed_at, "isoformat") else str(last_run.completed_at) if last_run.completed_at else None,
            "engines_available": avail,
            "files_scanned": last_run.files_scanned,
            "processes_scanned": last_run.processes_scanned,
            "threats_found": last_run.threats_found,
            "findings": findings,
        }

    def _get_blocked_ips(self, db: Session) -> List[str]:
        logs = db.query(FirewallRuleLog).order_by(FirewallRuleLog.created_at.asc()).all()
        blocked = set()
        for row in logs:
            if row.action == "block" and row.enforced:
                blocked.add(row.target_ip)
            elif row.action == "unblock":
                blocked.discard(row.target_ip)
        return sorted(blocked)

    def get_snapshot(self, db: Session) -> dict:
        settings = _get_or_create_settings(db)
        net_info = self.last_network or (
            self._sim_network_override or self._default_sim_network()
            if settings.simulation_mode
            else detect_network_environment()
        )
        ensure_genesis_block(db, net_info["ssid"])

        devices_rows = db.query(Device).order_by(
            Device.is_online.desc(), Device.is_safe.asc(), Device.is_gateway.desc(), Device.ip.asc()
        ).all()
        alerts_rows = db.query(Alert).order_by(Alert.resolved.asc(), Alert.created_at.desc()).limit(80).all()

        devices = [_serialize_device(d) for d in devices_rows]
        alerts = [_serialize_alert(a) for a in alerts_rows]
        ids_stats = self.ids.get_stats()
        arp_rates, syn_ports = self.ids.get_ml_telemetry()
        ml_summary = ml_engine.evaluate_snapshot(devices, alerts, ids_stats, arp_rates, syn_ports)
        ledger_summary = get_ledger_summary(db)
        malware_summary = self._get_malware_summary(db)
        firewall_status = get_firewall_status(
            blocked_ips=self._get_blocked_ips(db),
            lockdown_active=self.lockdown_active,
        )
        advisor = build_security_advice(net_info, devices, alerts, malware_summary, firewall_status, ml_summary)

        online = [d for d in devices if d["is_online"]]
        counts = {
            "total_connected": len(online),
            "safe_devices": sum(1 for d in online if d["is_safe"]),
            "unverified_devices": sum(1 for d in online if not d["is_safe"]),
            "active_alerts": sum(1 for a in alerts if not a["resolved"]),
            "critical_alerts": sum(1 for a in alerts if not a["resolved"] and a["severity"] == "critical"),
            "malware_threats": malware_summary["threats_found"],
            "blocked_ips": len(firewall_status["blocked_ips"]),
            "ml_anomalies": ml_summary["anomalous_devices"],
            "ledger_blocks": ledger_summary["total_blocks"],
        }

        return {
            "mode": "simulation" if settings.simulation_mode else "live",
            "last_scan_at": self.last_scan_at.isoformat() if hasattr(self.last_scan_at, "isoformat") else str(self.last_scan_at) if self.last_scan_at else None,
            "capabilities": self.get_capabilities(),
            "network": net_info,
            "counts": counts,
            "devices": devices,
            "alerts": alerts,
            "ids_stats": ids_stats,
            "ml": ml_summary,
            "ledger": ledger_summary,
            "malware": malware_summary,
            "firewall": firewall_status,
            "advisor": advisor,
            "settings": _serialize_settings(settings),
        }

    async def trigger_simulation(self, db: Session, scenario: str) -> dict:
        # GARUDA v8 Fix: Never lock settings.simulation_mode=True in DB.
        # Simulations run as isolated ephemeral injections while real physical Wi-Fi stays active.
        settings = _get_or_create_settings(db)
        if scenario == "reset":
            settings.simulation_mode = False
            db.commit()
        now = datetime.now(timezone.utc)

        if scenario == "reset":
            self._sim_network_override = None
            self._sim_extra_devices = []
            ml_engine.inject_simulated_anomaly("", None)
            db.query(Alert).update({Alert.resolved: True})
            db.query(Device).filter(Device.mac.in_(["DE:AD:BE:9F:01:22", "28:6C:07:55:AA:91", "B8:27:EB:88:11:09"])).delete(synchronize_session=False)
            db.commit()
            return await self.run_scan(db, active_sweep=False, check_doh=False)

        if scenario == "ml_beacon":
            self._sim_extra_devices = [d for d in self._sim_extra_devices if d["mac"] != "B8:27:EB:88:11:09"]
            self._sim_extra_devices.append({
                "ip": "192.168.1.94", "mac": "B8:27:EB:88:11:09", "real_name": "xk9q2z7m4p1w-iot",
                "name_source": "dhcp", "vendor": "Raspberry Pi", "device_type": "iot", "os_hint": "Linux Embedded",
                "is_gateway": False, "is_self": False, "is_randomized_mac": False, "latency_ms": 148,
            })
            ml_engine.inject_simulated_anomaly("B8:27:EB:88:11:09", {
                "latency_zscore": 0.88,
                "dns_entropy_norm": 0.91,
                "beacon_regularity": 0.96,
            })
            a = Alert(
                severity="critical", category="active_attack", attack_type="ml_c2_beacon",
                title="AI Detected Robotic C2 Beaconing & High-Entropy DNS (192.168.1.94)",
                plain_explanation=(
                    "GARUDA's IsolationForest + Welford ML ensemble flagged 'xk9q2z7m4p1w-iot' (192.168.1.94) for robotic 30-second "
                    "periodic beaconing, +4.4σ latency jump, and randomized DGA domain entropy."
                ),
                what_to_do="Open AI & Ledger to review top ML contributing factors, then block 192.168.1.94 via Firewall Shield.",
                related_mac="B8:27:EB:88:11:09", related_ip="192.168.1.94", resolved=False, created_at=now,
            )
            db.add(a)
            db.commit()
            append_attestation_block(
                db,
                event_type="ml_c2_beacon",
                summary=a.title,
                payload={"mac": "B8:27:EB:88:11:09", "ip": "192.168.1.94", "beacon_regularity": 0.96, "dns_entropy": 0.91},
            )
            return await self.run_scan(db, active_sweep=False, check_doh=False)

        if scenario == "new_unknown_device":
            self._sim_extra_devices = [d for d in self._sim_extra_devices if d["mac"] != "28:6C:07:55:AA:91"]
            self._sim_extra_devices.append({
                "ip": "192.168.1.87", "mac": "28:6C:07:55:AA:91", "real_name": "Redmi Note 13 (Unknown Guest)",
                "name_source": "dhcp", "vendor": "Xiaomi", "device_type": "phone", "os_hint": "Android DHCP",
                "is_gateway": False, "is_self": False, "is_randomized_mac": False, "latency_ms": 17,
            })
            return await self.run_scan(db, active_sweep=False, check_doh=False)

        if scenario == "arp_spoof":
            base = self._default_sim_network()
            base["gateway_mac"] = "DE:AD:BE:9F:01:22"
            self._sim_network_override = base
            self._sim_extra_devices = [d for d in self._sim_extra_devices if d["mac"] != "DE:AD:BE:9F:01:22"]
            self._sim_extra_devices.append({
                "ip": "192.168.1.109", "mac": "DE:AD:BE:9F:01:22", "real_name": "Kali-Attacker-0x9F",
                "name_source": "dhcp", "vendor": "Spoofed / Test MAC", "device_type": "unknown", "os_hint": "Impersonating Router",
                "is_gateway": False, "is_self": False, "is_randomized_mac": False, "latency_ms": 4,
            })
            ml_engine.inject_simulated_anomaly("DE:AD:BE:9F:01:22", {"arp_burst_norm": 1.0, "syn_fanout_norm": 0.55})
            return await self.run_scan(db, active_sweep=False, check_doh=False)

        if scenario == "open_wifi":
            base = self._default_sim_network()
            base.update({
                "ssid": "Airport_Free_WiFi_Guest (Simulated)",
                "network_type": "Public / Open Wi-Fi (Unencrypted)",
                "security_protocol": "Open (Unencrypted)",
                "encryption_grade": "None",
                "is_public_or_untrusted": True,
                "plain_summary": "No Wi-Fi encryption. Anyone nearby can silently eavesdrop on unencrypted traffic.",
            })
            self._sim_network_override = base
            return await self.run_scan(db, active_sweep=False, check_doh=False)

        if scenario == "dns_hijack":
            base = self._default_sim_network()
            base["dns_servers"] = ["185.220.101.45"]
            self._sim_network_override = base
            return await self.run_scan(db, active_sweep=False, check_doh=False)

        if scenario in ("rogue_dhcp", "port_sweep", "malware_eicar"):
            if scenario == "rogue_dhcp":
                item = {
                    "severity": "critical", "category": "active_attack", "attack_type": "rogue_dhcp",
                    "title": "Active Rogue DHCP Server Detected (192.168.1.109)",
                    "plain_explanation": "An unauthorized device tried to hand out fake router and DNS settings to devices on your Wi-Fi.",
                    "what_to_do": "Block 192.168.1.109 via Firewall Shield and enable Encrypted Private DNS.",
                    "related_mac": "DE:AD:BE:9F:01:22", "related_ip": "192.168.1.109",
                }
            elif scenario == "port_sweep":
                item = {
                    "severity": "critical", "category": "active_attack", "attack_type": "port_sweep",
                    "title": "Active Port Scan Targeting Your Computer from 192.168.1.87",
                    "plain_explanation": "192.168.1.87 probed 24 different ports on your device in under 4 seconds looking for exposed services.",
                    "what_to_do": "Activate Firewall Lockdown Mode or block 192.168.1.87 in Firewall Shield.",
                    "related_mac": "28:6C:07:55:AA:91", "related_ip": "192.168.1.87",
                }
            else:
                finding = {
                    "id": "sim-eicar-01", "severity": "critical", "engine": "yara", "category": "virus",
                    "name": "EICAR Antivirus Test Signature (Simulated)", "target": "~/Downloads/invoice_test.txt",
                    "plain_explanation": "Simulated malware detection verifying GARUDA's virus alert pipeline.",
                    "what_to_do": "Delete or quarantine the flagged file immediately.", "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                }
                db.add(MalwareScanRun(
                    scan_type="simulated", target_path="~/Downloads", engines_used="yara,builtin_sig",
                    files_scanned=18, processes_scanned=94, threats_found=1, findings_json=json.dumps([finding]),
                    started_at=now, completed_at=now,
                ))
                item = {
                    "severity": "critical", "category": "malware_threat", "attack_type": "malware_file",
                    "title": "Malware Signature Detected in Downloads",
                    "plain_explanation": finding["plain_explanation"],
                    "what_to_do": finding["what_to_do"],
                    "related_mac": None, "related_ip": None,
                }
            db.add(Alert(**item, resolved=False, created_at=now))
            db.commit()
            append_attestation_block(
                db,
                event_type=f"sim_{scenario}",
                summary=item["title"],
                payload={"scenario": scenario, "ip": item["related_ip"], "mac": item["related_mac"]},
            )
            snap = self.get_snapshot(db)
            await ws_manager.broadcast("snapshot", snap)
            return snap

        return await self.run_scan(db, active_sweep=False, check_doh=False)

    async def background_loop(self):
        while True:
            interval = 15
            try:
                db = SessionLocal()
                try:
                    s = _get_or_create_settings(db)
                    interval = max(5, s.scan_interval_sec)
                    await self.run_scan(db, active_sweep=True, check_doh=True)
                finally:
                    db.close()
            except Exception:
                pass
            await asyncio.sleep(interval)


monitor = GarudaV4Monitor()
