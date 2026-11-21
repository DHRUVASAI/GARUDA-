from typing import Optional
import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from .config import FRONTEND_DIR
from .database import SessionLocal, get_db, init_db
from .models import Alert, Device, FirewallRuleLog, MalwareScanRun, NetworkBaseline
from .schemas import (
    AlertSettingsIn,
    AlertSettingsOut,
    CapabilitiesOut,
    DashboardSnapshotOut,
    DeviceRenameUpdate,
    DeviceTrustUpdate,
    DomainAnalysisIn,
    DomainAnalysisOut,
    FirewallBlockRequest,
    FirewallLockdownRequest,
    LedgerSealRequest,
    MalwareScanRequest,
    SimulateScenarioIn,
)
from .services.attestation_ledger import (
    anchor_merkle_root_evm,
    append_attestation_block,
    get_block_merkle_proof,
    get_ledger_summary,
    verify_ledger_integrity,
)
from .services.firewall_manager import enforce_block_ip, enforce_lockdown_mode
from .services.ids_engine import pin_static_gateway_arp
from .services.malware_scanner import run_host_malware_scan, sync_abusech_threat_feed
from .services.ml_engine import analyze_domain_dga, ml_engine
from .services.monitor import _get_or_create_settings, _serialize_device, _serialize_settings, monitor
from .services.notifier import ws_manager
from .services.oui_db import sync_ieee_oui_database
from .services.capability_probe import probe_network_environment
from .services.device_scanner import read_os_arp_table
from .services.network_detector import detect_network_environment
from .services.plugin_engine import plugin_orchestrator
from .services.rule_updater import rule_manager
from .services.campaign_correlator import correlate_attack_campaigns
from .services.aws_bridge import (
    SAMPLE_VPC_FLOW_LOGS,
    dispatch_aws_finding,
    parse_vpc_flow_logs,
    to_aws_security_hub_asff,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    monitor.bind_loop(asyncio.get_running_loop())
    monitor.ids.start()
    db = SessionLocal()
    try:
        await monitor.run_scan(db, active_sweep=False, check_doh=False)
    finally:
        db.close()
    monitor._bg_task = asyncio.create_task(monitor.background_loop())
    try:
        yield
    finally:
        monitor.ids.stop()
        if monitor._bg_task:
            monitor._bg_task.cancel()


app = FastAPI(
    title="GARUDA v6 — Adversarial-Hardened Auto-Adapting Network Guardian, Live IDS, ML Anomaly, AWS Bridge & Web3 Ledger API",
    version="6.0.0",
    description=(
        "Cross-platform personal network guardian with 5-layer real device naming, live Scapy packet IDS, "
        "IsolationForest + Welford ML behavioral engine, Ed25519 + SHA-256 Merkle Web3 attestation ledger, "
        "ClamAV/YARA/psutil malware shield, and real OS firewall enforcement."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "GARUDA v6 Engine", "version": "6.0.0"}


@app.get("/api/capabilities", response_model=CapabilitiesOut)
def capabilities():
    return monitor.get_capabilities()


@app.get("/api/snapshot", response_model=DashboardSnapshotOut)
def get_snapshot(db: Session = Depends(get_db)):
    return monitor.get_snapshot(db)


@app.post("/api/scan", response_model=DashboardSnapshotOut)
async def trigger_network_scan(db: Session = Depends(get_db)):
    return await monitor.run_scan(db, active_sweep=True, check_doh=True)


# -------------------- Devices & Safe Marking (with ML Baseline Feedback) --------------------
@app.post("/api/devices/{mac}/trust")
async def update_device_trust(mac: str, body: DeviceTrustUpdate, db: Session = Depends(get_db)):
    norm = mac.strip().upper().replace("-", ":")
    dev = db.query(Device).filter(Device.mac == norm).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    dev.is_safe = body.is_safe
    if body.custom_name is not None:
        dev.custom_name = body.custom_name.strip() or None
    if body.is_safe:
        db.query(Alert).filter(
            Alert.related_mac == norm,
            Alert.attack_type == "new_device",
            Alert.resolved == False,  # noqa: E712
        ).update({Alert.resolved: True}, synchronize_session=False)
        ml_engine.reinforce_safe_device(norm)
    db.commit()
    db.refresh(dev)
    snap = monitor.get_snapshot(db)
    await ws_manager.broadcast("snapshot", snap)
    return {"device": _serialize_device(dev), "snapshot": snap}


@app.patch("/api/devices/{mac}/rename")
async def rename_device(mac: str, body: DeviceRenameUpdate, db: Session = Depends(get_db)):
    norm = mac.strip().upper().replace("-", ":")
    dev = db.query(Device).filter(Device.mac == norm).first()
    if not dev:
        raise HTTPException(status_code=404, detail="Device not found")
    dev.custom_name = body.custom_name.strip()
    db.commit()
    db.refresh(dev)
    snap = monitor.get_snapshot(db)
    await ws_manager.broadcast("snapshot", snap)
    return {"device": _serialize_device(dev), "snapshot": snap}


# -------------------- AI / ML Behavioral Anomaly Engine --------------------
@app.post("/api/ml/analyze-domain", response_model=DomainAnalysisOut)
def analyze_domain(body: DomainAnalysisIn):
    return analyze_domain_dga(body.domain)


@app.post("/api/ml/retrain")
async def retrain_ml_baseline(db: Session = Depends(get_db)):
    result = await asyncio.to_thread(ml_engine.retrain_now)
    snap = monitor.get_snapshot(db)
    await ws_manager.broadcast("snapshot", snap)
    return {"result": result, "snapshot": snap}


# -------------------- Cryptographic Forensic & Web3 Attestation Ledger --------------------
@app.get("/api/ledger/verify")
def verify_ledger(db: Session = Depends(get_db)):
    return verify_ledger_integrity(db)


@app.get("/api/ledger/proof/{block_index}")
def get_merkle_proof(block_index: int, db: Session = Depends(get_db)):
    proof = get_block_merkle_proof(db, block_index)
    if not proof:
        raise HTTPException(status_code=404, detail="Ledger block not found")
    return proof


@app.post("/api/ledger/seal")
async def seal_posture_block(body: LedgerSealRequest, db: Session = Depends(get_db)):
    snap_before = monitor.get_snapshot(db)
    blk = append_attestation_block(
        db,
        event_type="posture_seal",
        summary=body.note,
        payload={
            "ssid": snap_before["network"]["ssid"],
            "gateway_mac": snap_before["network"]["gateway_mac"],
            "safety_score": snap_before["advisor"]["safety_score"],
            "ml_anomaly_score": snap_before["ml"]["network_anomaly_score"],
            "connected_devices": snap_before["counts"]["total_connected"],
            "active_alerts": snap_before["counts"]["active_alerts"],
        },
    )
    snap = monitor.get_snapshot(db)
    await ws_manager.broadcast("snapshot", snap)
    return {"block_index": blk.block_index, "block_hash": blk.block_hash, "merkle_root": blk.merkle_root, "snapshot": snap}


@app.post("/api/ledger/anchor")
async def anchor_ledger(db: Session = Depends(get_db)):
    snap_cur = monitor.get_snapshot(db)
    res = await asyncio.to_thread(anchor_merkle_root_evm, db, snap_cur["network"]["ssid"])
    snap = monitor.get_snapshot(db)
    await ws_manager.broadcast("snapshot", snap)
    return {"result": res, "snapshot": snap}


@app.get("/api/ledger/export")
def export_forensic_bundle(db: Session = Depends(get_db)):
    return {
        "schema": "garuda-v4-forensic-attestation-bundle",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "integrity": verify_ledger_integrity(db),
        "ledger": get_ledger_summary(db),
    }


# -------------------- MITM Defense (Static ARP Pinning) --------------------
@app.post("/api/mitm/pin-gateway")
async def pin_gateway(db: Session = Depends(get_db)):
    snap = monitor.get_snapshot(db)
    net = snap["network"]
    res = await asyncio.to_thread(
        pin_static_gateway_arp, net["gateway_ip"], net["gateway_mac"], net["interface_name"]
    )
    if res["enforced"]:
        monitor.arp_pinned_ssids.add(net["ssid"])
        base = db.query(NetworkBaseline).filter(NetworkBaseline.ssid == net["ssid"]).first()
        if base:
            base.arp_pinned = True
            db.commit()
        append_attestation_block(
            db,
            event_type="mitm_arp_pin",
            summary=f"Pinned gateway {net['gateway_ip']} ({net['gateway_mac']})",
            payload={"gateway_ip": net["gateway_ip"], "gateway_mac": net["gateway_mac"], "ssid": net["ssid"]},
        )
    new_snap = monitor.get_snapshot(db)
    await ws_manager.broadcast("snapshot", new_snap)
    return {"result": res, "snapshot": new_snap}


# -------------------- Malware & Process Scanner --------------------
@app.post("/api/malware/scan")
async def trigger_malware_scan(body: MalwareScanRequest, db: Session = Depends(get_db)):
    started = datetime.now(timezone.utc)
    result = await asyncio.to_thread(
        run_host_malware_scan, body.target_path, body.scan_processes
    )
    completed = datetime.now(timezone.utc)
    run_row = MalwareScanRun(
        scan_type="folder" if body.target_path else "quick_host",
        target_path=result["target_path"],
        engines_used=",".join(result["engines_available"]),
        files_scanned=result["files_scanned"],
        processes_scanned=result["processes_scanned"],
        threats_found=result["threats_found"],
        status="completed",
        findings_json=json.dumps(result["findings"]),
        started_at=started,
        completed_at=completed,
    )
    db.add(run_row)
    for f in result["findings"]:
        db.add(Alert(
            severity=f["severity"],
            category="malware_threat",
            attack_type=f["category"],
            title=f["name"],
            plain_explanation=f["plain_explanation"],
            what_to_do=f["what_to_do"],
            technical_evidence=json.dumps({"engine": f["engine"], "target": f["target"], "sha256": f.get("sha256")}),
            resolved=False,
            created_at=completed,
        ))
    db.commit()
    if result["threats_found"] > 0:
        append_attestation_block(
            db,
            event_type="malware_detected",
            summary=f"Malware scan flagged {result['threats_found']} threat(s)",
            payload={"target_path": result["target_path"], "threats_found": result["threats_found"]},
        )
    snap = monitor.get_snapshot(db)
    await ws_manager.broadcast("snapshot", snap)
    return {"scan": result, "snapshot": snap}


# -------------------- Real OS Firewall Controller --------------------
@app.post("/api/firewall/block")
async def block_ip(body: FirewallBlockRequest, db: Session = Depends(get_db)):
    try:
        res = await asyncio.to_thread(enforce_block_ip, body.ip, False)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {exc}")
    db.add(FirewallRuleLog(
        target_ip=body.ip.strip(),
        rule_name=res["rule_name"],
        action="block",
        reason=body.reason,
        enforced=res["enforced"],
        command_used=res["command"],
    ))
    db.commit()
    append_attestation_block(
        db,
        event_type="firewall_block",
        summary=f"Firewall block requested for {body.ip.strip()} (enforced={res['enforced']})",
        payload={"ip": body.ip.strip(), "enforced": res["enforced"], "reason": body.reason},
    )
    snap = monitor.get_snapshot(db)
    await ws_manager.broadcast("snapshot", snap)
    return {"result": res, "snapshot": snap}


@app.post("/api/firewall/unblock")
async def unblock_ip(body: FirewallBlockRequest, db: Session = Depends(get_db)):
    try:
        res = await asyncio.to_thread(enforce_block_ip, body.ip, True)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {exc}")
    db.add(FirewallRuleLog(
        target_ip=body.ip.strip(),
        rule_name=res["rule_name"],
        action="unblock",
        reason=body.reason,
        enforced=res["enforced"],
        command_used=res["command"],
    ))
    db.commit()
    snap = monitor.get_snapshot(db)
    await ws_manager.broadcast("snapshot", snap)
    return {"result": res, "snapshot": snap}


@app.post("/api/firewall/lockdown")
async def set_firewall_lockdown(body: FirewallLockdownRequest, db: Session = Depends(get_db)):
    res = await asyncio.to_thread(enforce_lockdown_mode, body.enable)
    if res["enforced"]:
        monitor.lockdown_active = body.enable
    db.add(FirewallRuleLog(
        target_ip="0.0.0.0/0",
        rule_name="GARUDA_LOCKDOWN",
        action="lockdown_on" if body.enable else "lockdown_off",
        reason="Public Wi-Fi Lockdown toggle",
        enforced=res["enforced"],
        command_used=res["command"],
    ))
    db.commit()
    snap = monitor.get_snapshot(db)
    await ws_manager.broadcast("snapshot", snap)
    return {"result": res, "snapshot": snap}


# -------------------- Intelligence Sync (IEEE OUI & Abuse.ch C2 Feed) --------------------
@app.post("/api/oui/sync")
async def sync_oui():
    try:
        return await sync_ieee_oui_database()
    except Exception as exc:
        logger.warning(f"OUI sync warning (recovered via local cache): {exc}")
        from .services.oui_db import get_oui_count, IEEE_OUI_CACHE_PATH
        return {
            "status": "success",
            "synced": get_oui_count(),
            "source": "fallback_cache",
            "cache_path": str(IEEE_OUI_CACHE_PATH),
            "details": f"Recovered using verified cached OUI database ({get_oui_count():,} hardware vendor prefixes)."
        }


@app.post("/api/threat-intel/sync")
async def sync_threat_feed():
    try:
        return await sync_abusech_threat_feed()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not sync Abuse.ch Feodo Tracker: {exc}")


# -------------------- Alerts, Settings & Safe Simulation --------------------
@app.post("/api/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.resolved = True
    db.commit()
    snap = monitor.get_snapshot(db)
    await ws_manager.broadcast("snapshot", snap)
    return {"ok": True, "snapshot": snap}


@app.post("/api/alerts/resolve-all")
async def resolve_all_alerts(db: Session = Depends(get_db)):
    db.query(Alert).filter(Alert.resolved == False).update({Alert.resolved: True}, synchronize_session=False)  # noqa: E712
    db.commit()
    snap = monitor.get_snapshot(db)
    await ws_manager.broadcast("snapshot", snap)
    return {"ok": True, "snapshot": snap}


@app.get("/api/settings", response_model=AlertSettingsOut)
def get_settings(db: Session = Depends(get_db)):
    return _serialize_settings(_get_or_create_settings(db))


@app.patch("/api/settings", response_model=AlertSettingsOut)
async def update_settings(body: AlertSettingsIn, db: Session = Depends(get_db)):
    s = _get_or_create_settings(db)
    data = body.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(s, k, v)
    db.commit()
    db.refresh(s)
    if "simulation_mode" in data:
        await monitor.run_scan(db, active_sweep=False, check_doh=False)
    else:
        await ws_manager.broadcast("snapshot", monitor.get_snapshot(db))
    return _serialize_settings(s)



# =====================================================================
# GARUDA v5 Future-Proof Resilience, Plugin & AWS Edge-to-Cloud Routes
# =====================================================================

@app.get("/api/v5/environment")
def v5_environment_probe():
    """Run the v5 Startup Capability Probe (Home / Campus-Safe / VPN + Proxy-ARP + Plugin health)."""
    net_info = detect_network_environment()
    arp_entries = read_os_arp_table()
    env = probe_network_environment(net_info, arp_entries)
    monitor.ids.set_proxy_arp_mode(bool(env["proxy_arp_detected"]), net_info.get("gateway_mac"))
    env["plugin_health"] = plugin_orchestrator.last_run_report
    env["proxy_arp_suppressed_events"] = monitor.ids.proxy_arp_suppressed_count
    env["ssid"] = net_info.get("ssid", "Unknown")
    return env


@app.get("/api/v5/rules")
def v5_get_rules():
    """Return the active externalized v5 threat & OS signature manifest summary."""
    return rule_manager.summary()


@app.post("/api/v5/rules/reload")
def v5_reload_rules():
    """Hot-reload externalized JSON rules without restarting GARUDA."""
    rule_manager.reload()
    return {"status": "reloaded", "manifest": rule_manager.summary()}


@app.post("/api/v5/aws/asff-preview")
def v5_aws_asff_preview(db: Session = Depends(get_db)):
    """Convert the latest GARUDA alert (or a sample finding) into official AWS Security Hub ASFF."""
    latest = db.query(Alert).order_by(Alert.id.desc()).first()
    if latest:
        alert_dict = {
            "id": latest.id,
            "severity": latest.severity,
            "category": latest.category,
            "attack_type": latest.attack_type,
            "title": latest.title,
            "plain_explanation": latest.plain_explanation,
            "what_to_do": latest.what_to_do,
            "related_ip": latest.related_ip,
            "related_mac": latest.related_mac,
        }
    else:
        alert_dict = {
            "id": "demo-001",
            "severity": "critical",
            "category": "active_attack",
            "attack_type": "arp_spoof",
            "title": "Active Gateway ARP Spoofing Detected (GARUDA Edge Sensor)",
            "plain_explanation": "A rogue host attempted to impersonate the local Wi-Fi gateway MAC address.",
            "what_to_do": "Pin static gateway ARP or isolate the offending MAC.",
            "related_ip": "192.168.1.1",
            "related_mac": "DE:AD:BE:EF:00:01",
        }
    asff = to_aws_security_hub_asff(alert_dict)
    return dispatch_aws_finding(asff, dry_run=True)


@app.post("/api/v5/aws/vpc-flow-analyze")
def v5_aws_vpc_flow_analyze(payload: Optional[dict] = None):
    """Analyze AWS VPC Flow Logs (user-supplied or built-in sample) for port sweeps & exfiltration spikes."""
    raw_logs = (payload or {}).get("raw_logs") or SAMPLE_VPC_FLOW_LOGS
    result = parse_vpc_flow_logs(raw_logs)
    result["used_sample"] = not bool((payload or {}).get("raw_logs"))
    return result



# =====================================================================
# GARUDA v6 Purple-Team Campaign Correlation & Adversarial IDS Routes
# =====================================================================

@app.get("/api/v6/campaigns")
def v6_correlate_campaigns(db: Session = Depends(get_db)):
    """Correlate active/historical alerts, devices, firewall logs & ledger blocks into Purple Team campaigns (PT-01..PT-08)."""
    from .models import AttestationBlock

    alerts = [
        {
            "id": a.id,
            "severity": a.severity,
            "category": a.category,
            "attack_type": a.attack_type,
            "title": a.title,
            "related_ip": a.related_ip,
            "related_mac": a.related_mac,
            "created_at": a.created_at.isoformat() if a.created_at else "",
        }
        for a in db.query(Alert).order_by(Alert.created_at.asc()).limit(200).all()
    ]
    devices = [{"mac": d.mac, "ip": d.ip, "is_safe": d.is_safe} for d in db.query(Device).all()]
    fw_logs = [{"target_ip": f.target_ip, "action": f.action, "enforced": f.enforced} for f in db.query(FirewallRuleLog).all()]
    blocks = [{"block_index": b.block_index, "block_hash": b.block_hash} for b in db.query(AttestationBlock).all()]
    return correlate_attack_campaigns(alerts, devices=devices, firewall_logs=fw_logs, ledger_blocks=blocks)


@app.post("/api/simulate", response_model=DashboardSnapshotOut)
async def simulate_event(body: SimulateScenarioIn, db: Session = Depends(get_db)):
    return await monitor.trigger_simulation(db, body.scenario)


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    db = SessionLocal()
    try:
        await websocket.send_json({"type": "snapshot", "data": monitor.get_snapshot(db)})
    finally:
        db.close()
    try:
        while True:
            await websocket.receive_text()
    except (WebSocketDisconnect, Exception):
        ws_manager.disconnect(websocket)


if FRONTEND_DIR.exists() and (FRONTEND_DIR / "index.html").exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    def serve_frontend():
        return FileResponse(str(FRONTEND_DIR / "index.html"))
else:
    @app.get("/")
    def root_status():
        return JSONResponse({
            "service": "GARUDA v4 Backend Engine",
            "docs": "/docs",
            "snapshot": "/api/snapshot",
            "websocket": "/ws/live",
        })
