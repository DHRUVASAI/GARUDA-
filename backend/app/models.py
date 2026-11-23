from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from .database import Base


def utcnow():
    return datetime.now(timezone.utc)


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    mac = Column(String(32), unique=True, index=True, nullable=False)
    ip = Column(String(64), index=True, nullable=False)
    real_name = Column(String(255), nullable=False, default="Unidentified Device")
    name_source = Column(String(40), nullable=False, default="oui")
    custom_name = Column(String(255), nullable=True)
    vendor = Column(String(160), nullable=False, default="Unknown Manufacturer")
    device_type = Column(String(64), nullable=False, default="unknown")
    os_hint = Column(String(120), nullable=True)
    is_gateway = Column(Boolean, default=False, nullable=False)
    is_self = Column(Boolean, default=False, nullable=False)
    is_safe = Column(Boolean, default=False, nullable=False)
    is_online = Column(Boolean, default=True, nullable=False)
    is_randomized_mac = Column(Boolean, default=False, nullable=False)
    latency_ms = Column(Integer, nullable=True)
    first_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    severity = Column(String(24), nullable=False, index=True)
    category = Column(String(32), nullable=False, index=True)
    attack_type = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    plain_explanation = Column(Text, nullable=False)
    what_to_do = Column(Text, nullable=False)
    technical_evidence = Column(Text, nullable=True)
    related_mac = Column(String(32), nullable=True)
    related_ip = Column(String(64), nullable=True)
    resolved = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class NetworkBaseline(Base):
    __tablename__ = "network_baselines"

    id = Column(Integer, primary_key=True, index=True)
    ssid = Column(String(128), nullable=False, index=True)
    bssid = Column(String(32), nullable=True)
    gateway_ip = Column(String(64), nullable=False)
    gateway_mac = Column(String(32), nullable=False)
    dns_servers = Column(String(255), nullable=False, default="")
    security_protocol = Column(String(64), nullable=False, default="Unknown")
    network_type = Column(String(64), nullable=False, default="Home / Private Wi-Fi")
    arp_pinned = Column(Boolean, default=False, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class MalwareScanRun(Base):
    __tablename__ = "malware_scan_runs"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(32), nullable=False)
    target_path = Column(String(512), nullable=True)
    engines_used = Column(String(255), nullable=False, default="")
    files_scanned = Column(Integer, default=0, nullable=False)
    processes_scanned = Column(Integer, default=0, nullable=False)
    threats_found = Column(Integer, default=0, nullable=False)
    status = Column(String(24), default="completed", nullable=False)
    findings_json = Column(Text, nullable=False, default="[]")
    started_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    completed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class FirewallRuleLog(Base):
    __tablename__ = "firewall_rule_logs"

    id = Column(Integer, primary_key=True, index=True)
    target_ip = Column(String(64), nullable=False, index=True)
    rule_name = Column(String(128), nullable=False)
    action = Column(String(24), nullable=False)
    reason = Column(String(255), nullable=False, default="")
    enforced = Column(Boolean, default=False, nullable=False)
    command_used = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AttestationBlock(Base):
    __tablename__ = "attestation_blocks"

    id = Column(Integer, primary_key=True, index=True)
    block_index = Column(Integer, unique=True, index=True, nullable=False)
    timestamp_utc = Column(String(64), nullable=False)
    event_type = Column(String(64), nullable=False, index=True)
    summary = Column(String(255), nullable=False)
    payload_json = Column(Text, nullable=False)
    payload_sha256 = Column(String(64), nullable=False)
    prev_hash = Column(String(64), nullable=False)
    merkle_root = Column(String(64), nullable=False)
    block_hash = Column(String(64), unique=True, index=True, nullable=False)
    signature_alg = Column(String(32), nullable=False, default="Ed25519")
    signature_hex = Column(String(256), nullable=False)
    signer_pubkey_hex = Column(String(128), nullable=False)
    anchor_status = Column(String(32), nullable=False, default="local_signed")  # local_signed | anchored_evm
    chain_name = Column(String(64), nullable=True)
    tx_hash = Column(String(128), nullable=True)
    contract_address = Column(String(64), nullable=True)


class AlertSettings(Base):
    __tablename__ = "alert_settings"

    id = Column(Integer, primary_key=True, default=1)
    sound_enabled = Column(Boolean, default=True, nullable=False)
    desktop_notifications = Column(Boolean, default=True, nullable=False)
    alert_on_new_device = Column(Boolean, default=True, nullable=False)
    alert_on_passive_risk = Column(Boolean, default=True, nullable=False)
    auto_block_active_attackers = Column(Boolean, default=False, nullable=False)
    webhook_url = Column(String(512), nullable=True)
    telegram_bot_token = Column(String(256), nullable=True)
    telegram_chat_id = Column(String(128), nullable=True)
    simulation_mode = Column(Boolean, default=False, nullable=False)
    scan_interval_sec = Column(Integer, default=15, nullable=False)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    email = Column(String(128), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(24), default="viewer", nullable=False)  # admin | analyst | viewer
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class AdminAuditLog(Base):
    __tablename__ = "admin_audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    actor_username = Column(String(64), nullable=False, index=True)
    action = Column(String(100), nullable=False, index=True)
    target = Column(String(255), nullable=True)
    detail = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class DoctorReport(Base):
    __tablename__ = "doctor_reports"

    id = Column(Integer, primary_key=True, index=True)
    triggered_by = Column(String(64), nullable=False, default="system")
    health_score = Column(Integer, nullable=False)
    grade = Column(String(16), nullable=False)
    issues_count = Column(Integer, default=0, nullable=False)
    report_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class FleetAgentReport(Base):
    __tablename__ = "fleet_agent_reports"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(64), nullable=False, index=True)
    agent_name = Column(String(128), nullable=False)
    agent_os = Column(String(64), nullable=False)
    ssid = Column(String(128), nullable=False, index=True)
    gateway_ip = Column(String(64), nullable=True)
    gateway_mac = Column(String(64), nullable=True)
    subnet_cidr = Column(String(64), nullable=True)
    device_count = Column(Integer, default=0, nullable=False)
    devices_json = Column(Text, nullable=False, default="[]")
    alerts_count = Column(Integer, default=0, nullable=False)
    alerts_json = Column(Text, nullable=False, default="[]")
    security_score = Column(Integer, default=100, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)

