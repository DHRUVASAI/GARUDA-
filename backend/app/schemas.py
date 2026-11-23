from datetime import datetime
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class CapabilitiesOut(BaseModel):
    os_name: str
    is_admin: bool
    ids_mode: str
    scapy_available: bool
    zeroconf_available: bool
    psutil_available: bool
    clamav_available: bool
    yara_available: bool
    sklearn_available: bool
    crypto_signature_alg: str
    web3_configured: bool
    firewall_backend: str
    ieee_oui_entries: int
    threat_feed_ips: int


class DeviceOut(BaseModel):
    id: int
    mac: str
    ip: str
    real_name: str
    name_source: str
    custom_name: Optional[str] = None
    display_name: str
    vendor: str
    device_type: str
    os_hint: Optional[str] = None
    is_gateway: bool
    is_self: bool
    is_safe: bool
    is_online: bool
    is_randomized_mac: bool
    latency_ms: Optional[int] = None
    first_seen: datetime
    last_seen: datetime


class DeviceTrustUpdate(BaseModel):
    is_safe: bool
    custom_name: Optional[str] = Field(default=None, max_length=120)


class DeviceRenameUpdate(BaseModel):
    custom_name: str = Field(..., min_length=1, max_length=120)


class AlertOut(BaseModel):
    id: int
    severity: str
    category: str
    attack_type: str
    title: str
    plain_explanation: str
    what_to_do: str
    technical_evidence: Optional[str] = None
    related_mac: Optional[str] = None
    related_ip: Optional[str] = None
    resolved: bool
    created_at: datetime


class NetworkInfoOut(BaseModel):
    ssid: str
    bssid: Optional[str] = None
    ssid_permission_warning: Optional[str] = None
    connection_medium: str
    network_type: str
    security_protocol: str
    cipher: Optional[str] = None
    signal_percent: Optional[int] = None
    encryption_grade: str
    local_ip: str
    gateway_ip: str
    gateway_mac: str
    subnet_cidr: str
    dns_servers: List[str]
    interface_name: str
    vpn_active: bool
    vpn_interface: Optional[str] = None
    is_public_or_untrusted: bool
    arp_pinned: bool = False
    plain_summary: str


class IDSStatsOut(BaseModel):
    mode: str
    packets_inspected: int
    arp_events_observed: int
    dhcp_offers_observed: int
    dns_checks_passed: bool
    dns_check_note: str
    cleartext_flows_detected: int
    active_sniffer_running: bool


class MLFactorOut(BaseModel):
    feature: str
    label: str
    value: float
    contribution_pct: float


class MLDeviceScoreOut(BaseModel):
    mac: str
    ip: str
    display_name: str
    anomaly_score: float
    risk_level: str                 # normal | elevated | critical
    iforest_score: float
    statistical_score: float
    top_factors: List[MLFactorOut]
    plain_summary: str


class MLSummaryOut(BaseModel):
    engine_name: str
    sklearn_active: bool
    baseline_samples: int
    last_trained_at: Optional[datetime] = None
    network_anomaly_score: float
    status_label: str
    headline: str
    anomalous_devices: int
    device_scores: List[MLDeviceScoreOut]


class DomainAnalysisIn(BaseModel):
    domain: str = Field(..., min_length=2, max_length=255)


class DomainAnalysisOut(BaseModel):
    domain: str
    entropy_bits: float
    digit_ratio: float
    vowel_ratio: float
    label_length: int
    dga_probability: float
    verdict: str
    plain_explanation: str


class AttestationBlockOut(BaseModel):
    block_index: int
    timestamp_utc: str
    event_type: str
    summary: str
    payload_sha256: str
    prev_hash: str
    merkle_root: str
    block_hash: str
    signature_alg: str
    signature_hex: str
    signer_pubkey_hex: str
    anchor_status: str
    chain_name: Optional[str] = None
    tx_hash: Optional[str] = None
    contract_address: Optional[str] = None


class LedgerSummaryOut(BaseModel):
    integrity_valid: bool
    total_blocks: int
    anchored_blocks: int
    merkle_root: str
    signature_alg: str
    node_pubkey_short: str
    node_pubkey: str
    web3_configured: bool
    web3_chain_name: str
    contract_address: str
    plain_summary: str
    recent_blocks: List[AttestationBlockOut]


class LedgerSealRequest(BaseModel):
    note: str = Field(default="Manual forensic posture seal", max_length=180)


class MalwareFindingOut(BaseModel):
    id: str
    severity: str
    engine: str
    category: str
    name: str
    target: str
    plain_explanation: str
    what_to_do: str
    sha256: Optional[str] = None


class MalwareSummaryOut(BaseModel):
    last_scan_at: Optional[datetime] = None
    engines_available: List[str]
    files_scanned: int
    processes_scanned: int
    threats_found: int
    findings: List[MalwareFindingOut]


class MalwareScanRequest(BaseModel):
    target_path: Optional[str] = None
    scan_processes: bool = True
    check_malwarebazaar_hashes: bool = False


class FirewallPortOut(BaseModel):
    port: int
    protocol: str
    process_name: str
    bind_address: str
    risk_level: str
    plain_note: str


class FirewallStatusOut(BaseModel):
    backend: str
    enabled: bool
    profiles: Dict[str, str]
    can_enforce: bool
    lockdown_active: bool
    blocked_ips: List[str]
    listening_ports: List[FirewallPortOut]
    plain_summary: str
    privilege_note: Optional[str] = None


class FirewallBlockRequest(BaseModel):
    ip: str
    reason: str = "Blocked by user via GARUDA"


class FirewallLockdownRequest(BaseModel):
    enable: bool


class AdviceItemOut(BaseModel):
    id: str
    priority: str
    title: str
    why_it_matters: str
    simple_step: str
    safe_for: str


class ActivitySafetyOut(BaseModel):
    activity: str
    status: str
    note: str


class SecurityAdvisorOut(BaseModel):
    safety_score: int
    safety_label: str
    headline: str
    recommendations: List[AdviceItemOut]
    activity_guide: List[ActivitySafetyOut]
    passive_honesty_note: str


class AlertSettingsIn(BaseModel):
    sound_enabled: Optional[bool] = None
    desktop_notifications: Optional[bool] = None
    alert_on_new_device: Optional[bool] = None
    alert_on_passive_risk: Optional[bool] = None
    auto_block_active_attackers: Optional[bool] = None
    webhook_url: Optional[str] = None
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None
    simulation_mode: Optional[bool] = None
    scan_interval_sec: Optional[int] = Field(default=None, ge=5, le=120)


class AlertSettingsOut(BaseModel):
    sound_enabled: bool
    desktop_notifications: bool
    alert_on_new_device: bool
    alert_on_passive_risk: bool
    auto_block_active_attackers: bool
    webhook_url: Optional[str] = None
    telegram_configured: bool
    simulation_mode: bool
    scan_interval_sec: int


class DashboardSnapshotOut(BaseModel):
    mode: str
    last_scan_at: datetime
    capabilities: CapabilitiesOut
    network: NetworkInfoOut
    counts: Dict[str, int]
    devices: List[DeviceOut]
    alerts: List[AlertOut]
    ids_stats: IDSStatsOut
    ml: MLSummaryOut
    ledger: LedgerSummaryOut
    malware: MalwareSummaryOut
    firewall: FirewallStatusOut
    advisor: SecurityAdvisorOut
    settings: AlertSettingsOut


class SimulateScenarioIn(BaseModel):
    scenario: str


class FleetReportIn(BaseModel):
    agent_id: str
    agent_name: str
    agent_os: str
    ssid: str
    gateway_ip: Optional[str] = None
    gateway_mac: Optional[str] = None
    subnet_cidr: Optional[str] = None
    device_count: int = 0
    devices: List[dict] = []
    alerts_count: int = 0
    alerts: List[dict] = []
    security_score: int = 100

