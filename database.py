"""
GARUDA Database Layer
SQLite schema + helper functions for all persistence
"""

import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), 'garuda.db')


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # faster concurrent writes
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Create all tables if they don't exist"""
    conn = get_conn()
    c = conn.cursor()

    # ── SCANS ─────────────────────────────────────────────
    # One row per scan run
    c.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT NOT NULL,
        duration    REAL,
        ssid        TEXT,
        bssid       TEXT,
        encryption  TEXT,
        signal      TEXT,
        gateway_ip  TEXT,
        local_ip    TEXT,
        device_count INTEGER DEFAULT 0,
        active_count INTEGER DEFAULT 0,
        unknown_count INTEGER DEFAULT 0,
        risk_score  REAL DEFAULT 0,
        risk_label  TEXT,
        threat_level TEXT
    )""")

    # ── DEVICES ───────────────────────────────────────────
    # Every device seen in every scan
    c.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id         INTEGER NOT NULL,
        timestamp       TEXT NOT NULL,
        ip              TEXT,
        mac             TEXT,
        vendor          TEXT,
        hostname        TEXT,
        status          TEXT,
        detection_method TEXT,
        open_ports      TEXT,   -- JSON array
        device_type     TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )""")

    # ── KNOWN DEVICES ─────────────────────────────────────
    # One row per unique MAC — tracks first/last seen
    c.execute("""
    CREATE TABLE IF NOT EXISTS known_devices (
        mac             TEXT PRIMARY KEY,
        vendor          TEXT,
        hostname        TEXT,
        first_seen      TEXT NOT NULL,
        last_seen       TEXT NOT NULL,
        last_ip         TEXT,
        times_seen      INTEGER DEFAULT 1,
        is_trusted      INTEGER DEFAULT 0,   -- 0=unknown, 1=trusted, 2=blocked
        label           TEXT                 -- user-given label e.g. "Dad's Phone"
    )""")

    # ── ALERTS ────────────────────────────────────────────
    c.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT NOT NULL,
        type        TEXT NOT NULL,   -- NEW_DEVICE, ARP_SPOOF, PORT_CHANGE, MITM_RISK
        severity    TEXT NOT NULL,   -- CRITICAL, HIGH, MEDIUM, LOW, INFO
        title       TEXT NOT NULL,
        description TEXT,
        ip          TEXT,
        mac         TEXT,
        extra       TEXT,            -- JSON for any extra data
        acknowledged INTEGER DEFAULT 0
    )""")

    # ── TRAFFIC HISTORY ───────────────────────────────────
    c.execute("""
    CREATE TABLE IF NOT EXISTS traffic (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp       TEXT NOT NULL,
        bytes_sent      INTEGER DEFAULT 0,
        bytes_recv      INTEGER DEFAULT 0,
        packets_sent    INTEGER DEFAULT 0,
        packets_recv    INTEGER DEFAULT 0,
        errin           INTEGER DEFAULT 0,
        errout          INTEGER DEFAULT 0,
        dropin          INTEGER DEFAULT 0,
        dropout         INTEGER DEFAULT 0
    )""")

    # ── ARP SNAPSHOTS ─────────────────────────────────────
    # For detecting ARP spoofing — track IP→MAC mappings
    c.execute("""
    CREATE TABLE IF NOT EXISTS arp_snapshots (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT NOT NULL,
        ip          TEXT NOT NULL,
        mac         TEXT NOT NULL
    )""")

    # ── PORT HISTORY ──────────────────────────────────────
    # Track open ports per device over time
    c.execute("""
    CREATE TABLE IF NOT EXISTS port_history (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT NOT NULL,
        ip          TEXT NOT NULL,
        mac         TEXT,
        ports       TEXT NOT NULL   -- JSON array
    )""")

    conn.commit()
    conn.close()
    print(f"[DB] Initialized at {DB_PATH}")


# ─────────────────────────────────────────────
#  WRITE HELPERS
# ─────────────────────────────────────────────

def save_scan(scan_result: dict) -> int:
    """Save a full scan result. Returns scan_id."""
    conn = get_conn()
    c = conn.cursor()
    now = datetime.now().isoformat()

    net = scan_result.get('connected_network', {})
    pred = scan_result.get('attack_prediction', {})
    summary = scan_result.get('security_summary', {})
    devices = scan_result.get('connected_devices', [])

    # Insert scan row
    c.execute("""
    INSERT INTO scans (timestamp, duration, ssid, bssid, encryption, signal,
        gateway_ip, local_ip, device_count, active_count, unknown_count,
        risk_score, risk_label, threat_level)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        now,
        float(scan_result.get('scan_duration', '0').replace('s', '') or 0),
        net.get('ssid'), net.get('bssid'), net.get('encryption'), net.get('signal'),
        scan_result.get('gateway'), scan_result.get('local_ip'),
        summary.get('total_devices', len(devices)),
        summary.get('active_devices', 0),
        summary.get('unknown_vendors', 0),
        pred.get('risk_score', 0),
        pred.get('risk_label', 'UNKNOWN'),
        summary.get('threat_level', 'UNKNOWN')
    ))
    scan_id = c.lastrowid

    # Insert devices
    port_data = scan_result.get('port_scan', {})
    for d in devices:
        ip = d.get('ip', '')
        ports = port_data.get(ip, [])
        c.execute("""
        INSERT INTO devices (scan_id, timestamp, ip, mac, vendor, hostname,
            status, detection_method, open_ports, device_type)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (
            scan_id, now, ip, d.get('mac'), d.get('vendor'),
            d.get('hostname'), d.get('status'), d.get('detection_method'),
            json.dumps(ports), d.get('type', 'NODE')
        ))

        # Update known_devices
        mac = d.get('mac', '')
        if mac and mac not in ('Unknown', '<INCOMPLETE>'):
            c.execute("""
            INSERT INTO known_devices (mac, vendor, hostname, first_seen, last_seen, last_ip, times_seen)
            VALUES (?,?,?,?,?,?,1)
            ON CONFLICT(mac) DO UPDATE SET
                last_seen=excluded.last_seen,
                last_ip=excluded.last_ip,
                times_seen=times_seen+1,
                vendor=COALESCE(excluded.vendor, vendor),
                hostname=COALESCE(excluded.hostname, hostname)
            """, (mac, d.get('vendor'), d.get('hostname'), now, now, ip))

    # Save traffic snapshot
    t = scan_result.get('network_traffic', {})
    if t and 'bytes_sent_raw' in t:
        c.execute("""
        INSERT INTO traffic (timestamp, bytes_sent, bytes_recv, packets_sent,
            packets_recv, errin, errout, dropin, dropout)
        VALUES (?,?,?,?,?,?,?,?,?)
        """, (
            now,
            t.get('bytes_sent_raw', 0), t.get('bytes_recv_raw', 0),
            t.get('packets_sent_raw', 0), t.get('packets_recv_raw', 0),
            t.get('errin', 0), t.get('errout', 0),
            t.get('dropin', 0), t.get('dropout', 0)
        ))

    # Save ARP snapshot
    for d in devices:
        ip = d.get('ip', '')
        mac = d.get('mac', '')
        if ip and mac and mac != 'Unknown':
            c.execute(
                "INSERT INTO arp_snapshots (timestamp, ip, mac) VALUES (?,?,?)",
                (now, ip, mac)
            )

    # Save port history
    for ip, ports in port_data.items():
        mac = next((d.get('mac') for d in devices if d.get('ip') == ip), None)
        c.execute(
            "INSERT INTO port_history (timestamp, ip, mac, ports) VALUES (?,?,?,?)",
            (now, ip, mac, json.dumps(ports))
        )

    conn.commit()
    conn.close()
    return scan_id


def save_alert(type_: str, severity: str, title: str, description: str = None,
               ip: str = None, mac: str = None, extra: dict = None):
    """Save an alert to the database."""
    conn = get_conn()
    conn.execute("""
    INSERT INTO alerts (timestamp, type, severity, title, description, ip, mac, extra)
    VALUES (?,?,?,?,?,?,?,?)
    """, (
        datetime.now().isoformat(), type_, severity, title,
        description, ip, mac, json.dumps(extra or {})
    ))
    conn.commit()
    conn.close()


# ─────────────────────────────────────────────
#  READ HELPERS
# ─────────────────────────────────────────────

def get_scan_history(limit=50):
    conn = get_conn()
    rows = conn.execute("""
        SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_recent_alerts(limit=50, unacked_only=False):
    conn = get_conn()
    q = "SELECT * FROM alerts"
    if unacked_only:
        q += " WHERE acknowledged=0"
    q += " ORDER BY timestamp DESC LIMIT ?"
    rows = conn.execute(q, (limit,)).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if d.get('extra'):
            try:
                d['extra'] = json.loads(d['extra'])
            except:
                pass
        result.append(d)
    return result


def get_known_devices(trusted_only=False):
    conn = get_conn()
    q = "SELECT * FROM known_devices"
    if trusted_only:
        q += " WHERE is_trusted=1"
    q += " ORDER BY last_seen DESC"
    rows = conn.execute(q).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_traffic_history(hours=24):
    conn = get_conn()
    rows = conn.execute("""
        SELECT * FROM traffic
        WHERE timestamp >= datetime('now', ?)
        ORDER BY timestamp ASC
    """, (f'-{hours} hours',)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_device_timeline(mac: str):
    """Full history for a specific device by MAC."""
    conn = get_conn()
    rows = conn.execute("""
        SELECT d.timestamp, d.ip, d.status, d.open_ports, d.detection_method
        FROM devices d
        WHERE d.mac = ?
        ORDER BY d.timestamp DESC
        LIMIT 100
    """, (mac,)).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if d.get('open_ports'):
            try:
                d['open_ports'] = json.loads(d['open_ports'])
            except:
                pass
        result.append(d)
    return result


def get_arp_history(ip: str, hours: int = 24):
    """Get MAC history for an IP — detect if it changed (ARP spoofing)."""
    conn = get_conn()
    rows = conn.execute("""
        SELECT timestamp, ip, mac FROM arp_snapshots
        WHERE ip = ? AND timestamp >= datetime('now', ?)
        ORDER BY timestamp DESC
    """, (ip, f'-{hours} hours')).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_dashboard_summary():
    """Single call to get everything needed for dashboard."""
    conn = get_conn()

    # Latest scan
    latest = conn.execute(
        "SELECT * FROM scans ORDER BY timestamp DESC LIMIT 1"
    ).fetchone()

    # Scan count last 24h
    scan_count_24h = conn.execute("""
        SELECT COUNT(*) as cnt FROM scans
        WHERE timestamp >= datetime('now', '-24 hours')
    """).fetchone()['cnt']

    # Total unique devices ever seen
    total_known = conn.execute(
        "SELECT COUNT(*) as cnt FROM known_devices"
    ).fetchone()['cnt']

    # Unacknowledged alerts
    unacked = conn.execute(
        "SELECT COUNT(*) as cnt FROM alerts WHERE acknowledged=0"
    ).fetchone()['cnt']

    # Risk trend (last 10 scans)
    risk_trend = conn.execute("""
        SELECT timestamp, risk_score, risk_label, device_count, threat_level
        FROM scans ORDER BY timestamp DESC LIMIT 10
    """).fetchall()

    # Recent alerts
    recent_alerts = conn.execute("""
        SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10
    """).fetchall()

    conn.close()

    return {
        'latest_scan': dict(latest) if latest else None,
        'scans_last_24h': scan_count_24h,
        'total_known_devices': total_known,
        'unacked_alerts': unacked,
        'risk_trend': [dict(r) for r in risk_trend],
        'recent_alerts': [dict(r) for r in recent_alerts],
    }


def acknowledge_alert(alert_id: int):
    conn = get_conn()
    conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()


def get_port_changes():
    """Detect devices whose open ports changed between last two scans."""
    conn = get_conn()
    rows = conn.execute("""
        SELECT ip, ports, timestamp FROM port_history
        WHERE timestamp >= datetime('now', '-2 hours')
        ORDER BY ip, timestamp DESC
    """).fetchall()
    conn.close()

    # Group by IP, compare latest vs previous
    by_ip = {}
    for r in rows:
        ip = r['ip']
        if ip not in by_ip:
            by_ip[ip] = []
        by_ip[ip].append({'timestamp': r['timestamp'], 'ports': json.loads(r['ports'] or '[]')})

    changes = []
    for ip, history in by_ip.items():
        if len(history) >= 2:
            current = set(history[0]['ports'])
            previous = set(history[1]['ports'])
            new_ports = current - previous
            closed_ports = previous - current
            if new_ports or closed_ports:
                changes.append({
                    'ip': ip,
                    'new_ports': list(new_ports),
                    'closed_ports': list(closed_ports),
                    'timestamp': history[0]['timestamp']
                })
    return changes


if __name__ == '__main__':
    init_db()
    print("[DB] Schema created successfully")
    print(f"[DB] Location: {DB_PATH}")