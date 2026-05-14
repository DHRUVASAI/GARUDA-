"""
GARUDA Database Layer
SQLite schema + helper functions for all persistence
"""

from __future__ import annotations

import sqlite3
import json
import logging
from datetime import datetime
from typing import Optional, Tuple

from config import DB_PATH, SCAN_HISTORY_RETENTION_DAYS, ALERT_DEDUPE_COOLDOWN_SECONDS

logger = logging.getLogger(__name__)


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _table_columns(conn, table: str) -> set:
    cur = conn.execute(f"PRAGMA table_info({table})")
    return {row[1] for row in cur.fetchall()}


def _ensure_column(conn, table: str, coldef: str):
    """Forward-compatible migrations: add column if missing."""
    name = coldef.strip().split()[0]
    if name not in _table_columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {coldef}")
        logger.info("[DB] Migration: added column %s.%s", table, name)


def _create_indexes(conn):
    stmts = [
        "CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip)",
        "CREATE INDEX IF NOT EXISTS idx_devices_timestamp ON devices(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_devices_scan_id ON devices(scan_id)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(type)",
        "CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip)",
        "CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_arp_snapshots_ip ON arp_snapshots(ip)",
        "CREATE INDEX IF NOT EXISTS idx_arp_snapshots_ts ON arp_snapshots(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_port_history_ip ON port_history(ip)",
        "CREATE INDEX IF NOT EXISTS idx_port_history_ts ON port_history(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic(timestamp)",
    ]
    for sql in stmts:
        conn.execute(sql)


def init_db():
    """Create all tables if they don't exist, migrate schema, add indexes."""
    conn = get_conn()
    c = conn.cursor()

    c.execute(
        """
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
    )"""
    )

    c.execute(
        """
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
        open_ports      TEXT,
        device_type     TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )"""
    )

    c.execute(
        """
    CREATE TABLE IF NOT EXISTS known_devices (
        mac             TEXT PRIMARY KEY,
        vendor          TEXT,
        hostname        TEXT,
        first_seen      TEXT NOT NULL,
        last_seen       TEXT NOT NULL,
        last_ip         TEXT,
        times_seen      INTEGER DEFAULT 1,
        is_trusted      INTEGER DEFAULT 0,
        label           TEXT
    )"""
    )

    c.execute(
        """
    CREATE TABLE IF NOT EXISTS alerts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT NOT NULL,
        type        TEXT NOT NULL,
        severity    TEXT NOT NULL,
        title       TEXT NOT NULL,
        description TEXT,
        ip          TEXT,
        mac         TEXT,
        extra       TEXT,
        acknowledged INTEGER DEFAULT 0
    )"""
    )

    c.execute(
        """
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
    )"""
    )

    c.execute(
        """
    CREATE TABLE IF NOT EXISTS arp_snapshots (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT NOT NULL,
        ip          TEXT NOT NULL,
        mac         TEXT NOT NULL
    )"""
    )

    c.execute(
        """
    CREATE TABLE IF NOT EXISTS port_history (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp   TEXT NOT NULL,
        ip          TEXT NOT NULL,
        mac         TEXT,
        ports       TEXT NOT NULL
    )"""
    )

    conn.commit()

    _ensure_column(conn, "alerts", "confidence REAL")
    for col in (
        "ping_rtt_ms REAL",
        "icmp_ttl INTEGER",
        "os_guess TEXT",
        "persistent_threat INTEGER",
    ):
        _ensure_column(conn, "devices", col)
    _create_indexes(conn)
    conn.commit()
    conn.close()

    prune_old_data(SCAN_HISTORY_RETENTION_DAYS)
    logger.info("[DB] Initialized at %s", DB_PATH)


def prune_old_data(retention_days: int):
    """Remove scan rows (and dependent devices) and old telemetry past retention."""
    if retention_days < 1:
        return
    conn = get_conn()
    try:
        cutoff = f"-{int(retention_days)} days"
        rows = conn.execute(
            "SELECT id FROM scans WHERE timestamp < datetime('now', ?)",
            (cutoff,),
        ).fetchall()
        ids = [r[0] for r in rows]
        did_delete = False
        if ids:
            q_marks = ",".join("?" * len(ids))
            conn.execute(f"DELETE FROM devices WHERE scan_id IN ({q_marks})", ids)
            conn.execute(f"DELETE FROM scans WHERE id IN ({q_marks})", ids)
            logger.info("[DB] Pruned %s old scan(s)", len(ids))
            did_delete = True
        cur = conn.execute(
            "DELETE FROM arp_snapshots WHERE timestamp < datetime('now', ?)",
            (cutoff,),
        )
        did_delete = did_delete or cur.rowcount > 0
        cur = conn.execute(
            "DELETE FROM port_history WHERE timestamp < datetime('now', ?)",
            (cutoff,),
        )
        did_delete = did_delete or cur.rowcount > 0
        cur = conn.execute(
            "DELETE FROM traffic WHERE timestamp < datetime('now', ?)",
            (cutoff,),
        )
        did_delete = did_delete or cur.rowcount > 0
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("[DB] prune_old_data failed")
        raise
    finally:
        conn.close()
    if did_delete:
        try:
            vconn = sqlite3.connect(DB_PATH)
            vconn.execute("VACUUM")
            vconn.close()
        except Exception:
            logger.warning("[DB] VACUUM after prune skipped", exc_info=True)


def _recent_duplicate_alert(conn, type_: str, ip, mac, cooldown_sec: int) -> bool:
    if cooldown_sec <= 0:
        return False
    row = conn.execute(
        """
        SELECT 1 FROM alerts
        WHERE type = ?
          AND IFNULL(ip, '') = IFNULL(?, '')
          AND IFNULL(mac, '') = IFNULL(?, '')
          AND datetime(timestamp) >= datetime('now', ?)
        LIMIT 1
        """,
        (type_, ip, mac, f"-{int(cooldown_sec)} seconds"),
    ).fetchone()
    return row is not None


def record_arp_snapshots_bulk(arp_table: dict) -> None:
    """Persist current ARP bindings for ARP-spoof frequency / time-weighting (monitor calls each tick)."""
    if not arp_table:
        return
    now = datetime.now().isoformat()
    rows = [
        (now, ip, mac)
        for ip, mac in arp_table.items()
        if mac and mac not in ("Unknown", "<INCOMPLETE>")
    ]
    if not rows:
        return
    conn = get_conn()
    try:
        conn.executemany(
            "INSERT INTO arp_snapshots (timestamp, ip, mac) VALUES (?,?,?)",
            rows,
        )
        conn.commit()
    finally:
        conn.close()


def arp_total_observations_for_ip(ip: str, hours: int = 48) -> int:
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT COUNT(*) AS c FROM arp_snapshots
            WHERE ip = ? AND timestamp >= datetime('now', ?)
            """,
            (ip, f"-{int(hours)} hours"),
        ).fetchone()
        return int(row["c"]) if row else 0
    finally:
        conn.close()


def arp_mac_sightings_count(ip: str, mac: str, hours: int = 48) -> int:
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT COUNT(*) AS c FROM arp_snapshots
            WHERE ip = ? AND mac = ? AND timestamp >= datetime('now', ?)
            """,
            (ip, mac, f"-{int(hours)} hours"),
        ).fetchone()
        return int(row["c"]) if row else 0
    finally:
        conn.close()


def arp_mac_pair_span_seconds(ip: str, mac: str, hours: int = 168) -> float:
    """Seconds between first and last ARP snapshot for this IP+MAC (0 if none)."""
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT MIN(timestamp) AS t0, MAX(timestamp) AS t1 FROM arp_snapshots
            WHERE ip = ? AND mac = ? AND timestamp >= datetime('now', ?)
            """,
            (ip, mac, f"-{int(hours)} hours"),
        ).fetchone()
        if not row or not row["t0"] or not row["t1"]:
            return 0.0
        r0 = conn.execute(
            "SELECT julianday(?) - julianday(?) AS d", (row["t1"], row["t0"])
        ).fetchone()
        days = float(r0["d"]) if r0 and r0["d"] is not None else 0.0
        return max(0.0, days * 86400.0)
    finally:
        conn.close()


def count_alerts_for_ip_hours(ip: str, hours: int = 1) -> int:
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT COUNT(*) AS c FROM alerts
            WHERE ip = ? AND datetime(timestamp) >= datetime('now', ?)
            """,
            (ip, f"-{int(hours)} hours"),
        ).fetchone()
        return int(row["c"]) if row else 0
    finally:
        conn.close()


def save_scan(scan_result: dict) -> int:
    """Save a full scan result. Returns scan_id."""
    conn = get_conn()
    try:
        c = conn.cursor()
        now = datetime.now().isoformat()

        net = scan_result.get("connected_network", {})
        pred = scan_result.get("attack_prediction", {})
        summary = scan_result.get("security_summary", {})
        devices = scan_result.get("connected_devices", [])

        dur_raw = scan_result.get("scan_duration", "0")
        try:
            duration = float(str(dur_raw).replace("s", "") or 0)
        except ValueError:
            duration = 0.0

        c.execute(
            """
        INSERT INTO scans (timestamp, duration, ssid, bssid, encryption, signal,
            gateway_ip, local_ip, device_count, active_count, unknown_count,
            risk_score, risk_label, threat_level)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
            (
                now,
                duration,
                net.get("ssid"),
                net.get("bssid"),
                net.get("encryption"),
                net.get("signal"),
                scan_result.get("gateway"),
                scan_result.get("local_ip"),
                summary.get("total_devices", len(devices)),
                summary.get("active_devices", 0),
                summary.get("unknown_vendors", 0),
                pred.get("risk_score", 0),
                pred.get("risk_label", "UNKNOWN"),
                summary.get("threat_level", "UNKNOWN"),
            ),
        )
        scan_id = c.lastrowid

        port_data = scan_result.get("port_scan", {})
        for d in devices:
            ip = d.get("ip", "")
            ports = port_data.get(ip, [])
            persist = 1 if count_alerts_for_ip_hours(ip, 1) >= 3 else 0
            c.execute(
                """
            INSERT INTO devices (scan_id, timestamp, ip, mac, vendor, hostname,
                status, detection_method, open_ports, device_type,
                ping_rtt_ms, icmp_ttl, os_guess, persistent_threat)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
                (
                    scan_id,
                    now,
                    ip,
                    d.get("mac"),
                    d.get("vendor"),
                    d.get("hostname"),
                    d.get("status"),
                    d.get("detection_method"),
                    json.dumps(ports),
                    d.get("type", "NODE"),
                    d.get("ping_rtt_ms"),
                    d.get("icmp_ttl"),
                    d.get("os_guess"),
                    persist,
                ),
            )

            mac = d.get("mac", "")
            if mac and mac not in ("Unknown", "<INCOMPLETE>"):
                c.execute(
                    """
                INSERT INTO known_devices (mac, vendor, hostname, first_seen, last_seen, last_ip, times_seen)
                VALUES (?,?,?,?,?,?,1)
                ON CONFLICT(mac) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    last_ip=excluded.last_ip,
                    times_seen=times_seen+1,
                    vendor=COALESCE(excluded.vendor, vendor),
                    hostname=COALESCE(excluded.hostname, hostname)
                """,
                    (mac, d.get("vendor"), d.get("hostname"), now, now, ip),
                )

        t = scan_result.get("network_traffic", {})
        if t and "bytes_sent_raw" in t:
            c.execute(
                """
            INSERT INTO traffic (timestamp, bytes_sent, bytes_recv, packets_sent,
                packets_recv, errin, errout, dropin, dropout)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
                (
                    now,
                    t.get("bytes_sent_raw", 0),
                    t.get("bytes_recv_raw", 0),
                    t.get("packets_sent_raw", 0),
                    t.get("packets_recv_raw", 0),
                    t.get("errin", 0),
                    t.get("errout", 0),
                    t.get("dropin", 0),
                    t.get("dropout", 0),
                ),
            )

        for d in devices:
            ip = d.get("ip", "")
            mac = d.get("mac", "")
            if ip and mac and mac != "Unknown":
                c.execute(
                    "INSERT INTO arp_snapshots (timestamp, ip, mac) VALUES (?,?,?)",
                    (now, ip, mac),
                )

        for ip, ports in port_data.items():
            mac = next((d.get("mac") for d in devices if d.get("ip") == ip), None)
            c.execute(
                "INSERT INTO port_history (timestamp, ip, mac, ports) VALUES (?,?,?,?)",
                (now, ip, mac, json.dumps(ports)),
            )

        conn.commit()
        return scan_id
    except Exception:
        conn.rollback()
        logger.exception("[DB] save_scan failed; rolled back")
        raise
    finally:
        conn.close()


def save_alert(
    type_: str,
    severity: str,
    title: str,
    description: str = None,
    ip: str = None,
    mac: str = None,
    extra: dict = None,
    confidence: float = None,
    cooldown_seconds: int = None,
) -> Optional[int]:
    """
    Save an alert. Returns row id, or None if suppressed as a duplicate within cooldown.
    """
    cool = cooldown_seconds if cooldown_seconds is not None else ALERT_DEDUPE_COOLDOWN_SECONDS
    conn = get_conn()
    rid = None
    try:
        if _recent_duplicate_alert(conn, type_, ip, mac, cool):
            return None
        has_conf = "confidence" in _table_columns(conn, "alerts")
        if has_conf:
            conn.execute(
                """
            INSERT INTO alerts (timestamp, type, severity, title, description, ip, mac, extra, confidence)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
                (
                    datetime.now().isoformat(),
                    type_,
                    severity,
                    title,
                    description,
                    ip,
                    mac,
                    json.dumps(extra or {}),
                    confidence,
                ),
            )
        else:
            conn.execute(
                """
            INSERT INTO alerts (timestamp, type, severity, title, description, ip, mac, extra)
            VALUES (?,?,?,?,?,?,?,?)
            """,
                (
                    datetime.now().isoformat(),
                    type_,
                    severity,
                    title,
                    description,
                    ip,
                    mac,
                    json.dumps(extra or {}),
                ),
            )
        conn.commit()
        rid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    except Exception:
        conn.rollback()
        logger.exception("[DB] save_alert failed; rolled back")
        raise
    finally:
        conn.close()
    if rid:
        try:
            from alert_bus import broadcast_alert

            broadcast_alert(
                {
                    "type": "alert",
                    "id": rid,
                    "alert_type": type_,
                    "severity": severity,
                    "title": title,
                    "ip": ip,
                    "mac": mac,
                    "confidence": confidence,
                    "timestamp": datetime.now().isoformat(),
                }
            )
        except Exception:
            logger.debug("alert SSE broadcast skipped", exc_info=True)
    return rid


def get_dominant_mac_for_ip(ip: str, hours: int = 168) -> Tuple[Optional[str], int]:
    """
    Return (mac, sample_count) for the most frequently observed MAC for this IP
    in arp_snapshots within the window.
    """
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT mac, COUNT(*) AS c FROM arp_snapshots
            WHERE ip = ? AND timestamp >= datetime('now', ?)
            GROUP BY mac
            ORDER BY c DESC
            LIMIT 1
            """,
            (ip, f"-{int(hours)} hours"),
        ).fetchone()
        if not row:
            return None, 0
        return row[0], int(row[1])
    finally:
        conn.close()


def get_known_mac_for_ip(ip: str) -> Optional[str]:
    """Most recently seen MAC in known_devices where last_ip matches."""
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT mac FROM known_devices
            WHERE last_ip = ?
            ORDER BY last_seen DESC
            LIMIT 1
            """,
            (ip,),
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def get_scan_history(limit=50):
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?
    """,
        (limit,),
    ).fetchall()
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
        if d.get("extra"):
            try:
                d["extra"] = json.loads(d["extra"])
            except json.JSONDecodeError:
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
    rows = conn.execute(
        """
        SELECT * FROM traffic
        WHERE timestamp >= datetime('now', ?)
        ORDER BY timestamp ASC
    """,
        (f"-{hours} hours",),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_device_timeline(mac: str):
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT d.timestamp, d.ip, d.status, d.open_ports, d.detection_method
        FROM devices d
        WHERE d.mac = ?
        ORDER BY d.timestamp DESC
        LIMIT 100
    """,
        (mac,),
    ).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        if d.get("open_ports"):
            try:
                d["open_ports"] = json.loads(d["open_ports"])
            except json.JSONDecodeError:
                pass
        result.append(d)
    return result


def get_arp_history(ip: str, hours: int = 24):
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT timestamp, ip, mac FROM arp_snapshots
        WHERE ip = ? AND timestamp >= datetime('now', ?)
        ORDER BY timestamp DESC
    """,
        (ip, f"-{hours} hours"),
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_dashboard_summary():
    conn = get_conn()

    latest = conn.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 1").fetchone()

    scan_count_24h = conn.execute(
        """
        SELECT COUNT(*) as cnt FROM scans
        WHERE timestamp >= datetime('now', '-24 hours')
    """
    ).fetchone()["cnt"]

    total_known = conn.execute("SELECT COUNT(*) as cnt FROM known_devices").fetchone()["cnt"]

    unacked = conn.execute("SELECT COUNT(*) as cnt FROM alerts WHERE acknowledged=0").fetchone()["cnt"]

    risk_trend = conn.execute(
        """
        SELECT timestamp, risk_score, risk_label, device_count, threat_level
        FROM scans ORDER BY timestamp DESC LIMIT 10
    """
    ).fetchall()

    recent_alerts = conn.execute(
        """
        SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10
    """
    ).fetchall()

    conn.close()

    return {
        "latest_scan": dict(latest) if latest else None,
        "scans_last_24h": scan_count_24h,
        "total_known_devices": total_known,
        "unacked_alerts": unacked,
        "risk_trend": [dict(r) for r in risk_trend],
        "recent_alerts": [dict(r) for r in recent_alerts],
    }


def acknowledge_alert(alert_id: int):
    conn = get_conn()
    try:
        conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
        conn.commit()
    except Exception:
        conn.rollback()
        logger.exception("[DB] acknowledge_alert failed")
        raise
    finally:
        conn.close()


def get_port_changes():
    conn = get_conn()
    rows = conn.execute(
        """
        SELECT ip, ports, timestamp FROM port_history
        WHERE timestamp >= datetime('now', '-2 hours')
        ORDER BY ip, timestamp DESC
    """
    ).fetchall()
    conn.close()

    by_ip = {}
    for r in rows:
        ip = r["ip"]
        if ip not in by_ip:
            by_ip[ip] = []
        try:
            plist = json.loads(r["ports"] or "[]")
        except json.JSONDecodeError:
            plist = []
        by_ip[ip].append({"timestamp": r["timestamp"], "ports": plist})

    changes = []
    for ip, history in by_ip.items():
        if len(history) >= 2:
            current = set(history[0]["ports"])
            previous = set(history[1]["ports"])
            new_ports = current - previous
            closed_ports = previous - current
            if new_ports or closed_ports:
                changes.append(
                    {
                        "ip": ip,
                        "new_ports": list(new_ports),
                        "closed_ports": list(closed_ports),
                        "timestamp": history[0]["timestamp"],
                    }
                )
    return changes


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    init_db()
    logger.info("[DB] Schema ready at %s", DB_PATH)
