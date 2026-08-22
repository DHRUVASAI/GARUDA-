"""
device_aliases.py — Manual device labeling for GARUDA-X

Lets a user assign a persistent, human-chosen name to any device the
active-discovery stack (gethostbyaddr / NetBIOS / mDNS / LLMNR) can't
resolve on its own — e.g. phones/laptops with MAC randomization and
mDNS/NetBIOS disabled, which are *by design* silent on the network.

Keying strategy:
    - Prefer MAC address as the key. Most 'private Wi-Fi address'
      implementations (iOS 14+, Android 10+) keep ONE random MAC per SSID
      for as long as you stay joined to that network, so a MAC-keyed alias
      is stable across IP changes from DHCP lease renewal.
    - Fall back to IP as the key only when no usable MAC is available
      (vendor == 'Private MAC Device' with no OUI, or MAC otherwise
      unknown/incomplete). IP-keyed aliases are inherently less stable
      (they'll go stale if DHCP reassigns the address) but are strictly
      better than nothing for those cases.

Same pattern as the attestation ledger in garuda_backend.py: prefers
functions from database.py if that module has been extended with
save_device_alias/get_device_alias/list_device_aliases/delete_device_alias,
otherwise falls back to a small local SQLite table so this module has
zero hard dependency on a database.py change that hasn't happened yet.
"""

import os
import sqlite3
import threading
from datetime import datetime
from typing import Optional

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
_ALIAS_DB_PATH = os.path.join(BASE_DIR, 'garuda_device_aliases.db')
_alias_lock = threading.Lock()

_ALIAS_DB_NATIVE = False
try:
    from database import save_device_alias as _db_save_alias          # type: ignore
    from database import get_device_alias as _db_get_alias            # type: ignore
    from database import list_device_aliases as _db_list_aliases      # type: ignore
    from database import delete_device_alias as _db_delete_alias      # type: ignore
    _ALIAS_DB_NATIVE = True
except Exception:
    _ALIAS_DB_NATIVE = False


def _norm_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    m = mac.upper().replace('-', ':').strip()
    if m in ('', 'UNKNOWN', '<INCOMPLETE>'):
        return None
    return m


def _init_fallback_db():
    conn = sqlite3.connect(_ALIAS_DB_PATH)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS device_aliases (
                key_type TEXT NOT NULL,      -- 'mac' or 'ip'
                key_value TEXT NOT NULL,     -- the normalized MAC or IP
                alias TEXT NOT NULL,
                notes TEXT,
                mac TEXT,
                last_known_ip TEXT,
                created_at TEXT,
                updated_at TEXT,
                PRIMARY KEY (key_type, key_value)
            )
        """)
        conn.commit()
    finally:
        conn.close()


if not _ALIAS_DB_NATIVE:
    try:
        _init_fallback_db()
    except Exception:
        pass


def _resolve_key(mac: Optional[str], ip: Optional[str]):
    """Returns (key_type, key_value) — MAC preferred, IP as fallback."""
    nm = _norm_mac(mac)
    if nm:
        return 'mac', nm
    if ip:
        return 'ip', ip
    return None, None


def save_alias(mac: Optional[str], ip: Optional[str], alias: str, notes: Optional[str] = None) -> dict:
    """Creates or updates an alias. Requires alias text and at least one of
    mac/ip. Raises ValueError if neither key is usable or alias is blank."""
    alias = (alias or '').strip()
    if not alias:
        raise ValueError("alias must not be empty")
    key_type, key_value = _resolve_key(mac, ip)
    if not key_type:
        raise ValueError("at least one of mac or ip is required")

    now = datetime.now().isoformat()
    record = {
        "key_type": key_type,
        "key_value": key_value,
        "alias": alias,
        "notes": notes,
        "mac": _norm_mac(mac),
        "last_known_ip": ip,
        "updated_at": now,
    }

    if _ALIAS_DB_NATIVE:
        return _db_save_alias(record)

    with _alias_lock:
        conn = sqlite3.connect(_ALIAS_DB_PATH)
        try:
            existing = conn.execute(
                "SELECT created_at FROM device_aliases WHERE key_type=? AND key_value=?",
                (key_type, key_value),
            ).fetchone()
            created_at = existing[0] if existing else now
            conn.execute(
                """INSERT INTO device_aliases
                   (key_type, key_value, alias, notes, mac, last_known_ip, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?)
                   ON CONFLICT(key_type, key_value) DO UPDATE SET
                     alias=excluded.alias,
                     notes=excluded.notes,
                     mac=excluded.mac,
                     last_known_ip=excluded.last_known_ip,
                     updated_at=excluded.updated_at""",
                (key_type, key_value, alias, notes, record["mac"], ip, created_at, now),
            )
            conn.commit()
        finally:
            conn.close()
    record["created_at"] = record.get("created_at", now)
    return record


def get_alias(mac: Optional[str] = None, ip: Optional[str] = None) -> Optional[dict]:
    """Looks up an alias, checking MAC first (if provided) then IP."""
    if _ALIAS_DB_NATIVE:
        return _db_get_alias(mac=mac, ip=ip)

    conn = sqlite3.connect(_ALIAS_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        nm = _norm_mac(mac)
        if nm:
            row = conn.execute(
                "SELECT * FROM device_aliases WHERE key_type='mac' AND key_value=?", (nm,)
            ).fetchone()
            if row:
                return dict(row)
        if ip:
            row = conn.execute(
                "SELECT * FROM device_aliases WHERE key_type='ip' AND key_value=?", (ip,)
            ).fetchone()
            if row:
                return dict(row)
        return None
    finally:
        conn.close()


def list_aliases(limit: int = 500) -> list:
    if _ALIAS_DB_NATIVE:
        return _db_list_aliases(limit)
    conn = sqlite3.connect(_ALIAS_DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM device_aliases ORDER BY updated_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def delete_alias(mac: Optional[str] = None, ip: Optional[str] = None) -> bool:
    if _ALIAS_DB_NATIVE:
        return _db_delete_alias(mac=mac, ip=ip)
    key_type, key_value = _resolve_key(mac, ip)
    if not key_type:
        return False
    with _alias_lock:
        conn = sqlite3.connect(_ALIAS_DB_PATH)
        try:
            cur = conn.execute(
                "DELETE FROM device_aliases WHERE key_type=? AND key_value=?",
                (key_type, key_value),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def apply_alias_to_device(device: dict) -> dict:
    """Given one device dict from get_connected_devices()/scan output,
    overlays a saved alias onto display_name if one exists. Non-destructive:
    keeps the original hostname/vendor-derived name in 'auto_display_name'
    so the UI can show both ('Dhruv's Phone' / was 'Device 10.10.51.42')."""
    match = get_alias(mac=device.get('mac'), ip=device.get('ip'))
    if match:
        device['auto_display_name'] = device.get('display_name')
        device['display_name'] = match['alias']
        device['is_user_labeled'] = True
        device['alias_notes'] = match.get('notes')
        device['alias_key_type'] = match.get('key_type')  # 'mac' (stable) or 'ip' (may go stale)
    else:
        device['is_user_labeled'] = False
    return device
