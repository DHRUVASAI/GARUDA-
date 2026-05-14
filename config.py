"""
GARUDA configuration — environment variables override defaults.
Copy to .env and load with a shell, or export GARUDA_* variables.
"""

import os
from pathlib import Path

_BASE_DIR = Path(__file__).resolve().parent

try:
    from dotenv import load_dotenv
    load_dotenv(_BASE_DIR / ".env", override=False)
except ImportError:
    pass


def _env(key: str, default, cast=str):
    raw = os.environ.get(key)
    if raw is None or raw == "":
        return default
    if cast is int:
        return int(raw)
    if cast is float:
        return float(raw)
    if cast is bool:
        return str(raw).lower() in ("1", "true", "yes", "on")
    return str(raw)


# Flask / Gunicorn
HOST = _env("GARUDA_HOST", "0.0.0.0")
PORT = _env("GARUDA_PORT", 5000, int)
FLASK_DEBUG = _env("GARUDA_DEBUG", False, bool)
FLASK_THREADED = _env("GARUDA_THREADED", True, bool)

# Logging
LOG_LEVEL = _env("GARUDA_LOG_LEVEL", "INFO")

# Database
DB_PATH = _env("GARUDA_DB_PATH", str(_BASE_DIR / "garuda.db"))
SCAN_HISTORY_RETENTION_DAYS = _env("GARUDA_SCAN_RETENTION_DAYS", 30, int)
ALERT_DEDUPE_COOLDOWN_SECONDS = _env("GARUDA_ALERT_COOLDOWN_SEC", 300, int)

# ARP false-positive controls
DHCP_VOLATILE_RANGE = _env("GARUDA_DHCP_VOLATILE_RANGE", "")  # e.g. 192.168.1.100-200
ARP_OLD_MAC_MIN_SECONDS = _env("GARUDA_ARP_OLD_MAC_MIN_SEC", 300, int)
ARP_NEW_MAC_MIN_SIGHTINGS = _env("GARUDA_ARP_NEW_MAC_MIN_SIGHTINGS", 2, int)

# Port scan
PORT_CRITICAL = {22, 80, 443, 3389, 445}
PORT_TIMEOUT_FAST_MS = _env("GARUDA_PORT_TIMEOUT_FAST_MS", 400, int)
PORT_TIMEOUT_MED_MS = _env("GARUDA_PORT_TIMEOUT_MED_MS", 700, int)
PORT_TIMEOUT_SLOW_MS = _env("GARUDA_PORT_TIMEOUT_SLOW_MS", 1200, int)
PORT_CRITICAL_FLOOR_MS = _env("GARUDA_PORT_CRITICAL_FLOOR_MS", 1000, int)

# Background monitor (monitor.py)
MONITOR_SCAN_INTERVAL_SEC = _env("GARUDA_MONITOR_SCAN_INTERVAL", 300, int)
MONITOR_ARP_INTERVAL_SEC = _env("GARUDA_MONITOR_ARP_INTERVAL", 30, int)

# API rate limits (Flask-Limiter)
SCAN_FULL_RATE = _env("GARUDA_RATE_SCAN_FULL", "8 per minute")
SCAN_CONNECTED_RATE = _env("GARUDA_RATE_SCAN_CONNECTED", "30 per minute")

# UI Settings
UI_POLL_INTERVAL_SEC = _env("GARUDA_POLL_INTERVAL", 5, int)

# Content-Security-Policy (adjust if you host external assets)
CONTENT_SECURITY_POLICY = _env(
    "GARUDA_CSP",
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; "
    "connect-src 'self' http://localhost:5000 http://127.0.0.1:5000 ws://localhost:5000 ws://127.0.0.1:5000; base-uri 'self'; frame-ancestors 'none';",
)
