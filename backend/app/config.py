import ctypes
import os
import platform
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BASE_DIR / "data"
RULES_DIR = BASE_DIR / "rules"
FRONTEND_DIR = BASE_DIR / "frontend"
CONTRACTS_DIR = BASE_DIR / "contracts"

DATA_DIR.mkdir(parents=True, exist_ok=True)
RULES_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL") or os.getenv("GARUDA_DB_URL", f"sqlite:///{(DATA_DIR / 'garuda_v4.db').as_posix()}")
IEEE_OUI_CACHE_PATH = DATA_DIR / "ieee_oui_cache.json"
THREAT_FEED_CACHE_PATH = DATA_DIR / "threat_feed_cache.json"
ML_BASELINE_PATH = DATA_DIR / "ml_baseline.json"
NODE_KEY_PATH = DATA_DIR / "garuda_node_ed25519.pem"
YARA_RULES_PATH = RULES_DIR / "garuda_yara.yar"

# Optional EVM Blockchain Anchoring Configuration (100% opt-in; defaults to local Ed25519 + Merkle Ledger)
WEB3_RPC_URL = os.getenv("GARUDA_WEB3_RPC_URL", "").strip()
WEB3_CONTRACT_ADDRESS = os.getenv("GARUDA_WEB3_CONTRACT", "").strip()
WEB3_PRIVATE_KEY = os.getenv("GARUDA_WEB3_PRIVATE_KEY", "").strip()
WEB3_CHAIN_NAME = os.getenv("GARUDA_WEB3_CHAIN_NAME", "Polygon Amoy Testnet").strip()

DEFAULT_SCAN_INTERVAL = int(os.getenv("GARUDA_SCAN_INTERVAL", "15"))
DEFAULT_SIMULATION_MODE = os.getenv("GARUDA_SIMULATION_MODE", "false").lower() in ("1", "true", "yes")

TRUSTED_PUBLIC_DNS = {
    "1.1.1.1", "1.0.0.1",               # Cloudflare
    "8.8.8.8", "8.8.4.4",               # Google
    "9.9.9.9", "149.112.112.112",       # Quad9
    "208.67.222.222", "208.67.220.220", # OpenDNS
    "94.140.14.14", "94.140.15.15",     # AdGuard
}

CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP"}
CRYPTOMINER_PORTS = {3333, 4444, 5555, 7777, 14433, 14444, 45560, 45700}
LATERAL_SPREAD_PORTS = {135, 139, 445, 3389, 5900, 5985}


def is_admin_or_root() -> bool:
    """Return True if running with Administrator (Windows) or root/sudo (Linux/macOS) privileges."""
    try:
        if platform.system().lower() == "windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False

# GARUDA v7 Auth, RBAC & Production Security Settings
JWT_SECRET_KEY = os.getenv("GARUDA_JWT_SECRET", "garuda-dev-secret-change-in-production-min-32-chars")
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "720"))
REQUIRE_AUTH = os.getenv("GARUDA_REQUIRE_AUTH", "false").lower() in ("1", "true", "yes")
ALLOWED_ORIGINS = [
    o.strip() for o in os.getenv("ALLOWED_ORIGINS", "*").split(",") if o.strip()
]
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
BOOTSTRAP_ADMIN_USER = os.getenv("GARUDA_ADMIN_USER", "").strip()
BOOTSTRAP_ADMIN_EMAIL = os.getenv("GARUDA_ADMIN_EMAIL", "admin@garuda.local").strip()
BOOTSTRAP_ADMIN_PASSWORD = os.getenv("GARUDA_ADMIN_PASSWORD", "").strip()
