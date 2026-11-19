"""MAC OUI Vendor & Device-Type Lookup.
Combines an expanded built-in offline registry with optional one-click sync of the
official IEEE Standards Association OUI registry (~35,000+ prefixes) cached locally.
"""

import csv
import io
import json
from typing import Dict, Tuple
from ..config import IEEE_OUI_CACHE_PATH

BUILTIN_OUI: Dict[str, Tuple[str, str]] = {
    # Apple
    "00:03:93": ("Apple", "laptop"), "00:1C:B3": ("Apple", "phone"), "00:25:00": ("Apple", "laptop"),
    "04:0C:CE": ("Apple", "laptop"), "14:7D:DA": ("Apple", "phone"), "18:AF:61": ("Apple", "phone"),
    "24:A0:74": ("Apple", "phone"), "28:CF:E9": ("Apple", "laptop"), "34:36:3B": ("Apple", "laptop"),
    "3C:15:C2": ("Apple", "laptop"), "40:A6:D9": ("Apple", "phone"), "48:D7:05": ("Apple", "laptop"),
    "54:26:96": ("Apple", "phone"), "60:03:08": ("Apple", "laptop"), "68:5B:35": ("Apple", "laptop"),
    "70:56:81": ("Apple", "phone"), "78:31:C1": ("Apple", "laptop"), "88:66:5A": ("Apple", "phone"),
    "98:01:A7": ("Apple", "laptop"), "A4:83:E7": ("Apple", "laptop"), "AC:BC:32": ("Apple", "laptop"),
    "B8:E8:56": ("Apple", "laptop"), "C8:69:CD": ("Apple", "tv"), "D0:81:7A": ("Apple", "phone"),
    "DC:A9:04": ("Apple", "laptop"), "E0:AC:CB": ("Apple", "phone"), "F0:18:98": ("Apple", "phone"),
    "F4:5C:89": ("Apple", "laptop"), "FC:25:3F": ("Apple", "phone"),
    # Samsung
    "00:16:32": ("Samsung", "phone"), "00:26:37": ("Samsung", "phone"), "14:F4:2A": ("Samsung", "phone"),
    "18:22:7E": ("Samsung", "phone"), "24:4B:81": ("Samsung", "tv"), "34:23:BA": ("Samsung", "tv"),
    "40:0E:85": ("Samsung", "phone"), "50:01:BB": ("Samsung", "phone"), "5C:3C:27": ("Samsung", "tv"),
    "6C:2F:2C": ("Samsung", "phone"), "78:47:1D": ("Samsung", "phone"), "84:25:DB": ("Samsung", "phone"),
    "94:35:0A": ("Samsung", "phone"), "A0:82:1F": ("Samsung", "tv"), "B4:EF:39": ("Samsung", "phone"),
    "C4:57:6E": ("Samsung", "tv"), "CC:07:AB": ("Samsung", "phone"), "D0:22:BE": ("Samsung", "phone"),
    "E4:58:E7": ("Samsung", "phone"), "F4:7B:5E": ("Samsung", "tv"),
    # Google / Pixel / Nest
    "3C:5A:B4": ("Google", "iot"), "54:60:09": ("Google", "iot"), "94:EB:2C": ("Google", "phone"),
    "D8:6C:63": ("Google", "iot"), "F4:F5:D8": ("Google", "phone"), "F4:F5:E8": ("Google", "tv"),
    # Xiaomi / Redmi / Poco / OnePlus / Realme / Vivo / Oppo / Nothing / Motorola
    "0C:1D:AF": ("Xiaomi", "phone"), "14:F6:5A": ("Xiaomi", "phone"), "28:6C:07": ("Xiaomi", "phone"),
    "34:80:B3": ("Xiaomi", "phone"), "50:64:2B": ("Xiaomi", "iot"), "64:B4:73": ("Xiaomi", "phone"),
    "78:11:DC": ("Xiaomi", "iot"), "7C:1D:D9": ("Xiaomi", "phone"), "8C:BE:BE": ("Xiaomi", "phone"),
    "A0:86:C6": ("Xiaomi", "iot"), "F8:A4:5F": ("Xiaomi", "phone"),
    "94:65:2D": ("OnePlus", "phone"), "A4:50:46": ("OnePlus", "phone"), "C0:EE:FB": ("OnePlus", "phone"),
    "24:18:1D": ("Vivo", "phone"), "38:A4:ED": ("Vivo", "phone"), "B0:F1:EC": ("Oppo", "phone"),
    "DC:6D:CD": ("Realme", "phone"), "E8:6F:38": ("Realme", "phone"), "2C:BE:EB": ("Nothing", "phone"),
    "00:1E:46": ("Motorola", "phone"), "84:10:0D": ("Motorola", "phone"),
    # Routers & ISP CPE (Airtel, JioFiber, ACT, TP-Link, Netgear, Asus, D-Link, Nokia, Huawei, ZTE, Ubiquiti, Cisco, MikroTik)
    "50:C7:BF": ("TP-Link", "router"), "98:DA:C4": ("TP-Link", "router"), "C0:25:E9": ("TP-Link", "router"),
    "E8:DE:27": ("TP-Link", "router"), "14:CC:20": ("TP-Link", "router"), "60:E3:27": ("TP-Link", "router"),
    "A0:04:60": ("Netgear", "router"), "28:C6:8E": ("Netgear", "router"), "C4:04:15": ("Netgear", "router"),
    "00:1A:2B": ("Cisco", "router"), "00:1E:F7": ("Cisco", "router"), "34:6F:90": ("Cisco", "router"),
    "70:85:C2": ("Nokia / Airtel Fiber", "router"), "68:15:90": ("Nokia / Airtel Fiber", "router"),
    "C4:A8:1D": ("D-Link", "router"), "1C:7E:E5": ("D-Link", "router"), "B8:A3:86": ("D-Link", "router"),
    "48:8F:5A": ("MikroTik", "router"), "64:D1:54": ("MikroTik", "router"),
    "74:83:C2": ("Ubiquiti", "router"), "F0:9F:C2": ("Ubiquiti", "router"), "B4:FB:E4": ("Ubiquiti", "router"),
    "00:25:9C": ("Linksys", "router"), "A8:9C:ED": ("Huawei / JioFiber", "router"),
    "48:46:FB": ("Huawei / JioFiber", "router"), "E0:24:7F": ("Huawei / JioFiber", "router"),
    "2C:AB:25": ("ZTE Fiber Router", "router"), "78:96:82": ("ZTE Fiber Router", "router"),
    "04:D4:C4": ("ASUS Router", "router"), "2C:FD:A1": ("ASUS", "laptop"), "B0:6E:BF": ("ASUS", "laptop"),
    "00:1D:AA": ("DrayTek", "router"), "C8:3A:35": ("Tenda Router", "router"), "CC:2D:21": ("Tenda Router", "router"),
    # Laptops, PCs & Network Cards (Intel, Realtek, Dell, HP, Lenovo, Acer, Microsoft, Qualcomm)
    "00:14:22": ("Dell", "laptop"), "F8:B1:56": ("Dell", "laptop"), "A4:4C:C8": ("Dell", "laptop"),
    "D4:BE:D9": ("Dell", "laptop"), "3C:D9:2B": ("HP", "printer"), "9C:B6:54": ("HP", "laptop"),
    "10:60:4B": ("HP", "laptop"), "00:21:CC": ("Lenovo", "laptop"), "54:EE:75": ("Lenovo", "laptop"),
    "98:FA:9B": ("Lenovo", "laptop"), "00:1B:21": ("Intel PC", "laptop"), "3C:F0:11": ("Intel Wi-Fi PC", "laptop"),
    "48:51:B7": ("Intel Wi-Fi PC", "laptop"), "8C:8D:28": ("Intel Wi-Fi PC", "laptop"),
    "A4:C3:F0": ("Intel Wi-Fi PC", "laptop"), "F4:8C:50": ("Intel Wi-Fi PC", "laptop"),
    "00:E0:4C": ("Realtek PC", "laptop"), "52:54:00": ("QEMU / KVM Virtual Machine", "laptop"),
    "00:50:F2": ("Microsoft", "laptop"), "28:18:78": ("Microsoft Surface", "laptop"),
    "9C:5C:8E": ("ASUS", "laptop"), "C0:3F:D5": ("Acer", "laptop"),
    # Smart TVs, IoT, Printers, Consoles & SBCs
    "B8:27:EB": ("Raspberry Pi", "iot"), "DC:A6:32": ("Raspberry Pi", "iot"), "E4:5F:01": ("Raspberry Pi", "iot"),
    "24:6F:28": ("Espressif Smart IoT", "iot"), "30:AE:A4": ("Espressif Smart IoT", "iot"),
    "84:CC:A8": ("Espressif Smart IoT", "iot"), "44:65:0D": ("Amazon Echo / Fire TV", "tv"),
    "FC:65:DE": ("Amazon Echo / Fire TV", "tv"), "68:54:FD": ("Amazon Fire TV", "tv"),
    "00:09:DF": ("LG Smart TV", "tv"), "78:5D:C8": ("LG Smart TV", "tv"), "A8:23:FE": ("LG Smart TV", "tv"),
    "00:04:1F": ("Sony PlayStation / TV", "tv"), "FC:0F:E6": ("Sony Bravia TV", "tv"),
    "00:1E:8F": ("Canon Printer", "printer"), "00:26:AB": ("Epson Printer", "printer"),
    "00:1B:A9": ("Brother Printer", "printer"), "00:0C:29": ("VMware Virtual Machine", "unknown"),
    "08:00:27": ("VirtualBox VM", "unknown"), "00:15:5D": ("Microsoft Hyper-V VM", "unknown"),
    "DE:AD:BE": ("Spoofed / Test MAC", "unknown"),
}

_IEEE_CACHE: Dict[str, str] = {}
_CACHE_LOADED = False


def _load_ieee_cache():
    global _IEEE_CACHE, _CACHE_LOADED
    if _CACHE_LOADED:
        return
    _CACHE_LOADED = True
    if IEEE_OUI_CACHE_PATH.exists():
        try:
            _IEEE_CACHE = json.loads(IEEE_OUI_CACHE_PATH.read_text(encoding="utf-8"))
        except Exception:
            _IEEE_CACHE = {}


def get_oui_count() -> int:
    _load_ieee_cache()
    return max(len(BUILTIN_OUI), len(_IEEE_CACHE))


def is_locally_administered_mac(mac: str) -> bool:
    """Return True if the MAC has the locally-administered bit set (randomized private Wi-Fi MAC)."""
    try:
        first_octet = int(mac.strip().replace("-", ":").split(":")[0], 16)
        return bool(first_octet & 0x02) and not bool(first_octet & 0x01)
    except Exception:
        return False


def infer_device_type_from_vendor_or_name(text: str, fallback: str = "unknown") -> str:
    low = (text or "").lower()
    if any(k in low for k in ("iphone", "android", "pixel", "galaxy", "redmi", "poco", "oneplus", "vivo", "oppo", "realme", "phone", "mobile", "nothing")):
        return "phone"
    if any(k in low for k in ("macbook", "laptop", "desktop", "thinkpad", "ideapad", "inspiron", "pavilion", "workstation", "ubuntu", "windows", "surface", "dell", "lenovo", "intel", "asus", "acer")):
        return "laptop"
    if any(k in low for k in ("ipad", "tablet", "tab ")):
        return "tablet"
    if any(k in low for k in ("tv", "bravia", "firetv", "fire tv", "roku", "chromecast", "appletv", "webos", "playstation", "xbox")):
        return "tv"
    if any(k in low for k in ("printer", "laserjet", "deskjet", "officejet", "epson", "canon", "brother")):
        return "printer"
    if any(k in low for k in ("router", "gateway", "modem", "airtel", "jiofiber", "tp-link", "tplink", "netgear", "unifi", "ubiquiti", "mikrotik", "d-link", "tenda", "cisco", "zte", "huawei")):
        return "router"
    if any(k in low for k in ("echo", "alexa", "nest", "cam", "bulb", "plug", "espressif", "raspberry", "homepod", "sonos", "tuya")):
        return "iot"
    return fallback


def lookup_mac_vendor(mac: str) -> Tuple[str, str, bool]:
    """Return (vendor_name, device_type, is_randomized_mac)."""
    _load_ieee_cache()
    if not mac:
        return "Unknown Manufacturer", "unknown", False
    clean = mac.strip().upper().replace("-", ":")
    parts = [p.zfill(2) for p in clean.split(":") if p]
    if len(parts) < 3:
        return "Unknown Manufacturer", "unknown", False
    prefix = ":".join(parts[:3])

    if prefix in BUILTIN_OUI:
        v, dt = BUILTIN_OUI[prefix]
        return v, dt, False

    if prefix in _IEEE_CACHE:
        vendor = _IEEE_CACHE[prefix]
        return vendor, infer_device_type_from_vendor_or_name(vendor, "unknown"), False

    if is_locally_administered_mac(clean):
        return "Private Wi-Fi Address (Randomized MAC)", "phone", True

    return "Unknown Manufacturer", "unknown", False


async def sync_ieee_oui_database() -> dict:
    """Download the official IEEE OUI CSV (~35,000+ hardware vendors) and cache locally."""
    global _IEEE_CACHE, _CACHE_LOADED
    import httpx

    url = "https://standards-oui.ieee.org/oui/oui.csv"
    async with httpx.AsyncClient(timeout=25.0, follow_redirects=True) as client:
        resp = await client.get(url, headers={"User-Agent": "GARUDA-Network-Guardian/3.0"})
        resp.raise_for_status()
        text = resp.text

    reader = csv.DictReader(io.StringIO(text))
    parsed: Dict[str, str] = {}
    for row in reader:
        assignment = (row.get("Assignment") or "").strip().upper()
        org = (row.get("Organization Name") or "").strip()
        if len(assignment) == 6 and org:
            prefix = f"{assignment[0:2]}:{assignment[2:4]}:{assignment[4:6]}"
            parsed[prefix] = org

    if parsed:
        IEEE_OUI_CACHE_PATH.write_text(json.dumps(parsed), encoding="utf-8")
        _IEEE_CACHE = parsed
        _CACHE_LOADED = True
    return {"synced": len(parsed), "cache_path": str(IEEE_OUI_CACHE_PATH)}
