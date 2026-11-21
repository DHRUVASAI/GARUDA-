"""Unit & Regression Tests for Resilient IEEE OUI Sync and Smart Device Classification.
Verifies:
1. Multi-tier IEEE OUI synchronization never fails and always yields >= 40,000 entries.
2. Network failure fallback to bundled cache guarantees zero HTTP 502/418 exceptions.
3. Accurate vendor normalization ("Amazon Technologies Inc." -> "Amazon").
4. Amazon Alexa / Echo hardware and model classification (Dot, Show, Studio, Flex, Pop).
5. Amazon Fire TV Stick hardware and model classification (AFTMM, AFTS, AFTT, AFTM, AFTB).
6. Port and mDNS signature fusion for smart devices (Google Nest, Chromecast, Apple TV, Roku, Espressif).
"""

import pytest
import asyncio
import sys
from pathlib import Path
from unittest.mock import patch, AsyncMock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.oui_db import (
    sync_ieee_oui_database,
    lookup_mac_vendor,
    normalize_vendor_name,
    infer_device_type_from_vendor_or_name,
    get_oui_count,
    IEEE_OUI_CACHE_PATH,
)
from app.services.device_scanner import resolve_device_identity, classify_smart_device


@pytest.fixture(autouse=True)
def speed_up_unit_tests():
    """Mock network timeouts (NetBIOS / rDNS) for non-existent synthetic test IPs."""
    with patch("app.services.device_scanner.query_netbios_name", return_value=None), \
         patch("socket.gethostbyaddr", side_effect=Exception("Host not found")):
        yield


@pytest.mark.anyio
async def test_ieee_sync_live_and_cache():
    """Verify live multi-source sync or bundled fallback returns >= 40,000 entries with success status."""
    result = await sync_ieee_oui_database()
    assert result["status"] == "success"
    assert result["synced"] >= 40000
    assert result["source"] in ("hwdata_linux_mirror", "arpscan_mirror", "ieee_official_csv", "bundled_cache")
    assert IEEE_OUI_CACHE_PATH.exists()
    assert get_oui_count() >= 40000


@pytest.mark.anyio
async def test_ieee_sync_network_failure_resilience():
    """Verify that when all network mirrors fail (e.g. offline/WAF block), sync safely falls back to bundled cache."""
    with patch("httpx.AsyncClient.get", side_effect=Exception("Simulated Network Timeout / WAF 418")):
        result = await sync_ieee_oui_database()
        assert result["status"] == "success"
        assert result["synced"] >= 1000
        assert result["source"] in ("bundled_cache", "builtin_table")


def test_amazon_vendor_normalization():
    """Verify verbose IEEE legal entity names are normalized to clean 'Amazon'."""
    assert normalize_vendor_name("Amazon Technologies Inc.") == "Amazon"
    assert normalize_vendor_name("AMAZON TECHNOLOGIES INC.") == "Amazon"
    assert normalize_vendor_name("Amazon.com, Inc.") == "Amazon"
    assert normalize_vendor_name("Apple, Inc.") == "Apple"
    assert normalize_vendor_name("Samsung Electronics Co.,Ltd") == "Samsung"


def test_amazon_oui_mac_lookups():
    """Verify known Amazon hardware MACs resolve to vendor Amazon and device_type iot/tv."""
    amazon_macs = [
        "84:28:59:12:34:56",
        "44:65:0D:AB:CD:EF",
        "28:73:F6:00:11:22",
        "E0:CB:1D:33:44:55",
        "FC:D7:49:66:77:88",
        "08:91:A3:99:AA:BB",
    ]
    for mac in amazon_macs:
        vendor, dtype, is_rand = lookup_mac_vendor(mac)
        assert vendor == "Amazon", f"MAC {mac} failed to resolve to Amazon (got {vendor})"
        assert dtype in ("iot", "tv"), f"MAC {mac} has unexpected device_type {dtype}"
        assert is_rand is False


def test_amazon_fire_tv_stick_recognition():
    """Verify Amazon Fire TV Stick models (AFTMM, AFTS, AFTT, hostnames, ports) are accurately identified."""
    # Model code AFTMM = Fire TV Stick 4K Max
    ident_aftmm = resolve_device_identity(
        ip="192.168.1.120", mac="84:28:59:AA:BB:CC", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={}, dhcp_map={"84:28:59:AA:BB:CC": "AFTMM"},
    )
    assert ident_aftmm["real_name"] == "Amazon Fire TV Stick 4K Max"
    assert ident_aftmm["device_type"] == "tv"
    assert "Fire OS" in ident_aftmm["os_hint"]
    assert ident_aftmm["vendor"] == "Amazon"

    # Hostname firetv-livingroom
    ident_host = resolve_device_identity(
        ip="192.168.1.121", mac="84:28:59:11:22:33", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={}, dhcp_map={"84:28:59:11:22:33": "Living Room Fire TV"},
    )
    assert "Fire TV" in ident_host["real_name"]
    assert ident_host["device_type"] == "tv"

    # Port signature: DIAL multiscreen (port 8008) on Amazon device
    ident_port = resolve_device_identity(
        ip="192.168.1.122", mac="84:28:59:44:55:66", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={}, dhcp_map={}, open_ports=[8008],
    )
    assert ident_port["real_name"] == "Amazon Fire TV Stick (122)"
    assert ident_port["device_type"] == "tv"


def test_amazon_echo_alexa_recognition():
    """Verify Amazon Echo/Alexa devices (Echo Dot, Echo Show, Spotify port, mDNS) are accurately identified."""
    # Echo Dot DHCP
    ident_dot = resolve_device_identity(
        ip="192.168.1.130", mac="84:28:59:EE:FF:01", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={}, dhcp_map={"84:28:59:EE:FF:01": "echodot-kitchen"},
    )
    assert ident_dot["real_name"] == "Amazon Echo Dot (Alexa)"
    assert ident_dot["device_type"] == "iot"
    assert ident_dot["vendor"] == "Amazon"

    # Echo Show mDNS
    ident_show = resolve_device_identity(
        ip="192.168.1.131", mac="84:28:59:EE:FF:02", is_gateway=False, is_self=False,
        mdns_map={"192.168.1.131": ("Echo Show 8", "Amazon Alexa")}, ssdp_map={}, dhcp_map={},
    )
    assert ident_show["real_name"] == "Amazon Echo Show (Alexa)"
    assert ident_show["device_type"] == "iot"

    # Port signature: Spotify Connect (port 4070) on Amazon device
    ident_port = resolve_device_identity(
        ip="192.168.1.132", mac="84:28:59:EE:FF:03", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={}, dhcp_map={}, open_ports=[4070],
    )
    assert ident_port["real_name"] == "Amazon Echo / Alexa (132)"
    assert ident_port["device_type"] == "iot"


def test_raw_amazon_mac_graceful_labeling():
    """Verify a raw Amazon MAC with no hostname and no ports is named gracefully and never 'Unidentified'."""
    ident_raw = resolve_device_identity(
        ip="192.168.1.140", mac="84:28:59:99:99:99", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={}, dhcp_map={},
    )
    assert ident_raw["real_name"] == "Amazon Smart Device (Echo / Fire TV) (140)"
    assert ident_raw["device_type"] == "iot"
    assert ident_raw["vendor"] == "Amazon"
    assert "Fire OS" in ident_raw["os_hint"]


def test_broader_smart_device_classification():
    """Verify Google Nest, Chromecast, Apple TV, Roku, Espressif devices are recognized."""
    # Google Nest
    ident_nest = resolve_device_identity(
        ip="192.168.1.150", mac="3C:5A:B4:01:02:03", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={}, dhcp_map={"3C:5A:B4:01:02:03": "google-nest-mini"},
    )
    assert "Nest" in ident_nest["real_name"] and ident_nest["device_type"] == "iot"

    # Google Chromecast
    ident_cast = resolve_device_identity(
        ip="192.168.1.151", mac="F4:F5:E8:01:02:03", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={}, dhcp_map={"F4:F5:E8:01:02:03": "Living-Room-Chromecast"},
    )
    assert "Chromecast" in ident_cast["real_name"] and ident_cast["device_type"] == "tv"

    # Apple TV
    ident_appletv = resolve_device_identity(
        ip="192.168.1.152", mac="C8:69:CD:01:02:03", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={}, dhcp_map={"C8:69:CD:01:02:03": "Apple-TV-4K"},
    )
    assert ident_appletv["real_name"] == "Apple TV" and ident_appletv["device_type"] == "tv"

    # Roku
    ident_roku = resolve_device_identity(
        ip="192.168.1.153", mac="AC:AE:19:01:02:03", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={}, dhcp_map={"AC:AE:19:01:02:03": "Roku-Streaming-Stick"},
    )
    assert "Roku" in ident_roku["real_name"] and ident_roku["device_type"] == "tv"

    # Espressif Smart IoT
    ident_esp = resolve_device_identity(
        ip="192.168.1.154", mac="24:6F:28:01:02:03", is_gateway=False, is_self=False,
        mdns_map={}, ssdp_map={}, dhcp_map={},
    )
    assert "Espressif" in ident_esp["real_name"] and ident_esp["device_type"] == "iot"
