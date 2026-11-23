import json
import os
from backend.app.services.oui_db import (
    is_locally_administered_mac,
    lookup_mac_vendor,
    lookup_v8_iot_vendor,
)


def test_ieee_oui_cache_populated_with_smart_devices():
    cache_path = os.path.join("data", "ieee_oui_cache.json")
    assert os.path.exists(cache_path)
    with open(cache_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert len(data) >= 80
    assert "10:D5:61" in data  # Tuya Smart
    assert "00:80:77" in data  # Brother


def test_smart_device_lookup_vendors():
    assert lookup_v8_iot_vendor("00:1E:8F:11:22:33") == ("Canon Inc.", "printer")
    assert lookup_v8_iot_vendor("28:6C:07:11:22:33") == ("Xiaomi Communications", "mobile")
    assert lookup_v8_iot_vendor("FC:65:DE:11:22:33") == ("Amazon Technologies (Echo/Blink)", "iot")
    vendor, dtype, is_rand = lookup_mac_vendor("C4:2F:90:AA:BB:CC")
    assert "Hikvision" in vendor
    assert is_rand is False


def test_randomized_mac_detection():
    # Second hex nibble in {2, 6, A, E} indicates locally administered / randomized MAC
    assert is_locally_administered_mac("DA:A1:19:00:11:22") is True
    assert is_locally_administered_mac("00:1E:8F:00:11:22") is False
