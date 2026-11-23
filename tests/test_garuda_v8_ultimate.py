import os
from backend.app.services.fast_accel import (
    SynRingBuffer,
    fast_beacon_variance,
    fast_shannon_entropy,
)
from backend.app.services.oui_db import lookup_v8_iot_vendor


def test_fast_accel_syn_ring_buffer_o1():
    buf = SynRingBuffer(capacity=16)
    for port in range(1, 25):
        buf.push(port)
    assert buf.unique_ports == 16  # bounded O(1) eviction


def test_fast_accel_beacon_variance():
    mean, var = fast_beacon_variance([5.0, 5.0, 5.0, 5.0, 5.0])
    assert mean == 5.0
    assert var == 0.0  # perfect C2 periodicity


def test_fast_accel_shannon_entropy():
    low = fast_shannon_entropy("aaaaaaaaaa")
    high = fast_shannon_entropy("xk92a8f7q1z0m4n8p2")
    assert low == 0.0
    assert high > 3.5


def test_v8_iot_oui_recognition():
    assert lookup_v8_iot_vendor("00:1E:8F:AA:BB:CC") == ("Canon Inc.", "printer")
    assert lookup_v8_iot_vendor("28:6C:07:11:22:33") == ("Xiaomi Communications", "mobile")
    assert lookup_v8_iot_vendor("50:2B:73:44:55:66") == ("Realme Chongqing Mobile", "mobile")
    assert lookup_v8_iot_vendor("FC:65:DE:77:88:99") == ("Amazon Technologies (Echo/Blink)", "iot")


def test_monad_attestation_contract_exists():
    contract_path = os.path.join("contracts", "MonadSecurityAttestation.sol")
    assert os.path.exists(contract_path)
    with open(contract_path, "r", encoding="utf-8") as f:
        src = f.read()
    assert "contract MonadSecurityAttestation" in src
    assert "anchorBatch" in src


def test_v9_fast_accel_actively_wired():
    from backend.app.services.fast_accel import FastSlidingTracker
    from backend.app.services.ml_engine import shannon_entropy, compute_beacon_regularity
    from backend.app.services.ids_engine import LivePacketIDS

    tracker = FastSlidingTracker(window_sec=10.0)
    for p in range(1, 15):
        cnt = tracker.record(100.0, p)
    assert cnt == 14
    assert tracker.unique_count(115.0) == 0

    ids = LivePacketIDS()
    assert hasattr(ids, "_syn_trackers")
    assert hasattr(ids, "_slow_syn_trackers")
    assert shannon_entropy("xk92a8f7q1z0m4n8p2") > 3.5
    assert compute_beacon_regularity([0.0, 5.0, 10.0, 15.0, 20.0]) > 0.85
