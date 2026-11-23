import math
from backend.app.services.fast_accel import (
    FastSlidingTracker,
    SynRingBuffer,
    fast_beacon_variance,
    fast_shannon_entropy,
)


def test_fast_sliding_tracker_window_eviction():
    tracker = FastSlidingTracker(window_sec=10.0, maxlen=64)
    for port in range(100, 120):
        tracker.record(1000.0, port)
    assert tracker.unique_count(1005.0) == 20
    assert tracker.unique_count(1011.0) == 0


def test_syn_ring_buffer_capacity_bound():
    buf = SynRingBuffer(capacity=12)
    for p in range(1, 50):
        buf.push(p)
    assert buf.unique_ports == 12


def test_fast_beacon_variance_accuracy():
    mean, var = fast_beacon_variance([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0])
    assert math.isclose(mean, 5.0, rel_tol=1e-6)
    assert math.isclose(var, 4.0, rel_tol=1e-6)


def test_fast_shannon_entropy_matches_definition():
    # 4 equally likely symbols => exactly 2.0 bits
    assert math.isclose(fast_shannon_entropy("abcd"), 2.0, rel_tol=1e-6)
    assert fast_shannon_entropy("") == 0.0
    assert fast_shannon_entropy("zzzzzz") == 0.0
