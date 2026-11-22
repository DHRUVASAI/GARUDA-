"""Test suite for GARUDA v6 Fast-Path Accelerator (fast-anything pattern)."""

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import pytest
from app.services.fast_accel import (
    FastSlidingTracker,
    fast_beacon_regularity,
    fast_shannon_entropy,
    fast_dga_features,
    run_differential_verification,
    benchmark,
)


def test_fast_accel_differential_verification():
    """Verify that all fast-path routines produce 100% mathematically equivalent outputs."""
    ok, msg = run_differential_verification()
    assert ok is True, f"Differential verification failed: {msg}"


def test_fast_sliding_tracker_port_sweep():
    """Verify O(1) sliding tracker correctly reports distinct port counts under rapid bursts."""
    tracker = FastSlidingTracker(window_sec=10.0, maxlen=200)
    now = 100.0

    # Add 15 distinct ports within 5 seconds
    for p in range(1, 16):
        distinct = tracker.add(now + p * 0.2, p)
    assert distinct == 15

    # Repeat same ports — distinct count must stay 15
    for p in range(1, 16):
        distinct = tracker.add(now + 4.0, p)
    assert distinct == 15

    # Move time forward past window (now + 16.0s) — previous ports must expire
    new_now = now + 16.0
    distinct = tracker.get_distinct(now=new_now)
    assert distinct == 0


def test_fast_beacon_regularity_robotic_vs_benign():
    """Verify fast beacon regularity accurately scores rigid C2 callbacks vs human traffic."""
    # Machine-like beacon every 30.0s exactly
    robotic_ts = [100.0 + i * 30.0 for i in range(10)]
    score_robotic = fast_beacon_regularity(robotic_ts)
    assert score_robotic >= 0.90, f"Expected high beacon score for robotic callback, got {score_robotic}"

    # Highly irregular human browsing
    human_ts = [100.0, 102.5, 125.0, 128.0, 240.0, 241.0, 600.0, 605.0]
    score_human = fast_beacon_regularity(human_ts)
    assert score_human == 0.0, f"Expected zero beacon score for human jitter, got {score_human}"


def test_fast_dga_classification():
    """Verify single-pass DGA classifier flags botnet payloads and clears legitimate sites."""
    # High-entropy botnet domain
    malicious = fast_dga_features("x89fj2k39v0mz18qla9.ru")
    assert malicious["verdict"] in ("malicious_dga", "suspicious")
    assert malicious["dga_probability"] > 0.50

    # Legitimate human-readable domain
    benign = fast_dga_features("wikipedia.org")
    assert benign["verdict"] == "benign"
    assert benign["dga_probability"] < 0.20


def test_fast_accel_benchmark_speedup():
    """Verify that the accelerator provides measurable speedup over reference implementations."""
    bm = benchmark()
    assert bm["port_tracking"]["speedup"] >= 5.0, f"Port tracking speedup too low: {bm['port_tracking']['speedup']}x"
    assert bm["beacon_detection"]["speedup"] >= 2.0, f"Beacon detection speedup too low: {bm['beacon_detection']['speedup']}x"
