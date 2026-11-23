"""
GARUDA v9 fast-anything Accelerator Module (fast_accel.py)
----------------------------------------------------------
Actively wired into ids_engine.py and ml_engine.py:
  1. FastSlidingTracker: O(1) amortized time-windowed unique port tracker for SYN floods & slow scans.
  2. SynRingBuffer: O(1) fixed-size ring buffer for bounded fanout tracking.
  3. fast_beacon_variance: Single-pass Welford population mean/variance for C2 beacon regularity.
  4. fast_shannon_entropy: Precomputed log2 lookup table for zero-allocation DGA domain entropy.
"""
import collections
import math
from typing import Deque, Dict, Iterable, Tuple

_MAX_LEN = 256
_ENTROPY_LUT: Tuple[Tuple[float, ...], ...] = tuple(
    tuple(
        0.0 if c == 0 else -(c / n) * math.log2(c / n)
        for c in range(n + 1)
    )
    for n in range(_MAX_LEN + 1)
)


class FastSlidingTracker:
    """O(1) amortized sliding time-window tracker for unique ports per source IP."""

    __slots__ = ("_window", "_maxlen", "_dq", "_counts")

    def __init__(self, window_sec: float = 15.0, maxlen: int = 512) -> None:
        self._window = window_sec
        self._maxlen = maxlen
        self._dq: Deque[Tuple[float, int]] = collections.deque()
        self._counts: Dict[int, int] = {}

    def record(self, ts: float, port: int) -> int:
        """Record (ts, port), evict expired entries in O(1) amortized, return unique port count."""
        cutoff = ts - self._window
        dq = self._dq
        counts = self._counts

        while dq and (dq[0][0] < cutoff or len(dq) >= self._maxlen):
            _, old_port = dq.popleft()
            c = counts.get(old_port, 1) - 1
            if c <= 0:
                counts.pop(old_port, None)
            else:
                counts[old_port] = c

        dq.append((ts, port))
        counts[port] = counts.get(port, 0) + 1
        return len(counts)

    def unique_count(self, now: float) -> int:
        cutoff = now - self._window
        dq = self._dq
        counts = self._counts
        while dq and dq[0][0] < cutoff:
            _, old_port = dq.popleft()
            c = counts.get(old_port, 1) - 1
            if c <= 0:
                counts.pop(old_port, None)
            else:
                counts[old_port] = c
        return len(counts)


class SynRingBuffer:
    """O(1) bounded ring buffer tracking unique destination ports per source IP."""

    __slots__ = ("_cap", "_buf", "_counts", "_idx", "_size")

    def __init__(self, capacity: int = 256) -> None:
        self._cap = max(8, capacity)
        self._buf = [None] * self._cap
        self._counts: Dict[int, int] = {}
        self._idx = 0
        self._size = 0

    def push(self, port: int) -> int:
        old = self._buf[self._idx]
        if old is not None:
            cnt = self._counts.get(old, 1) - 1
            if cnt <= 0:
                self._counts.pop(old, None)
            else:
                self._counts[old] = cnt

        self._buf[self._idx] = port
        self._counts[port] = self._counts.get(port, 0) + 1
        self._idx = (self._idx + 1) % self._cap
        if self._size < self._cap:
            self._size += 1
        return len(self._counts)

    @property
    def unique_ports(self) -> int:
        return len(self._counts)


def fast_beacon_variance(intervals: Iterable[float]) -> Tuple[float, float]:
    """Single-pass population mean and variance (Welford's algorithm)."""
    n = 0
    mean = 0.0
    m2 = 0.0
    for x in intervals:
        n += 1
        delta = x - mean
        mean += delta / n
        m2 += delta * (x - mean)
    if n == 0:
        return 0.0, 0.0
    return mean, m2 / n


def fast_shannon_entropy(text: str) -> float:
    """Zero-allocation precomputed LUT Shannon entropy for DGA domain classification."""
    n = len(text)
    if n <= 1:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1

    if n <= _MAX_LEN:
        row = _ENTROPY_LUT[n]
        return sum(row[c] for c in freq.values())

    inv_n = 1.0 / n
    return -sum((c * inv_n) * math.log2(c * inv_n) for c in freq.values())
