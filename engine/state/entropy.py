from __future__ import annotations

import math
import zlib

import numpy as np

_MIX = 2654435761


class SlidingEntropy:
    def __init__(self, window_s: float = 1.0, buckets: int = 20, slots: int = 1024, seed: int = 0) -> None:
        if buckets < 2 or slots < 2:
            raise ValueError("buckets and slots must be at least 2")
        self.window_s = float(window_s)
        self.buckets = int(buckets)
        self.slots = int(slots)
        self.seed = int(seed)
        self._bucket_ns = max(1, int(self.window_s * 1e9 / self.buckets))
        self._counts = np.zeros((self.buckets, self.slots), dtype=np.int32)
        self._totals = np.zeros(self.slots, dtype=np.int64)
        self._n = 0
        self._cur = 0
        self._cur_start_ns: int | None = None

    def _slot(self, key: bytes) -> int:
        h = ((zlib.crc32(key) ^ self.seed) * _MIX) & 0xFFFFFFFF
        return (h * self.slots) >> 32

    def _advance(self, ts_ns: int) -> None:
        if self._cur_start_ns is None:
            self._cur_start_ns = ts_ns
            return
        steps = (ts_ns - self._cur_start_ns) // self._bucket_ns
        if steps <= 0:
            return
        if steps >= self.buckets:
            self._counts.fill(0)
            self._totals.fill(0)
            self._n = 0
            self._cur = 0
        else:
            for _ in range(int(steps)):
                self._cur = (self._cur + 1) % self.buckets
                row = self._counts[self._cur]
                self._totals -= row
                self._n -= int(row.sum())
                row.fill(0)
        self._cur_start_ns += int(steps) * self._bucket_ns

    def add(self, ts_ns: int, key: bytes, count: int = 1) -> None:
        self._advance(ts_ns)
        slot = self._slot(key)
        self._counts[self._cur, slot] += count
        self._totals[slot] += count
        self._n += count

    def entropy(self, ts_ns: int) -> float:
        self._advance(ts_ns)
        if self._n <= 0:
            return 0.0
        nz = self._totals[self._totals > 0]
        k = int(nz.size)
        if k < 2:
            return 0.0
        p = nz.astype(np.float64) / float(self._n)
        h = float(-(p * np.log(p)).sum())
        return min(1.0, h / math.log(k))

    def distinct(self, ts_ns: int) -> int:
        self._advance(ts_ns)
        return int(np.count_nonzero(self._totals))

    def total(self, ts_ns: int) -> int:
        self._advance(ts_ns)
        return int(self._n)

    def clear(self) -> None:
        self._counts.fill(0)
        self._totals.fill(0)
        self._n = 0
        self._cur = 0
        self._cur_start_ns = None

    @property
    def nbytes(self) -> int:
        return int(self._counts.nbytes + self._totals.nbytes)


class EwmaDeviation:
    def __init__(self, alpha: float = 0.1, warmup: int = 5) -> None:
        if not 0.0 < alpha <= 1.0:
            raise ValueError("alpha must be in (0, 1]")
        self.alpha = float(alpha)
        self.warmup = int(warmup)
        self.n = 0
        self.mean = 0.0
        self.var = 0.0

    def update(self, x: float) -> float:
        x = float(x)
        if self.n == 0:
            self.mean = x
            self.n = 1
            return 0.0
        delta = x - self.mean
        sigma = math.sqrt(self.var)
        dev = delta / sigma if sigma > 1e-12 else 0.0
        self.mean += self.alpha * delta
        self.var = (1.0 - self.alpha) * (self.var + self.alpha * delta * delta)
        self.n += 1
        return 0.0 if self.n <= self.warmup else dev

    @property
    def std(self) -> float:
        return math.sqrt(self.var)
