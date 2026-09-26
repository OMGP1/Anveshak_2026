from __future__ import annotations

import hashlib

import numpy as np

_U32_MAX = 0xFFFFFFFF


class CountMinSketch:
    def __init__(self, width: int = 2719, depth: int = 5, seed: int = 0) -> None:
        if width < 2 or depth < 1:
            raise ValueError("width must be >= 2 and depth >= 1")
        self.width = int(width)
        self.depth = int(depth)
        self.seed = int(seed)
        self.total = 0
        self._salt = (self.seed & _U32_MAX).to_bytes(4, "little")
        self._table = np.zeros((self.depth, self.width), dtype=np.uint32)

    def _slots(self, key: bytes) -> list[int]:
        d = hashlib.blake2b(key, digest_size=16, salt=self._salt).digest()
        h1 = int.from_bytes(d[:8], "little")
        h2 = int.from_bytes(d[8:], "little") | 1
        w = self.width
        return [(h1 + i * h2) % w for i in range(self.depth)]

    def add(self, key: bytes, count: int = 1) -> int:
        if count < 0:
            raise ValueError("count must be non-negative")
        self.total += count
        table = self._table
        best = _U32_MAX
        for row, col in enumerate(self._slots(key)):
            v = int(table[row, col]) + count
            if v > _U32_MAX:
                v = _U32_MAX
            table[row, col] = v
            if v < best:
                best = v
        return best

    def estimate(self, key: bytes) -> int:
        table = self._table
        return min(int(table[row, col]) for row, col in enumerate(self._slots(key)))

    def merge(self, other: "CountMinSketch") -> "CountMinSketch":
        if (other.width, other.depth, other.seed) != (self.width, self.depth, self.seed):
            raise ValueError("sketches must share width, depth and seed to merge")
        summed = self._table.astype(np.uint64) + other._table.astype(np.uint64)
        self._table = np.minimum(summed, _U32_MAX).astype(np.uint32)
        self.total += other.total
        return self

    def clear(self) -> None:
        self._table.fill(0)
        self.total = 0

    @property
    def error_bound(self) -> float:
        return 2.0 * self.total / self.width

    @property
    def table(self) -> np.ndarray:
        return self._table

    @property
    def nbytes(self) -> int:
        return int(self._table.nbytes)
