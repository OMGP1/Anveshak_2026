from __future__ import annotations

import hashlib
import math
import sys
from collections import OrderedDict

import numpy as np

_ODICT_ENTRY_BYTES = 100


def _alpha(m: int) -> float:
    if m == 16:
        return 0.673
    if m == 32:
        return 0.697
    if m == 64:
        return 0.709
    return 0.7213 / (1.0 + 1.079 / m)


class HyperLogLog:
    def __init__(self, m_bits: int = 12, seed: int = 0) -> None:
        if not 4 <= m_bits <= 20:
            raise ValueError("m_bits must be between 4 and 20")
        self.m_bits = int(m_bits)
        self.m = 1 << self.m_bits
        self.seed = int(seed)
        self._rho_bits = 64 - self.m_bits
        self._alpha_mm = _alpha(self.m) * self.m * self.m
        self._salt = (self.seed & 0xFFFFFFFF).to_bytes(4, "little")
        self.registers = np.zeros(self.m, dtype=np.uint8)

    def add(self, key: bytes) -> None:
        h = int.from_bytes(hashlib.blake2b(key, digest_size=8, salt=self._salt).digest(), "little")
        idx = h & (self.m - 1)
        w = h >> self.m_bits
        rho = self._rho_bits + 1 if w == 0 else self._rho_bits - w.bit_length() + 1
        if rho > self.registers[idx]:
            self.registers[idx] = rho

    def count(self) -> float:
        raw = self._alpha_mm / float(np.exp2(-self.registers.astype(np.float64)).sum())
        zeros = int(np.count_nonzero(self.registers == 0))
        if raw <= 2.5 * self.m and zeros > 0:
            return self.m * math.log(self.m / zeros)
        return raw

    def merge(self, other: "HyperLogLog") -> "HyperLogLog":
        if other.m_bits != self.m_bits or other.seed != self.seed:
            raise ValueError("sketches must share m_bits and seed to merge")
        np.maximum(self.registers, other.registers, out=self.registers)
        return self

    def clear(self) -> None:
        self.registers.fill(0)

    @property
    def relative_error(self) -> float:
        return 1.04 / math.sqrt(self.m)

    @property
    def nbytes(self) -> int:
        return int(self.registers.nbytes)


class HLLFamily:
    def __init__(self, m_bits: int = 8, capacity: int = 100_000, seed: int = 0) -> None:
        if capacity < 1:
            raise ValueError("capacity must be at least 1")
        self.m_bits = int(m_bits)
        self.capacity = int(capacity)
        self.seed = int(seed)
        self.evicted = 0
        self._entry_bytes = (1 << self.m_bits) + sys.getsizeof(HyperLogLog(m_bits)) + _ODICT_ENTRY_BYTES
        self._groups: OrderedDict[bytes, HyperLogLog] = OrderedDict()

    def add(self, group: bytes, key: bytes) -> None:
        h = self._groups.get(group)
        if h is None:
            h = HyperLogLog(self.m_bits, self.seed)
            self._groups[group] = h
            if len(self._groups) > self.capacity:
                self._groups.popitem(last=False)
                self.evicted += 1
        else:
            self._groups.move_to_end(group)
        h.add(key)

    def count(self, group: bytes) -> float:
        h = self._groups.get(group)
        return h.count() if h is not None else 0.0

    def drop(self, group: bytes) -> None:
        self._groups.pop(group, None)

    def clear(self) -> None:
        self._groups.clear()

    def __len__(self) -> int:
        return len(self._groups)

    def __contains__(self, group: bytes) -> bool:
        return group in self._groups

    @property
    def nbytes(self) -> int:
        return len(self._groups) * self._entry_bytes

    @property
    def capacity_bytes(self) -> int:
        return self.capacity * self._entry_bytes
