from __future__ import annotations

import sys
from collections import OrderedDict
from dataclasses import dataclass

import numpy as np

from engine.state.hll import HLLFamily
from engine.types import FlowState, PacketMeta

BeaconKey = tuple[int, int, int, int]

_ODICT_ENTRY_BYTES = 100


@dataclass(slots=True)
class Candidate:
    first_ts_ns: int
    last_ts_ns: int
    last_check_ns: int
    n_seen: int = 0
    n_samples: int = 0
    short_gaps: int = 0
    head: int = 0
    ring: np.ndarray | None = None


_CANDIDATE_BYTES = sys.getsizeof(Candidate(0, 0, 0)) + sys.getsizeof((0, 0, 0, 0)) + _ODICT_ENTRY_BYTES


class BeaconTable:
    def __init__(
        self,
        capacity: int = 50_000,
        ttl_s: float = 21600.0,
        ring: int = 64,
        min_samples: int = 12,
        min_packets: int = 4,
        max_mean_bytes: float = 1200.0,
        min_iat_s: float = 1.0,
        recheck_s: float = 60.0,
        max_short_gaps: int = 3,
    ) -> None:
        if capacity < 1 or ring < 4:
            raise ValueError("capacity must be >= 1 and ring >= 4")
        self.capacity = int(capacity)
        self.ttl_ns = int(ttl_s * 1e9)
        self.ring = int(ring)
        self.min_samples = min(int(min_samples), self.ring)
        self.min_packets = max(2, int(min_packets))
        self.max_mean_bytes = float(max_mean_bytes)
        self.min_iat_s = float(min_iat_s)
        self.recheck_ns = int(recheck_s * 1e9)
        self.max_short_gaps = int(max_short_gaps)
        self.rejected = 0
        self.dropped_chatty = 0
        self.evicted = 0
        self.expired = 0
        self._rings = 0
        self._ring_bytes = self.ring * 4
        self._table: OrderedDict[BeaconKey, Candidate] = OrderedDict()
        self._dirty: set[BeaconKey] = set()
        self._fanout = HLLFamily(m_bits=8, capacity=max(1024, self.capacity // 4))

    def observe(self, meta: PacketMeta, flow: FlowState) -> None:
        if not self._prefilter(flow):
            self.rejected += 1
            return
        key = self._key(meta, flow)
        self._fanout.add(key[1].to_bytes(16, "big"), key[2].to_bytes(16, "big") + key[3].to_bytes(2, "big"))
        cand = self._table.get(key)
        if cand is None:
            self._insert(key, meta.ts_ns)
            return
        self._table.move_to_end(key)
        gap_ns = meta.ts_ns - cand.last_ts_ns
        cand.n_seen += 1
        if gap_ns <= 0:
            return
        cand.last_ts_ns = meta.ts_ns
        if gap_ns < self.min_iat_s * 1e9:
            cand.short_gaps += 1
            if cand.short_gaps >= self.max_short_gaps:
                self._forget(key)
                self.dropped_chatty += 1
            return
        if cand.ring is None:
            cand.ring = np.zeros(self.ring, dtype=np.float32)
            self._rings += 1
        cand.ring[cand.head] = gap_ns / 1e9
        cand.head = (cand.head + 1) % self.ring
        cand.n_samples += 1
        if cand.n_samples >= self.min_samples:
            self._dirty.add(key)

    def ready(self, now_ns: int, limit: int = 0) -> list[tuple[BeaconKey, np.ndarray, float]]:
        self._expire(now_ns)
        out: list[tuple[BeaconKey, np.ndarray, float]] = []
        for key in list(self._dirty):
            cand = self._table.get(key)
            if cand is None or cand.ring is None or cand.n_samples < self.min_samples:
                self._dirty.discard(key)
                continue
            if now_ns - cand.last_check_ns < self.recheck_ns:
                continue
            cand.last_check_ns = now_ns
            self._dirty.discard(key)
            out.append((key, self.samples(key), self.dst_stability(key)))
            if limit > 0 and len(out) >= limit:
                break
        return out

    def samples(self, key: BeaconKey) -> np.ndarray:
        cand = self._table.get(key)
        if cand is None or cand.ring is None:
            return np.empty(0, dtype=np.float32)
        if cand.n_samples < self.ring:
            return cand.ring[: cand.n_samples].copy()
        return np.concatenate((cand.ring[cand.head :], cand.ring[: cand.head]))

    def dst_stability(self, key: BeaconKey) -> float:
        distinct = self._fanout.count(key[1].to_bytes(16, "big"))
        return 1.0 / max(1.0, distinct)

    def __len__(self) -> int:
        return len(self._table)

    def __contains__(self, key: BeaconKey) -> bool:
        return key in self._table

    @property
    def rings(self) -> int:
        return self._rings

    @property
    def nbytes(self) -> int:
        return len(self._table) * _CANDIDATE_BYTES + self._rings * self._ring_bytes + self._fanout.nbytes

    @property
    def capacity_bytes(self) -> int:
        return self.capacity * (_CANDIDATE_BYTES + self._ring_bytes) + self._fanout.capacity_bytes

    def _prefilter(self, flow: FlowState) -> bool:
        pkts = flow.packets
        if pkts < self.min_packets:
            return False
        if flow.bytes_total / pkts > self.max_mean_bytes:
            return False
        return flow.duration / (pkts - 1) >= self.min_iat_s

    @staticmethod
    def _key(meta: PacketMeta, flow: FlowState) -> BeaconKey:
        if flow.orientation_confidence > 0.0:
            return (meta.proto, flow.initiator_ip, flow.responder_ip, flow.responder_port)
        return (meta.proto, meta.src_ip, meta.dst_ip, meta.dst_port)

    def _insert(self, key: BeaconKey, ts_ns: int) -> None:
        self._table[key] = Candidate(first_ts_ns=ts_ns, last_ts_ns=ts_ns, last_check_ns=ts_ns, n_seen=1)
        if len(self._table) > self.capacity:
            old_key, old = self._table.popitem(last=False)
            self._release(old)
            self._dirty.discard(old_key)
            self.evicted += 1

    def _forget(self, key: BeaconKey) -> None:
        cand = self._table.pop(key, None)
        if cand is not None:
            self._release(cand)
        self._dirty.discard(key)

    def _release(self, cand: Candidate) -> None:
        if cand.ring is not None:
            self._rings -= 1
            cand.ring = None

    def _expire(self, now_ns: int) -> None:
        cutoff = now_ns - self.ttl_ns
        while self._table:
            key = next(iter(self._table))
            cand = self._table[key]
            if cand.last_ts_ns > cutoff:
                break
            self._table.popitem(last=False)
            self._release(cand)
            self._dirty.discard(key)
            self.expired += 1
