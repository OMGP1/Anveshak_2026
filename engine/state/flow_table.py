from __future__ import annotations

import sys
from collections import OrderedDict
from typing import Callable

from engine.types import ACK, FIN, RST, SYN, TCP, FlowKey, FlowState, PacketMeta

SPLT_LEN = 20

_ODICT_ENTRY_BYTES = 100

_SAMPLE = FlowState(key=FlowKey(TCP, 0, 0, 0, 0), first_ts_ns=0, last_ts_ns=0)

ENTRY_BYTES = (
    sys.getsizeof(_SAMPLE) + sys.getsizeof(_SAMPLE.key) + sys.getsizeof([]) + _ODICT_ENTRY_BYTES
)

SPLT_ENTRY_BYTES = sys.getsizeof((0, 0)) + 10

WELL_KNOWN_PORT = 1024
SERVICE_PORTS = frozenset((1080, 1194, 1433, 1521, 3128, 3306, 3389, 5432, 5900, 6379,
                           8000, 8080, 8443, 9200, 27017))

ORIENT_SYN = 1.0
ORIENT_SERVICE_PORT = 0.75
ORIENT_FIRST_PACKET = 0.5


def is_service_port(port: int) -> bool:
    return 0 < port < WELL_KNOWN_PORT or port in SERVICE_PORTS


def _guess_initiator(src_port: int, dst_port: int) -> tuple[bool, float]:
    src_service = is_service_port(src_port)
    dst_service = is_service_port(dst_port)
    if src_service != dst_service:
        return not src_service, ORIENT_SERVICE_PORT
    if src_port != dst_port:
        return src_port > dst_port, ORIENT_FIRST_PACKET
    return True, ORIENT_FIRST_PACKET


class FlowTable:
    def __init__(
        self,
        capacity: int = 200_000,
        idle_timeout_s: float = 120.0,
        collect_splt: bool = True,
        splt_capacity: int | None = None,
        on_evict: Callable[[FlowState], None] | None = None,
    ) -> None:
        if capacity < 1:
            raise ValueError("capacity must be at least 1")
        self.capacity = int(capacity)
        self.idle_timeout_ns = int(idle_timeout_s * 1e9)
        self.collect_splt = bool(collect_splt)
        self.on_evict = on_evict
        self.splt_capacity = max(1, self.capacity // 4) if splt_capacity is None else int(splt_capacity)
        self.evicted = 0
        self.expired = 0
        self.created = 0
        self.splt_shed = 0
        self._splt_budget = self.splt_capacity * SPLT_LEN
        self._splt_entries = 0
        self._flows: OrderedDict[FlowKey, FlowState] = OrderedDict()

    def observe(self, meta: PacketMeta) -> FlowState:
        key, _ = FlowKey.of(meta)
        st = self._flows.get(key)
        if st is None:
            st = FlowState(key=key, first_ts_ns=meta.ts_ns, last_ts_ns=meta.ts_ns)
            self._flows[key] = st
            self.created += 1
            if len(self._flows) > self.capacity:
                _, old = self._flows.popitem(last=False)
                self._splt_entries -= len(old.splt)
                self.evicted += 1
                if self.on_evict is not None:
                    self.on_evict(old)
        else:
            self._flows.move_to_end(key)
        self._orient(st, meta)
        self._account(st, meta)
        return st

    def get(self, key: FlowKey) -> FlowState | None:
        return self._flows.get(key)

    def expire(self, now_ns: int) -> list[FlowState]:
        cutoff = now_ns - self.idle_timeout_ns
        out: list[FlowState] = []
        while self._flows:
            key = next(iter(self._flows))
            st = self._flows[key]
            if st.last_ts_ns > cutoff:
                break
            self._flows.popitem(last=False)
            self._splt_entries -= len(st.splt)
            self.expired += 1
            out.append(st)
        return out

    def clear(self) -> None:
        self._flows.clear()
        self._splt_entries = 0

    def __len__(self) -> int:
        return len(self._flows)

    def __contains__(self, key: FlowKey) -> bool:
        return key in self._flows

    def __iter__(self):
        return iter(self._flows.values())

    @property
    def nbytes(self) -> int:
        return len(self._flows) * ENTRY_BYTES + self._splt_entries * SPLT_ENTRY_BYTES

    @property
    def capacity_bytes(self) -> int:
        splt = self._splt_budget * SPLT_ENTRY_BYTES if self.collect_splt else 0
        return self.capacity * ENTRY_BYTES + splt

    def _orient(self, st: FlowState, meta: PacketMeta) -> None:
        if st.orientation_confidence >= 1.0:
            return
        syn = meta.proto == TCP and bool(meta.tcp_flags & SYN)
        ack = bool(meta.tcp_flags & ACK)
        if syn and not ack:
            self._set_initiator(st, meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port, ORIENT_SYN)
        elif syn and ack:
            self._set_initiator(st, meta.dst_ip, meta.dst_port, meta.src_ip, meta.src_port, ORIENT_SYN)
        elif st.orientation_confidence == 0.0:
            src_first, conf = _guess_initiator(meta.src_port, meta.dst_port)
            if src_first:
                self._set_initiator(st, meta.src_ip, meta.src_port, meta.dst_ip, meta.dst_port, conf)
            else:
                self._set_initiator(st, meta.dst_ip, meta.dst_port, meta.src_ip, meta.src_port, conf)

    @staticmethod
    def _set_initiator(st: FlowState, ip: int, port: int, rip: int, rport: int, conf: float) -> None:
        flipped = st.orientation_confidence > 0.0 and (st.initiator_ip, st.initiator_port) != (ip, port)
        st.initiator_ip, st.initiator_port = ip, port
        st.responder_ip, st.responder_port = rip, rport
        st.orientation_confidence = conf
        if flipped:
            st.pkts_fwd, st.pkts_rev = st.pkts_rev, st.pkts_fwd
            st.bytes_fwd, st.bytes_rev = st.bytes_rev, st.bytes_fwd
            st.splt = [(-length, gap) for length, gap in st.splt]

    def _account(self, st: FlowState, meta: PacketMeta) -> None:
        gap_ns = meta.ts_ns - st.last_ts_ns
        if meta.ts_ns > st.last_ts_ns:
            st.last_ts_ns = meta.ts_ns
        from_initiator = meta.src_ip == st.initiator_ip and meta.src_port == st.initiator_port
        if from_initiator:
            st.pkts_fwd += meta.packets
            st.bytes_fwd += meta.length
        else:
            st.pkts_rev += meta.packets
            st.bytes_rev += meta.length
        if meta.proto == TCP:
            st.flags_seen |= meta.tcp_flags
            syn = bool(meta.tcp_flags & SYN)
            ack = bool(meta.tcp_flags & ACK)
            if syn and not ack:
                st.saw_syn = True
            elif syn and ack:
                st.saw_synack = True
            if meta.tcp_flags & FIN:
                st.saw_fin = True
            if meta.tcp_flags & RST:
                st.saw_rst = True
        if meta.tls is not None:
            if meta.tls.is_client_hello and not st.ja4:
                st.ja4 = meta.tls.ja4
            if meta.tls.alpn and not st.tls_alpn:
                st.tls_alpn = meta.tls.alpn
        if self.collect_splt and len(st.splt) < SPLT_LEN and not meta.from_flow_record:
            if self._splt_entries < self._splt_budget:
                length = meta.length if from_initiator else -meta.length
                st.splt.append((length, max(0, gap_ns) // 1000))
                self._splt_entries += 1
            else:
                self.splt_shed += 1
