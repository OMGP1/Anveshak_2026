from __future__ import annotations

import json
import math
import os
import sys
from collections import Counter, OrderedDict
from typing import Any, Callable, Iterator

from engine.decode.packet import format_ip
from engine.state.beacon_table import BeaconTable
from engine.state.hll import HLLFamily, HyperLogLog
from engine.types import ICMP, TCP, UDP, Detection, Evidence, FlowState, PacketMeta

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REFERENCE_DIR = os.path.join(ROOT, "data", "reference")

PROTO_NAMES = {TCP: "TCP", UDP: "UDP", ICMP: "ICMP"}

SEVERITY_BANDS = ((0.60, "LOW"), (0.75, "MEDIUM"), (0.90, "HIGH"), (2.0, "CRITICAL"))

_ODICT_ENTRY_BYTES = 100

DEFAULT_CONFIG: dict[str, Any] = {
    "dst_hot_capacity": 256,
    "dst_hot_pps": 8.0,
    "scan_hll_capacity": 8192,
    "scan_hll_m_bits": 6,
    "dns_hll_capacity": 8192,
    "dns_hll_m_bits": 8,
    "beacon_capacity": 50000,
    "beacon_ttl_s": 21600.0,
    "beacon_ring": 64,
    "beacon_min_samples": 12,
}


def clamp01(x: float) -> float:
    if x <= 0.0:
        return 0.0
    return 1.0 if x >= 1.0 else float(x)


def margin(value: float, threshold: float, span: float) -> float:
    if span <= 0.0:
        return 1.0 if value >= threshold else 0.0
    return clamp01((value - threshold) / span)


def confidence_from_margins(margins: list[float]) -> float:
    if not margins:
        return 0.5
    return round(0.5 + 0.5 * (sum(margins) / len(margins)), 4)


CONFIDENCE_BASIS = (
    "rule confidence is 0.5 exactly on the threshold and rises linearly to 1.0 when every "
    "clause of the rule is one full stated span past its own threshold, averaged over clauses"
)


def severity_for(confidence: float) -> str:
    for limit, name in SEVERITY_BANDS:
        if confidence < limit:
            return name
    return "CRITICAL"


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = float(len(text))
    return float(-sum((c / n) * math.log2(c / n) for c in counts.values()))


def flow_identifier(
    proto: int,
    src_ip: int | str,
    dst_ip: int | str,
    src_port: int,
    dst_port: int,
    window_start: float,
    window_end: float,
    directionality: str = "FWD_ONLY",
    completeness: bool = False,
) -> dict:
    return {
        "proto": PROTO_NAMES.get(proto, str(proto)),
        "src_ip": src_ip if isinstance(src_ip, str) else format_ip(src_ip),
        "dst_ip": dst_ip if isinstance(dst_ip, str) else format_ip(dst_ip),
        "src_port": int(src_port),
        "dst_port": int(dst_port),
        "directionality": directionality,
        "completeness_flag": bool(completeness),
        "window_start": float(window_start),
        "window_end": float(window_end),
        "window_start_ns": int(float(window_start) * 1e9),
        "window_end_ns": int(float(window_end) * 1e9),
    }


def flow_identifier_of(flow: FlowState, window_start: float, window_end: float) -> dict:
    if flow.pkts_fwd > 0 and flow.pkts_rev > 0:
        direction = "BIDIRECTIONAL"
    elif flow.pkts_rev > 0:
        direction = "REV_ONLY"
    else:
        direction = "FWD_ONLY"
    return flow_identifier(
        flow.key.proto,
        flow.initiator_ip,
        flow.responder_ip,
        flow.initiator_port,
        flow.responder_port,
        window_start,
        window_end,
        direction,
        flow.completeness_flag,
    )


def flow_features(flow: FlowState) -> dict[str, float]:
    pkts_fwd = float(flow.pkts_fwd)
    pkts_rev = float(flow.pkts_rev)
    return {
        "duration": float(flow.duration),
        "pkts_fwd": pkts_fwd,
        "pkts_rev": pkts_rev,
        "bytes_fwd": float(flow.bytes_fwd),
        "bytes_rev": float(flow.bytes_rev),
        "bytes_per_pkt_fwd": float(flow.bytes_fwd) / pkts_fwd if pkts_fwd else 0.0,
        "bytes_per_pkt_rev": float(flow.bytes_rev) / pkts_rev if pkts_rev else 0.0,
        "flags_seen_bitmap": float(flow.flags_seen),
        "completeness_flag": 1.0 if flow.completeness_flag else 0.0,
        "directionality": 1.0 if pkts_fwd and pkts_rev else 0.0,
        "initiator_is_lo": 1.0 if flow.initiator_ip == flow.key.lo_ip else 0.0,
        "orientation_confidence": float(flow.orientation_confidence),
    }


class LruMap:
    def __init__(
        self,
        capacity: int,
        factory: Callable[[], Any],
        entry_bytes: int = 0,
        on_evict: Callable[[Any, Any], None] | None = None,
    ) -> None:
        if capacity < 1:
            raise ValueError("capacity must be at least 1")
        self.capacity = int(capacity)
        self.factory = factory
        self.entry_bytes = int(entry_bytes) or _ODICT_ENTRY_BYTES
        self.on_evict = on_evict
        self.evicted = 0
        self._items: OrderedDict[Any, Any] = OrderedDict()

    def _trim(self) -> None:
        while len(self._items) > self.capacity:
            key, value = self._items.popitem(last=False)
            self.evicted += 1
            if self.on_evict is not None:
                self.on_evict(key, value)

    def get(self, key: Any) -> Any:
        item = self._items.get(key)
        if item is None:
            item = self.factory()
            self._items[key] = item
            self._trim()
        else:
            self._items.move_to_end(key)
        return item

    def put(self, key: Any, value: Any) -> Any:
        self._items[key] = value
        self._items.move_to_end(key)
        self._trim()
        return value

    def peek(self, key: Any) -> Any:
        return self._items.get(key)

    def drop(self, key: Any) -> None:
        self._items.pop(key, None)

    def items(self) -> Iterator[tuple[Any, Any]]:
        return iter(list(self._items.items()))

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, key: Any) -> bool:
        return key in self._items

    @property
    def nbytes(self) -> int:
        return len(self._items) * self.entry_bytes

    @property
    def capacity_bytes(self) -> int:
        return self.capacity * self.entry_bytes


class RotatingHLL:
    def __init__(self, window_s: float, m_bits: int = 10, seed: int = 0) -> None:
        self.window_ns = int(window_s * 1e9)
        self.m_bits = int(m_bits)
        self.seed = int(seed)
        self._epoch_ns = 0
        self._cur = HyperLogLog(self.m_bits, self.seed)
        self._prev = HyperLogLog(self.m_bits, self.seed)

    def _rotate(self, now_ns: int) -> None:
        if self._epoch_ns == 0:
            self._epoch_ns = now_ns
            return
        elapsed = now_ns - self._epoch_ns
        if elapsed < self.window_ns:
            return
        if elapsed >= 2 * self.window_ns:
            self._cur.clear()
            self._prev.clear()
        else:
            self._prev, self._cur = self._cur, self._prev
            self._cur.clear()
        self._epoch_ns = now_ns

    def add(self, now_ns: int, key: bytes) -> None:
        self._rotate(now_ns)
        self._cur.add(key)

    def count(self, now_ns: int) -> float:
        self._rotate(now_ns)
        return max(self._cur.count(), self._prev.count())

    @property
    def nbytes(self) -> int:
        return self._cur.nbytes + self._prev.nbytes


class WindowedHLLFamily:
    def __init__(self, window_s: float, m_bits: int = 6, capacity: int = 8192, seed: int = 0) -> None:
        self.window_s = float(window_s)
        self.window_ns = int(window_s * 1e9)
        self._epoch_ns = 0
        self._cur = HLLFamily(m_bits, capacity, seed)
        self._prev = HLLFamily(m_bits, capacity, seed)

    def _rotate(self, now_ns: int) -> None:
        if self._epoch_ns == 0:
            self._epoch_ns = now_ns
            return
        elapsed = now_ns - self._epoch_ns
        if elapsed < self.window_ns:
            return
        if elapsed >= 2 * self.window_ns:
            self._cur.clear()
            self._prev.clear()
        else:
            self._prev, self._cur = self._cur, self._prev
            self._cur.clear()
        self._epoch_ns = now_ns

    def add(self, now_ns: int, group: bytes, key: bytes) -> None:
        self._rotate(now_ns)
        self._cur.add(group, key)

    def count(self, now_ns: int, group: bytes) -> float:
        self._rotate(now_ns)
        return max(self._cur.count(group), self._prev.count(group))

    def __len__(self) -> int:
        return len(self._cur) + len(self._prev)

    @property
    def nbytes(self) -> int:
        return self._cur.nbytes + self._prev.nbytes

    @property
    def capacity_bytes(self) -> int:
        return self._cur.capacity_bytes + self._prev.capacity_bytes


class BigramModel:
    def __init__(self, blob: dict) -> None:
        self.alphabet = blob["alphabet"]
        self.start = blob["start_symbol"]
        self.end = blob["end_symbol"]
        self.index = {c: i for i, c in enumerate(self.alphabet)}
        self.size = len(self.alphabet)
        self.logp = [v for row in blob["logp"] for v in row]
        self.corpus = blob.get("corpus", {})
        self.version = blob.get("version", "0")
        self.floor = min(self.logp)

    def normalise(self, label: str) -> str:
        body = "".join(c if c in self.index and c not in (self.start, self.end) else "-"
                       for c in label.lower())
        return self.start + body + self.end

    def score(self, label: str) -> float:
        s = self.normalise(label)
        if len(s) < 2:
            return self.floor
        idx = self.index
        logp = self.logp
        size = self.size
        total = 0.0
        prev = idx[s[0]]
        for ch in s[1:]:
            cur = idx[ch]
            total += logp[prev * size + cur]
            prev = cur
        return total / (len(s) - 1)


class Reference:
    def __init__(self, directory: str = REFERENCE_DIR) -> None:
        self.directory = directory
        self.bigrams = self._bigrams()
        ja4 = self._json("ja4_tcp_reference.json", {"families": {}})
        self.ja4_families: dict[str, dict] = ja4.get("families", {})
        self.ja4_notes = {k: v for k, v in ja4.items() if k != "families"}
        dns = self._json("dns_reference.json", {"public_suffixes": [], "wildcard_domains": []})
        self.public_suffixes = frozenset(dns.get("public_suffixes", []))
        self.wildcard_domains = {row["domain"]: row.get("reason", "") for row in dns.get("wildcard_domains", [])}
        exfil = self._json("exfil_allowlist.json", {"entries": []})
        self.exfil_entries = [self._cidr(row) for row in exfil.get("entries", [])]

    def _json(self, name: str, fallback: dict) -> dict:
        path = os.path.join(self.directory, name)
        if not os.path.exists(path):
            return fallback
        with open(path, "r", encoding="ascii") as fh:
            return json.load(fh)

    def _bigrams(self) -> BigramModel | None:
        blob = self._json("domain_bigrams.json", {})
        return BigramModel(blob) if blob.get("logp") else None

    @staticmethod
    def _cidr(row: dict) -> tuple[int, int, frozenset, str]:
        net, _, bits = row["cidr"].partition("/")
        prefix = int(bits) if bits else 32
        mask = ((1 << prefix) - 1) << (32 - prefix) if prefix else 0
        base = 0
        for part in net.split("."):
            base = (base << 8) | int(part)
        return base & mask, mask, frozenset(row.get("ports", [])), row.get("reason", "")

    def registrable(self, qname: str) -> str:
        labels = qname.strip(".").lower().split(".")
        if len(labels) < 2:
            return qname
        if ".".join(labels[-2:]) in self.public_suffixes and len(labels) >= 3:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    def wildcard_reason(self, registrable: str) -> str:
        reason = self.wildcard_domains.get(registrable)
        if reason is not None:
            return reason
        for domain, why in self.wildcard_domains.items():
            if registrable.endswith("." + domain):
                return why
        return ""

    def ja4_expected(self, ja4: str) -> tuple[str, tuple[str, ...], float]:
        row = self.ja4_families.get(ja4)
        if row is None:
            return "", (), 0.0
        return row.get("label", ""), tuple(row.get("expected_tcp_families", ())), float(row.get("confidence", 0.0))

    def exfil_reason(self, dst_ip: int, dst_port: int) -> str:
        for base, mask, ports, reason in self.exfil_entries:
            if (dst_ip & mask) == base and (not ports or dst_port in ports):
                return reason
        return ""


class Context:
    def __init__(self, config: dict | None = None, reference: Reference | None = None) -> None:
        cfg = dict(DEFAULT_CONFIG)
        cfg.update(config or {})
        self.config = cfg
        self.reference = reference if reference is not None else Reference()
        self.now_ns = 0
        self.packets = 0
        self.suppressions: Counter = Counter()
        self.suppression_log: list[dict] = []
        self.scratch: dict[str, Any] = {}
        self.beacons = BeaconTable(
            capacity=int(cfg["beacon_capacity"]),
            ttl_s=float(cfg["beacon_ttl_s"]),
            ring=int(cfg["beacon_ring"]),
            min_samples=int(cfg["beacon_min_samples"]),
        )
        scan_cap = int(cfg["scan_hll_capacity"])
        scan_bits = int(cfg["scan_hll_m_bits"])
        self.scan_ports = {
            1.0: WindowedHLLFamily(1.0, scan_bits, max(1024, scan_cap // 2), seed=11),
            60.0: WindowedHLLFamily(60.0, scan_bits, scan_cap, seed=12),
            3600.0: WindowedHLLFamily(3600.0, scan_bits, scan_cap, seed=13),
        }
        self.scan_hosts = {
            1.0: WindowedHLLFamily(1.0, scan_bits, max(1024, scan_cap // 2), seed=21),
            60.0: WindowedHLLFamily(60.0, scan_bits, scan_cap, seed=22),
            3600.0: WindowedHLLFamily(3600.0, scan_bits, scan_cap, seed=23),
        }
        dns_cap = int(cfg["dns_hll_capacity"])
        dns_bits = int(cfg["dns_hll_m_bits"])
        self.dns_subdomains = WindowedHLLFamily(300.0, dns_bits, dns_cap, seed=31)
        self.dns_regdomains = WindowedHLLFamily(300.0, dns_bits, dns_cap, seed=32)

    def begin_packet(self, meta: PacketMeta, flow: FlowState) -> None:
        self.now_ns = meta.ts_ns
        self.packets += 1
        self.scratch.clear()

    def suppress(self, detector: str, reason: str, subject: str) -> None:
        self.suppressions[(detector, reason)] += 1
        if len(self.suppression_log) < 500:
            self.suppression_log.append(
                {"ts": self.now_ns / 1e9, "detector": detector, "reason": reason, "subject": subject}
            )

    def suppression_summary(self) -> list[dict]:
        return [
            {"detector": detector, "reason": reason, "count": int(count)}
            for (detector, reason), count in sorted(self.suppressions.items())
        ]

    def memory_bytes(self) -> dict[str, int]:
        scan = sum(f.nbytes for f in self.scan_ports.values())
        scan += sum(f.nbytes for f in self.scan_hosts.values())
        return {
            "beacon_table": int(self.beacons.nbytes),
            "scan_hll": int(scan),
            "dns_hll": int(self.dns_subdomains.nbytes + self.dns_regdomains.nbytes),
        }

    def memory_caps_bytes(self) -> dict[str, int]:
        scan = sum(f.capacity_bytes for f in self.scan_ports.values())
        scan += sum(f.capacity_bytes for f in self.scan_hosts.values())
        return {
            "beacon_table": int(self.beacons.capacity_bytes),
            "scan_hll": int(scan),
            "dns_hll": int(self.dns_subdomains.capacity_bytes + self.dns_regdomains.capacity_bytes),
        }

    @property
    def nbytes(self) -> int:
        return sum(self.memory_bytes().values())


class Detector:
    name = "detector"
    classes: list[str] = []

    def __init__(self, config: dict | None = None) -> None:
        self.config = dict(config or {})
        self.alerts = 0
        self._features: dict[str, float] = {}

    def observe(self, meta: PacketMeta, flow: FlowState, ctx: Context) -> list[Detection]:
        return []

    def tick(self, now_ns: int, ctx: Context) -> list[Detection]:
        return []

    def features(self) -> dict[str, float]:
        return dict(self._features)

    def stats(self) -> dict:
        return {"name": self.name, "alerts": self.alerts}

    @property
    def nbytes(self) -> int:
        return 0

    def _emit(
        self,
        ts_ns: int,
        threat_class: str,
        subtype: str,
        margins: list[float],
        flow: dict,
        evidence: list[Evidence],
        summary: str,
        context: dict | None = None,
    ) -> Detection:
        self.alerts += 1
        confidence = confidence_from_margins(margins)
        ctx = {
            "confidence_basis": CONFIDENCE_BASIS,
            "detector": self.name,
            "rule_margins": [round(float(m), 4) for m in margins],
        }
        ctx.update(context or {})
        return Detection(
            ts_ns=ts_ns,
            threat_class=threat_class,
            subtype=subtype,
            confidence=float(confidence),
            severity=severity_for(confidence),
            source="rule",
            flow=flow,
            evidence=evidence,
            summary=summary,
            context=ctx,
        )


def evidence(pairs: list[tuple[str, float, float]]) -> list[Evidence]:
    return [Evidence(feature=name, value=float(value), contribution=float(weight))
            for name, value, weight in pairs]


def entry_bytes_of(sample: Any) -> int:
    return sys.getsizeof(sample) + _ODICT_ENTRY_BYTES
