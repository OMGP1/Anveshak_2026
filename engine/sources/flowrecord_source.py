from __future__ import annotations

import csv
import ipaddress
import os
from typing import Iterator

from engine.decode.packet import ipv6_key
from engine.sources.base import ReplaySource, monotonic_ns
from engine.types import ACK, FIN, ICMP, PSH, RST, SYN, TCP, UDP, URG, PacketMeta

NS = 1_000_000_000

PROTO_NAMES = {"tcp": TCP, "udp": UDP, "icmp": ICMP, "6": TCP, "17": UDP, "1": ICMP}

FLAG_LETTERS = {"F": FIN, "S": SYN, "R": RST, "P": PSH, "A": ACK, "U": URG, ".": ACK}

REQUIRED_COLUMNS = ("src_ip", "dst_ip", "proto")


class FlowRecordSource(ReplaySource):
    def __init__(self, path: str) -> None:
        self.path = path
        self.name = os.path.basename(path)
        self.records_read = 0
        self.records_yielded = 0
        self.malformed = 0
        self.clamped = 0
        self.direction_hints: dict[str, int] = {}
        self.approximate_count = _count_rows(path)

    def __iter__(self) -> Iterator[PacketMeta]:
        self.records_read = 0
        self.records_yielded = 0
        self.malformed = 0
        self.clamped = 0
        self.direction_hints = {}
        last_ns = 0
        with open(self.path, "r", newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                self.records_read += 1
                meta = _row_to_meta(row)
                if meta is None:
                    self.malformed += 1
                    continue
                hint = (row.get("direction_hint") or "").strip().lower()
                if hint:
                    self.direction_hints[hint] = self.direction_hints.get(hint, 0) + 1
                clean = monotonic_ns(meta.ts_ns, last_ns)
                if clean != meta.ts_ns:
                    self.clamped += 1
                    meta = _retimed(meta, clean)
                last_ns = clean
                self.records_yielded += 1
                yield meta

    def stats(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "approximate_count": self.approximate_count,
            "records_read": self.records_read,
            "records_yielded": self.records_yielded,
            "malformed": self.malformed,
            "clamped": self.clamped,
            "direction_hints": dict(self.direction_hints),
        }


def _row_to_meta(row: dict) -> PacketMeta | None:
    if any(not (row.get(col) or "").strip() for col in REQUIRED_COLUMNS):
        return None
    try:
        src = ip_to_int(row["src_ip"])
        dst = ip_to_int(row["dst_ip"])
        proto = parse_proto(row["proto"])
    except (ValueError, KeyError):
        return None
    if src is None or dst is None or proto is None:
        return None
    start = _to_ns(row.get("ts_start"))
    end = _to_ns(row.get("ts_end"))
    ts_ns = end if end > start else start
    if ts_ns <= 0:
        return None
    packets = max(1, _to_int(row.get("packets"), 1))
    nbytes = max(0, _to_int(row.get("bytes"), 0))
    return PacketMeta(
        ts_ns=ts_ns,
        proto=proto,
        src_ip=src,
        dst_ip=dst,
        src_port=_to_int(row.get("src_port"), 0),
        dst_port=_to_int(row.get("dst_port"), 0),
        length=nbytes,
        tcp_flags=parse_flags(row.get("tcp_flags")),
        packets=packets,
        from_flow_record=True,
    )


def ip_to_int(text: str) -> int | None:
    value = text.strip()
    if not value:
        return None
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if addr.version == 4:
        return int(addr)
    return ipv6_key(addr.packed)


def parse_proto(text: str) -> int | None:
    value = text.strip().lower()
    if value in PROTO_NAMES:
        return PROTO_NAMES[value]
    try:
        return int(value)
    except ValueError:
        return None


def parse_flags(text: str | None) -> int:
    value = (text or "").strip()
    if not value:
        return 0
    try:
        return int(value, 0) & 0xFF
    except ValueError:
        pass
    flags = 0
    for letter in value.upper():
        flags |= FLAG_LETTERS.get(letter, 0)
    return flags


def _to_ns(text: str | None) -> int:
    value = (text or "").strip()
    if not value:
        return 0
    try:
        number = float(value)
    except ValueError:
        return 0
    if number <= 0:
        return 0
    if number > 1e17:
        return int(number)
    if number > 1e14:
        return int(number * 1000)
    if number > 1e11:
        return int(number * 1_000_000)
    return int(round(number * NS))


def _to_int(text: str | None, default: int) -> int:
    value = (text or "").strip()
    if not value:
        return default
    try:
        return int(float(value))
    except ValueError:
        return default


def _retimed(meta: PacketMeta, ts_ns: int) -> PacketMeta:
    return PacketMeta(
        ts_ns=ts_ns,
        proto=meta.proto,
        src_ip=meta.src_ip,
        dst_ip=meta.dst_ip,
        src_port=meta.src_port,
        dst_port=meta.dst_port,
        length=meta.length,
        tcp_flags=meta.tcp_flags,
        packets=meta.packets,
        from_flow_record=True,
    )


def _count_rows(path: str) -> int:
    with open(path, "r", newline="", encoding="utf-8") as fh:
        return max(0, sum(1 for _ in fh) - 1)
