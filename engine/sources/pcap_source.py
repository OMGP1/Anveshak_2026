from __future__ import annotations

import os
import struct
from decimal import Decimal
from typing import Iterator

import dpkt

from engine.decode.packet import parse_packet
from engine.sources.base import ReplaySource, monotonic_ns
from engine.types import PacketMeta

NS = 1_000_000_000
COUNT_SCAN_LIMIT = 5_000_000

PCAP_MAGICS = (0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1)
PCAPNG_MAGIC = 0x0A0D0D0A
PCAPNG_EPB = 6
PCAPNG_SPB = 3


class PcapSource(ReplaySource):
    def __init__(self, path: str) -> None:
        self.path = path
        self.name = os.path.basename(path)
        self.datalink = 0
        self.packets_read = 0
        self.packets_yielded = 0
        self.non_ip = 0
        self.clamped = 0
        with open(path, "rb") as fh:
            self.datalink = _open_reader(fh).datalink()
        self.approximate_count = _scan_count(path)

    def __iter__(self) -> Iterator[PacketMeta]:
        self.packets_read = 0
        self.packets_yielded = 0
        self.non_ip = 0
        self.clamped = 0
        last_ns = 0
        with open(self.path, "rb") as fh:
            reader = _open_reader(fh)
            divisor = getattr(reader, "_divisor", 1e6)
            linktype = reader.datalink()
            for ts, buf in reader:
                self.packets_read += 1
                ts_ns = _to_ns(ts, divisor)
                clean = monotonic_ns(ts_ns, last_ns)
                if clean != ts_ns:
                    self.clamped += 1
                last_ns = clean
                meta = parse_packet(clean, buf, linktype)
                if meta is None:
                    self.non_ip += 1
                    continue
                self.packets_yielded += 1
                yield meta

    def stats(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "datalink": self.datalink,
            "approximate_count": self.approximate_count,
            "packets_read": self.packets_read,
            "packets_yielded": self.packets_yielded,
            "non_ip": self.non_ip,
            "clamped": self.clamped,
        }


def _open_reader(fh) -> object:
    return dpkt.pcap.UniversalReader(fh)


def _to_ns(ts: object, divisor: object) -> int:
    if isinstance(ts, Decimal):
        return int(ts * NS)
    scale = float(divisor)
    step = NS / scale
    if step >= 1 and float(step).is_integer():
        return int(round(float(ts) * scale)) * int(step)
    return int(round(float(ts) * NS))


def _scan_count(path: str) -> int | None:
    with open(path, "rb") as fh:
        head = fh.read(4)
        if len(head) < 4:
            return 0
        magic_be = int.from_bytes(head, "big")
        magic_le = int.from_bytes(head, "little")
        if magic_le == PCAPNG_MAGIC or magic_be == PCAPNG_MAGIC:
            return _scan_pcapng(fh)
        if magic_be in PCAP_MAGICS or magic_le in PCAP_MAGICS:
            little = magic_le in (0xA1B2C3D4, 0xA1B23C4D)
            return _scan_pcap(fh, little)
    return None


def _scan_pcap(fh, little: bool) -> int:
    fh.seek(24)
    fmt = "<IIII" if little else ">IIII"
    count = 0
    while count < COUNT_SCAN_LIMIT:
        hdr = fh.read(16)
        if len(hdr) < 16:
            break
        caplen = struct.unpack(fmt, hdr)[2]
        if caplen > 0x400000:
            break
        fh.seek(caplen, os.SEEK_CUR)
        count += 1
    return count


def _scan_pcapng(fh) -> int:
    fh.seek(8)
    little = struct.unpack("<I", fh.read(4))[0] == 0x1A2B3C4D
    fh.seek(0)
    fmt = "<II" if little else ">II"
    count = 0
    while count < COUNT_SCAN_LIMIT:
        hdr = fh.read(8)
        if len(hdr) < 8:
            break
        block_type, block_len = struct.unpack(fmt, hdr)
        if block_len < 12 or block_len > 0x400000:
            break
        if block_type in (PCAPNG_EPB, PCAPNG_SPB):
            count += 1
        fh.seek(block_len - 8, os.SEEK_CUR)
    return count
