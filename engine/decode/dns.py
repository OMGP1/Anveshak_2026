from __future__ import annotations

import struct

import dpkt

from engine.types import DNSMeta

MAX_DNS_BYTES = 4096

_DECODE_ERRORS = (dpkt.UnpackError, dpkt.NeedData, struct.error, IndexError, ValueError)


def parse_dns(payload: bytes) -> DNSMeta | None:
    if not payload or len(payload) < 12:
        return None
    buf = payload[:MAX_DNS_BYTES]
    msg = None
    if len(payload) > 2 and int.from_bytes(payload[:2], "big") == len(payload) - 2:
        msg = _decode(buf[2:])
    if msg is None:
        msg = _decode(buf)
    if msg is None and len(buf) > 2:
        msg = _decode(buf[2:])
    if msg is None:
        return None
    qname = ""
    qtype = 0
    if msg.qd:
        qname = _clean_name(msg.qd[0].name)
        qtype = int(msg.qd[0].type)
    elif not msg.an:
        return None
    return DNSMeta(
        qname=qname,
        qtype=qtype,
        qname_len=len(qname),
        is_response=bool(msg.qr),
        answer_count=len(msg.an),
        rcode=int(getattr(msg, "rcode", 0) or 0),
    )


def _decode(buf: bytes) -> dpkt.dns.DNS | None:
    try:
        return dpkt.dns.DNS(buf)
    except _DECODE_ERRORS:
        return None


def _clean_name(name: object) -> str:
    text = name.decode("utf-8", "replace") if isinstance(name, bytes) else str(name)
    return text.rstrip(".").lower()
