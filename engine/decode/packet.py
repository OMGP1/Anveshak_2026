from __future__ import annotations

import hashlib
import struct

import dpkt

from engine.decode.dns import parse_dns
from engine.decode.tls import parse_tls
from engine.types import ICMP, PacketMeta, TCP, UDP

DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW_BSD = 12
DLT_RAW_LINUX = 101
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_IPV4 = 228
DLT_IPV6 = 229

RAW_LINKTYPES = frozenset((DLT_RAW_BSD, DLT_RAW_LINUX, DLT_IPV4, DLT_IPV6))
NULL_LINKTYPES = frozenset((DLT_NULL, DLT_LOOP))

ETH_TYPE_IP4 = 0x0800
ETH_TYPE_IP6 = 0x86DD
ETH_TYPE_ARP = 0x0806
VLAN_TYPES = frozenset((0x8100, 0x88A8, 0x9100, 0x9200))
KNOWN_ETH_TYPES = frozenset((ETH_TYPE_IP4, ETH_TYPE_IP6, ETH_TYPE_ARP)) | VLAN_TYPES

TLS_PORTS = frozenset((443, 465, 587, 636, 853, 993, 995, 8443))
DNS_PORTS = frozenset((53, 5353, 5355))

OPT_EOL, OPT_NOP, OPT_MSS = 0, 1, 2

ICMP_REPLY_TO_REQUEST = {0: 8, 14: 13, 16: 15, 18: 17, 129: 128}

_PARSE_ERRORS = (dpkt.UnpackError, dpkt.NeedData, struct.error, IndexError, ValueError, KeyError)


def parse_packet(ts_ns: int, raw: bytes, linktype: int | None = None, *,
                 ipv4_only: bool = False) -> PacketMeta | None:
    try:
        ip = _network_layer(raw, linktype)
    except _PARSE_ERRORS:
        return None
    if ip is None or (ipv4_only and not isinstance(ip, dpkt.ip.IP)):
        return None
    if isinstance(ip, dpkt.ip.IP):
        src, dst = ipv4_key(ip.src), ipv4_key(ip.dst)
        ttl, proto = ip.ttl, ip.p
        length = ip.len or len(raw)
        headerless = bool(ip.offset)
    else:
        src, dst = ipv6_key(ip.src), ipv6_key(ip.dst)
        ttl, proto = ip.hlim, getattr(ip, "p", ip.nxt)
        length = 40 + ip.plen if ip.plen else len(raw)
        headerless = False

    src_port = dst_port = 0
    flags = window = mss = 0
    icmp_type = icmp_code = 0
    opts: tuple[int, ...] = ()
    payload = b""
    l4 = ip.data

    if headerless:
        pass
    elif proto == TCP and isinstance(l4, dpkt.tcp.TCP):
        src_port, dst_port = l4.sport, l4.dport
        flags = l4.flags & 0xFF
        window = l4.win
        opts, mss = tcp_options(bytes(l4.opts))
        payload = bytes(l4.data)
    elif proto == UDP and isinstance(l4, dpkt.udp.UDP):
        src_port, dst_port = l4.sport, l4.dport
        payload = bytes(l4.data)
    elif proto == ICMP and isinstance(l4, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
        icmp_type = icmp_request_type(l4.type & 0xFF)
        icmp_code = l4.code & 0xFF

    tls = None
    dns = None
    if payload:
        if proto == TCP and _looks_like_tls(payload, src_port, dst_port):
            tls = parse_tls(payload)
        elif src_port in DNS_PORTS or dst_port in DNS_PORTS:
            dns = parse_dns(payload)
    del payload

    return PacketMeta(
        ts_ns=ts_ns,
        proto=proto,
        src_ip=src,
        dst_ip=dst,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        tcp_flags=flags,
        ttl=ttl,
        tcp_window=window,
        tcp_mss=mss,
        tcp_opts=opts,
        icmp_type=icmp_type,
        icmp_code=icmp_code,
        tls=tls,
        dns=dns,
    )


def icmp_request_type(kind: int) -> int:
    return ICMP_REPLY_TO_REQUEST.get(kind, kind)


def tcp_options(buf: bytes) -> tuple[tuple[int, ...], int]:
    kinds: list[int] = []
    mss = 0
    i = 0
    n = len(buf)
    while i < n:
        kind = buf[i]
        if kind == OPT_EOL:
            kinds.append(OPT_EOL)
            break
        if kind == OPT_NOP:
            kinds.append(OPT_NOP)
            i += 1
            continue
        if i + 1 >= n:
            break
        size = buf[i + 1]
        if size < 2 or i + size > n:
            break
        kinds.append(kind)
        if kind == OPT_MSS and size == 4:
            mss = int.from_bytes(buf[i + 2:i + 4], "big")
        i += size
    return tuple(kinds), mss


def ipv4_key(addr: bytes) -> int:
    return int.from_bytes(addr, "big")


def ipv6_key(addr: bytes) -> int:
    return int.from_bytes(hashlib.blake2b(addr, digest_size=4).digest(), "big")


def format_ip(value: int) -> str:
    return "%d.%d.%d.%d" % ((value >> 24) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF)


def guess_linktype(raw: bytes) -> int:
    if len(raw) >= 14 and int.from_bytes(raw[12:14], "big") in KNOWN_ETH_TYPES:
        return DLT_EN10MB
    if _looks_like_raw_ip(raw):
        return DLT_RAW_LINUX
    return DLT_EN10MB


def _looks_like_raw_ip(raw: bytes) -> bool:
    if len(raw) < 20:
        return False
    version = raw[0] >> 4
    if version == 4:
        ihl = (raw[0] & 0x0F) * 4
        total = int.from_bytes(raw[2:4], "big")
        return ihl >= 20 and 20 <= total <= len(raw) + 4
    if version == 6 and len(raw) >= 40:
        return 40 + int.from_bytes(raw[4:6], "big") <= len(raw) + 4
    return False


def _network_layer(raw: bytes, linktype: int | None) -> object | None:
    if linktype is None:
        linktype = guess_linktype(raw)
    if linktype == DLT_EN10MB:
        return _ip_or_none(dpkt.ethernet.Ethernet(raw).data)
    if linktype in RAW_LINKTYPES:
        return _raw_ip(raw)
    if linktype in NULL_LINKTYPES:
        return _raw_ip(raw[4:])
    if linktype == DLT_LINUX_SLL:
        return _ip_or_none(dpkt.sll.SLL(raw).data)
    return None


def _raw_ip(raw: bytes) -> object | None:
    if not raw:
        return None
    version = raw[0] >> 4
    if version == 4:
        return dpkt.ip.IP(raw)
    if version == 6:
        return dpkt.ip6.IP6(raw)
    return None


def _ip_or_none(obj: object) -> object | None:
    return obj if isinstance(obj, (dpkt.ip.IP, dpkt.ip6.IP6)) else None


def _looks_like_tls(payload: bytes, src_port: int, dst_port: int) -> bool:
    if len(payload) < 6 or payload[0] != 0x16 or payload[1] != 0x03:
        return False
    return payload[5] in (1, 2) or src_port in TLS_PORTS or dst_port in TLS_PORTS
