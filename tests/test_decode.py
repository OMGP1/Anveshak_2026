from __future__ import annotations

import hashlib
import struct
import time

import dpkt
import pytest

from engine.decode.dns import parse_dns
from engine.decode.packet import DLT_EN10MB, DLT_RAW_LINUX, format_ip, ipv6_key, parse_packet
from engine.decode.tcp_fingerprint import fingerprint_family, initial_ttl, tcp_fingerprint
from engine.decode.tls import alpn_code, ja4_string, parse_tls
from engine.sources.flowrecord_source import FlowRecordSource
from engine.sources.pcap_source import PcapSource
from engine.sources.replay_clock import ReplayClock
from engine.types import ACK, FlowKey, PacketMeta, SYN, TCP, UDP

CLIENT_IP = b"\x0a\x14\x00\x07"
SERVER_IP = b"\x0a\x14\x04\x11"

SYN_OPTS = (
    b"\x02\x04\x05\xb4"
    b"\x04\x02"
    b"\x08\x0a\x11\x22\x33\x44\x00\x00\x00\x00"
    b"\x01"
    b"\x03\x03\x07"
)


def build_tcp(payload: bytes = b"", flags: int = dpkt.tcp.TH_SYN, opts: bytes = SYN_OPTS,
              sport: int = 51314, dport: int = 443, win: int = 64240) -> dpkt.tcp.TCP:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=1, ack=0, flags=flags, win=win)
    tcp.opts = opts
    tcp.off = (20 + len(opts)) // 4
    tcp.data = payload
    return tcp


def build_ipv4(l4: object, proto: int = 6, ttl: int = 64) -> dpkt.ip.IP:
    ip = dpkt.ip.IP(src=CLIENT_IP, dst=SERVER_IP, p=proto, ttl=ttl, data=l4)
    ip.len = 20 + len(bytes(l4))
    return ip


def build_frame(l3: object) -> bytes:
    eth_type = 0x86DD if isinstance(l3, dpkt.ip6.IP6) else 0x0800
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55", dst=b"\x66\x77\x88\x99\xaa\xbb", type=eth_type, data=l3
    )
    return bytes(eth)


def build_client_hello(sni: bytes = b"cdn.example.net") -> bytes:
    ciphers = [0x0A0A, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0x009C]
    cipher_bytes = b"".join(struct.pack(">H", c) for c in ciphers)

    sni_data = struct.pack(">HBH", len(sni) + 3, 0, len(sni)) + sni
    alpn_body = bytes([2]) + b"h2" + bytes([8]) + b"http/1.1"
    alpn_data = struct.pack(">H", len(alpn_body)) + alpn_body
    sig_list = b"".join(struct.pack(">H", s) for s in (0x0403, 0x0804, 0x0401, 0x0503))
    sig_data = struct.pack(">H", len(sig_list)) + sig_list
    versions = b"".join(struct.pack(">H", v) for v in (0x0A0A, 0x0304, 0x0303))
    ver_data = bytes([len(versions)]) + versions

    exts = [
        (0x1A1A, b""),
        (0x0000, sni_data),
        (0x0017, b""),
        (0x000D, sig_data),
        (0x0010, alpn_data),
        (0x002B, ver_data),
        (0x000B, b"\x01\x00"),
        (0x000A, b"\x00\x04\x00\x1d\x00\x17"),
    ]
    ext_bytes = b"".join(struct.pack(">HH", t, len(d)) + d for t, d in exts)

    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + struct.pack(">H", len(cipher_bytes))
        + cipher_bytes
        + b"\x01\x00"
        + struct.pack(">H", len(ext_bytes))
        + ext_bytes
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def build_dns_query(name: str, qtype: int) -> bytes:
    query = dpkt.dns.DNS(id=0x1234)
    query.qd = [dpkt.dns.DNS.Q(name=name, type=qtype, cls=1)]
    return bytes(query)


def test_syn_packet_roundtrip():
    raw = build_frame(build_ipv4(build_tcp()))
    meta = parse_packet(1_700_000_000_000_000_000, raw, DLT_EN10MB)
    assert meta is not None
    assert meta.proto == TCP
    assert meta.src_ip == int.from_bytes(CLIENT_IP, "big")
    assert meta.dst_ip == int.from_bytes(SERVER_IP, "big")
    assert meta.src_port == 51314 and meta.dst_port == 443
    assert meta.tcp_flags & SYN and not meta.tcp_flags & ACK
    assert meta.ttl == 64
    assert meta.tcp_window == 64240
    assert meta.tcp_mss == 1460
    assert meta.tcp_opts == (2, 4, 8, 1, 3)
    assert meta.length == 20 + 40
    assert meta.packets == 1 and meta.from_flow_record is False


def test_packet_meta_has_no_payload_field():
    assert "payload" not in PacketMeta.__slots__
    assert not any("payload" in name for name in PacketMeta.__slots__)


def test_non_ip_frame_is_dropped():
    arp = dpkt.ethernet.Ethernet(
        src=b"\x00\x11\x22\x33\x44\x55", dst=b"\xff" * 6, type=0x0806, data=b"\x00" * 28
    )
    assert parse_packet(1, bytes(arp), DLT_EN10MB) is None


def test_raw_ip_linktype_and_autodetect():
    raw = bytes(build_ipv4(build_tcp()))
    typed = parse_packet(5, raw, DLT_RAW_LINUX)
    guessed = parse_packet(5, raw)
    assert typed is not None and guessed is not None
    assert typed.src_port == guessed.src_port == 51314


def test_ipv6_addresses_are_hashed_into_int_fields():
    src = bytes.fromhex("20010db8000000000000000000000001")
    dst = bytes.fromhex("20010db8000000000000000000000002")
    tcp = build_tcp(flags=dpkt.tcp.TH_SYN)
    ip6 = dpkt.ip6.IP6(src=src, dst=dst, nxt=6, hlim=64, plen=len(bytes(tcp)), data=tcp)
    meta = parse_packet(9, build_frame(ip6), DLT_EN10MB)
    assert meta is not None
    assert meta.proto == TCP
    assert meta.src_ip == ipv6_key(src)
    assert meta.dst_ip == ipv6_key(dst)
    assert meta.src_ip != meta.dst_ip
    assert 0 <= meta.src_ip < 2 ** 32
    assert meta.ttl == 64
    assert meta.length == 40 + len(bytes(tcp))


def test_udp_dns_query_yields_dns_meta():
    payload = build_dns_query("mail.corp.example.com", 16)
    udp = dpkt.udp.UDP(sport=41234, dport=53, data=payload)
    udp.ulen = 8 + len(payload)
    meta = parse_packet(11, build_frame(build_ipv4(udp, proto=17)), DLT_EN10MB)
    assert meta is not None
    assert meta.proto == UDP
    assert meta.dns is not None
    assert meta.dns.qname == "mail.corp.example.com"
    assert meta.dns.qtype == 16
    assert meta.dns.qname_len == len("mail.corp.example.com")
    assert meta.dns.is_response is False
    assert meta.dns.answer_count == 0
    assert meta.tls is None


def build_dns_reply(name: str, rcode: int, answers: int = 0) -> bytes:
    dns = dpkt.dns.DNS()
    dns.id = 4242
    dns.qr = dpkt.dns.DNS_R
    dns.opcode = dpkt.dns.DNS_QUERY
    dns.rcode = rcode
    dns.qd = [dpkt.dns.DNS.Q(name=name, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN)]
    dns.an = []
    for _ in range(answers):
        answer = dpkt.dns.DNS.RR(name=name, type=dpkt.dns.DNS_A, cls=dpkt.dns.DNS_IN, ttl=60)
        answer.ip = bytes.fromhex("5db8d822")
        dns.an.append(answer)
    return bytes(dns)


@pytest.mark.parametrize("rcode,answers", [(3, 0), (0, 0), (0, 1)])
def test_dns_meta_separates_nxdomain_from_an_empty_noerror(rcode: int, answers: int):
    payload = build_dns_reply("shop.example.com", rcode, answers)
    udp = dpkt.udp.UDP(sport=53, dport=41234, data=payload)
    udp.ulen = 8 + len(payload)
    meta = parse_packet(12, build_frame(build_ipv4(udp, proto=17)), DLT_EN10MB)
    assert meta is not None and meta.dns is not None
    assert meta.dns.is_response is True
    assert meta.dns.rcode == rcode
    assert meta.dns.answer_count == answers


def build_icmp(kind: int, code: int = 0) -> dpkt.icmp.ICMP:
    echo = dpkt.icmp.ICMP.Echo(id=7, seq=1, data=b"payload-bytes")
    icmp = dpkt.icmp.ICMP(type=kind, code=code, data=echo)
    return icmp


def test_an_echo_request_and_its_reply_land_on_one_flow():
    request = parse_packet(1, build_frame(build_ipv4(build_icmp(8), proto=1)), DLT_EN10MB)
    reply_ip = dpkt.ip.IP(src=SERVER_IP, dst=CLIENT_IP, p=1, ttl=64, data=build_icmp(0))
    reply_ip.len = 20 + len(bytes(reply_ip.data))
    reply = parse_packet(2, build_frame(reply_ip), DLT_EN10MB)
    assert request is not None and reply is not None
    assert request.src_port == request.dst_port == 0
    assert reply.src_port == reply.dst_port == 0
    assert request.icmp_type == reply.icmp_type == 8
    assert FlowKey.of(request)[0] == FlowKey.of(reply)[0]
    assert FlowKey.of(request)[1] is not FlowKey.of(reply)[1]


def test_dns_over_tcp_length_prefix():
    payload = build_dns_query("tunnel.evil.example", 10)
    framed = struct.pack(">H", len(payload)) + payload
    dns = parse_dns(framed)
    assert dns is not None and dns.qname == "tunnel.evil.example"


def test_client_hello_yields_stable_ja4():
    hello = build_client_hello()
    tcp = build_tcp(payload=hello, flags=dpkt.tcp.TH_ACK | dpkt.tcp.TH_PUSH, opts=b"")
    meta = parse_packet(13, build_frame(build_ipv4(tcp)), DLT_EN10MB)
    assert meta is not None and meta.tls is not None
    tls = meta.tls
    assert tls.is_client_hello is True
    assert tls.sni_present is True
    assert tls.alpn == "h2"
    assert tls.version == 0x0304
    assert tls.ext_count == 7
    assert tls.ja4 == parse_tls(hello).ja4
    assert len(tls.ja4.split("_")) == 3


def test_ja4_matches_the_public_spec_by_hand():
    tls = parse_tls(build_client_hello())
    assert tls is not None
    head, cipher_hash, ext_hash = tls.ja4.split("_")
    assert head == "t13d0807h2"

    ciphers = "009c,1301,1302,1303,c02b,c02c,c02f,c030"
    exts = "000a,000b,000d,0017,002b"
    sigs = "0403,0804,0401,0503"
    assert cipher_hash == hashlib.sha256(ciphers.encode()).hexdigest()[:12]
    assert ext_hash == hashlib.sha256((exts + "_" + sigs).encode()).hexdigest()[:12]


def test_ja4_drops_grease_and_pads_counts():
    plain = ja4_string(0x0303, False, [0x1301], [0x002B], [], "")
    greased = ja4_string(0x0303, False, [0x0A0A, 0x1301], [0x1A1A, 0x002B], [0x2A2A], "")
    assert plain == greased
    assert plain.startswith("t12i0101")
    assert alpn_code("") == "00"
    assert alpn_code("h2") == "h2"
    assert alpn_code("http/1.1") == "h1"


def test_server_hello_is_marked_and_not_a_client_ja4():
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + b"\x13\x01"
        + b"\x00"
        + struct.pack(">H", 10)
        + struct.pack(">HH", 0x002B, 2) + b"\x03\x04"
        + struct.pack(">HH", 0x0033, 0)
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake
    tls = parse_tls(record)
    assert tls is not None
    assert tls.is_client_hello is False
    assert tls.ja4.startswith("t130200_1301_")


def test_tcp_fingerprint_from_syn_and_family():
    raw = build_frame(build_ipv4(build_tcp()))
    meta = parse_packet(17, raw, DLT_EN10MB)
    fp = tcp_fingerprint(meta)
    assert fp == "64:64240:1460:mss,sok,ts,nop,ws"
    assert fingerprint_family(fp) == "linux"

    win_opts = b"\x02\x04\x05\xb4\x01\x03\x03\x08\x01\x01\x04\x02"
    win_raw = build_frame(build_ipv4(build_tcp(opts=win_opts, win=8192), ttl=128))
    win_meta = parse_packet(18, win_raw, DLT_EN10MB)
    win_fp = tcp_fingerprint(win_meta)
    assert win_fp == "128:8192:1460:mss,nop,ws,nop,nop,sok"
    assert fingerprint_family(win_fp) == "windows"

    bsd_opts = b"\x02\x04\x05\xb4\x01\x03\x03\x06\x01\x01\x08\x0a\x00\x00\x00\x01\x00\x00\x00\x00\x04\x02\x00"
    bsd_raw = build_frame(build_ipv4(build_tcp(opts=bsd_opts, win=65535)))
    bsd_meta = parse_packet(19, bsd_raw, DLT_EN10MB)
    assert fingerprint_family(tcp_fingerprint(bsd_meta)) == "bsd"

    assert initial_ttl(52) == 64 and initial_ttl(200) == 255 and initial_ttl(30) == 32
    assert fingerprint_family("garbage") == "unknown"


def test_fingerprint_is_empty_for_non_syn():
    tcp = build_tcp(flags=dpkt.tcp.TH_ACK, opts=b"")
    meta = parse_packet(21, build_frame(build_ipv4(tcp)), DLT_EN10MB)
    assert tcp_fingerprint(meta) == ""


def test_pcap_source_replays_in_monotonic_nanoseconds(tmp_path):
    path = tmp_path / "demo.pcap"
    frames = [build_frame(build_ipv4(build_tcp())) for _ in range(3)]
    with open(path, "wb") as fh:
        writer = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
        writer.writepkt(frames[0], ts=1700000000.000000)
        writer.writepkt(frames[1], ts=1700000000.250000)
        writer.writepkt(frames[2], ts=1699999999.900000)

    source = PcapSource(str(path))
    assert source.approximate_count == 3
    assert source.name == "demo.pcap"
    metas = list(source)
    assert len(metas) == 3
    assert [m.ts_ns for m in metas] == sorted(m.ts_ns for m in metas)
    assert metas[0].ts_ns == 1_700_000_000_000_000_000
    assert metas[1].ts_ns == 1_700_000_000_250_000_000
    assert metas[2].ts_ns == metas[1].ts_ns
    assert source.clamped == 1
    assert list(source) == metas


def test_pcap_source_skips_non_ip(tmp_path):
    path = tmp_path / "mixed.pcap"
    arp = bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\xff" * 6, type=0x0806, data=b"\x00" * 28))
    with open(path, "wb") as fh:
        writer = dpkt.pcap.Writer(fh, linktype=dpkt.pcap.DLT_EN10MB)
        writer.writepkt(arp, ts=1700000000.0)
        writer.writepkt(build_frame(build_ipv4(build_tcp())), ts=1700000000.1)
    source = PcapSource(str(path))
    metas = list(source)
    assert len(metas) == 1
    assert source.non_ip == 1 and source.packets_read == 2


def test_flow_record_row_becomes_packet_meta(tmp_path):
    path = tmp_path / "flows.csv"
    path.write_text(
        "ts_start,ts_end,src_ip,dst_ip,src_port,dst_port,proto,packets,bytes,tcp_flags,direction_hint\n"
        "1700000000.0,1700000002.5,10.20.0.7,10.20.4.17,51314,443,6,12,8400,0x12,egress\n"
        "1700000003.0,1700000004.0,10.20.0.9,8.8.8.8,53000,53,udp,2,180,,ingress\n",
        encoding="utf-8",
    )
    source = FlowRecordSource(str(path))
    assert source.approximate_count == 2
    metas = list(source)
    assert len(metas) == 2

    first = metas[0]
    assert first.from_flow_record is True
    assert first.packets == 12
    assert first.length == 8400
    assert first.proto == TCP
    assert first.src_ip == (10 << 24) + (20 << 16) + 7
    assert first.src_port == 51314 and first.dst_port == 443
    assert first.tcp_flags == (SYN | ACK)
    assert first.ts_ns == 1_700_000_002_500_000_000
    assert first.tls is None and first.dns is None

    second = metas[1]
    assert second.proto == UDP and second.packets == 2 and second.tcp_flags == 0
    assert format_ip(second.dst_ip) == "8.8.8.8"
    assert source.direction_hints == {"egress": 1, "ingress": 1}
    assert [m.ts_ns for m in metas] == sorted(m.ts_ns for m in metas)


def test_flow_record_skips_malformed_rows(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text(
        "ts_start,ts_end,src_ip,dst_ip,src_port,dst_port,proto,packets,bytes,tcp_flags\n"
        "1700000000.0,1700000001.0,not-an-ip,10.0.0.1,1,2,6,1,60,S\n"
        "1700000001.0,1700000002.0,10.0.0.2,10.0.0.1,1,2,tcp,1,60,S\n",
        encoding="utf-8",
    )
    source = FlowRecordSource(str(path))
    metas = list(source)
    assert len(metas) == 1 and source.malformed == 1
    assert metas[0].tcp_flags == SYN


def test_replay_clock_virtual_does_not_sleep():
    clock = ReplayClock(speed=1.0, mode="virtual")
    start = time.perf_counter()
    base = 1_700_000_000_000_000_000
    for i in range(5):
        clock.wait_until(base + i * 1_000_000_000)
    assert time.perf_counter() - start < 0.05
    assert clock.sleeps == 0
    assert clock.capture_elapsed_s == pytest.approx(4.0)


def test_replay_clock_realtime_honours_speed_multiplier():
    base = 1_700_000_000_000_000_000
    fast = ReplayClock(speed=100.0, mode="realtime")
    start = time.perf_counter()
    fast.wait_until(base)
    fast.wait_until(base + 2_000_000_000)
    fast_elapsed = time.perf_counter() - start

    slow = ReplayClock(speed=10.0, mode="realtime")
    start = time.perf_counter()
    slow.wait_until(base)
    slow.wait_until(base + 2_000_000_000)
    slow_elapsed = time.perf_counter() - start

    assert fast_elapsed == pytest.approx(0.02, abs=0.05)
    assert slow_elapsed == pytest.approx(0.2, abs=0.08)
    assert slow_elapsed > fast_elapsed
    assert slow.sleeps == 1


def test_replay_clock_rejects_bad_mode_and_speed():
    with pytest.raises(ValueError):
        ReplayClock(mode="turbo")
    with pytest.raises(ValueError):
        ReplayClock(speed=0.0)
