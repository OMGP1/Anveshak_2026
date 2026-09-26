from __future__ import annotations

import hashlib
import json
import os
import random
import struct
import sys

import dpkt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
if os.path.join(ROOT, "training") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "training"))

import scenarios as catalogue
from engine.types import ACK, FIN, PSH, RST, SYN, TCP, UDP

OUT_DIR = os.path.join(ROOT, "data", "scenarios")
BASE_TS_US = 1788775200_000_000
US = 1_000_000
MIN_GAP_US = 8
IDLE_TIMEOUT_US = 60 * US
ACTIVE_TIMEOUT_US = 120 * US
ETH_IPV4 = 0x0800
GW_MAC = b"\x02\x00\x00\x00\x00\x01"
INTERNAL_PREFIX = "10.20."

OS_PROFILES = {
    "windows": {
        "ttl": 128,
        "win": 65535,
        "mss": 1460,
        "opts": [("mss", 1460), ("nop",), ("ws", 8), ("nop",), ("nop",), ("sok",)],
        "tls": "chrome-windows",
    },
    "linux": {
        "ttl": 64,
        "win": 64240,
        "mss": 1460,
        "opts": [("mss", 1460), ("sok",), ("ts",), ("nop",), ("ws", 7)],
        "tls": "firefox-linux",
    },
    "macos": {
        "ttl": 64,
        "win": 65535,
        "mss": 1460,
        "opts": [("mss", 1460), ("nop",), ("ws", 6), ("nop",), ("nop",), ("ts",), ("sok",), ("eol",)],
        "tls": "safari-macos",
    },
}

GREASE = 0x0A0A

TLS_PROFILES = {
    "chrome-windows": {
        "ciphers": [
            GREASE, 0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030,
            0xCCA9, 0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
        ],
        "exts": [GREASE, 0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 21],
        "groups": [GREASE, 0x001D, 0x0017, 0x0018],
        "sigalgs": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        "alpn": ["h2", "http/1.1"],
        "pad_to": 517,
    },
    "firefox-linux": {
        "ciphers": [
            0x1301, 0x1303, 0x1302, 0xC02B, 0xC02F, 0xCCA9, 0xCCA8, 0xC02C,
            0xC030, 0xC00A, 0xC009, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
        ],
        "exts": [0, 23, 65281, 10, 11, 35, 16, 5, 34, 51, 43, 13, 45, 28],
        "groups": [0x001D, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101],
        "sigalgs": [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601],
        "alpn": ["h2", "http/1.1"],
        "pad_to": 0,
    },
    "safari-macos": {
        "ciphers": [
            GREASE, 0x1301, 0x1302, 0x1303, 0xC02C, 0xC02B, 0xCCA9, 0xC030,
            0xC02F, 0xCCA8, 0xC00A, 0xC009, 0xC014, 0xC013, 0x009D, 0x009C, 0x0035, 0x002F,
        ],
        "exts": [GREASE, 0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 21],
        "groups": [GREASE, 0x001D, 0x0017, 0x0018, 0x0019],
        "sigalgs": [0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0805, 0x0805, 0x0501],
        "alpn": ["h2", "http/1.1"],
        "pad_to": 517,
    },
}

WORDS = [
    "silver", "harbor", "meadow", "copper", "lantern", "willow", "marble", "amber", "cedar",
    "falcon", "granite", "hollow", "ivory", "juniper", "kettle", "lumber", "mandrel", "nimbus",
    "orchard", "pebble", "quarry", "ridge", "saddle", "timber", "umber", "velvet", "walnut",
    "yonder", "zephyr", "anchor", "bramble", "canvas", "dapple", "ember", "fathom", "gable",
    "hearth", "inlet", "jasper", "kindle", "lattice", "mortar", "notch", "opal", "prairie",
    "quiver", "rafter", "sable", "thistle", "upland", "vessel", "wicker", "yarrow", "bronze",
]

BRANDS = [
    "northwind", "contoso", "fabrikam", "adventureworks", "tailspin", "litware", "proseware",
    "woodgrove", "wingtip", "lucerne", "fourthcoffee", "alpineski", "blueyonder", "cohovineyard",
    "fasttrack", "humongous", "margiestravel", "nodpublishers", "olympicsports", "parnell",
    "relecloud", "southridge", "treyresearch", "vanarsdel", "wideworldimporters", "graphicdesign",
]

HOSTNAMES = ["www", "cdn", "api", "mail", "static", "assets", "img", "login", "docs", "portal",
             "update", "files", "edge", "media"]

TLDS = [".com", ".net", ".org", ".co.in", ".io"]

BASE32 = "abcdefghijklmnopqrstuvwxyz234567"


def ip_to_bytes(addr: str) -> bytes:
    return bytes(int(p) for p in addr.split("."))


def is_internal(addr: str) -> bool:
    return addr.startswith(INTERNAL_PREFIX)


def mac_of(addr: str) -> bytes:
    return b"\x02\x00" + ip_to_bytes(addr) if is_internal(addr) else GW_MAC


def _u8(n: int) -> bytes:
    return struct.pack("!B", n)


def _u16(n: int) -> bytes:
    return struct.pack("!H", n)


def _u24(n: int) -> bytes:
    return struct.pack("!I", n)[1:]


def encode_tcp_opts(spec: list[tuple], tsval: int = 0, tsecr: int = 0) -> bytes:
    out = b""
    for opt in spec:
        kind = opt[0]
        if kind == "mss":
            out += b"\x02\x04" + _u16(opt[1])
        elif kind == "nop":
            out += b"\x01"
        elif kind == "sok":
            out += b"\x04\x02"
        elif kind == "ts":
            out += b"\x08\x0a" + struct.pack("!II", tsval & 0xFFFFFFFF, tsecr & 0xFFFFFFFF)
        elif kind == "ws":
            out += b"\x03\x03" + _u8(opt[1])
        elif kind == "eol":
            out += b"\x00"
    while len(out) % 4:
        out += b"\x00"
    return out


class Capture:
    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)
        self.seed = seed
        self.events: list[dict] = []
        self.packets: list[tuple[int, bytes]] = []
        self.records: list[dict] = []

    def add(self, ts_us: int, frame: bytes, proto: int, src: str, dst: str,
            sport: int, dport: int, ip_len: int, flags: int = 0) -> None:
        self.events.append({"ts_us": int(ts_us), "frame": frame, "proto": proto, "src_ip": src,
                            "dst_ip": dst, "src_port": sport, "dst_port": dport,
                            "bytes": ip_len, "tcp_flags": flags})

    def tcp(self, ts_us: int, src: str, dst: str, sport: int, dport: int, flags: int,
            seq: int, ack: int, win: int, opts: bytes = b"", payload_len: int = 0,
            ttl: int = 64, payload: bytes | None = None) -> None:
        body = payload if payload is not None else b"\x00" * payload_len
        seg = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq & 0xFFFFFFFF, ack=ack & 0xFFFFFFFF,
                           win=win, data=body)
        seg.opts = opts
        seg.off = (20 + len(opts)) // 4
        seg.flags = flags
        pkt = dpkt.ip.IP(src=ip_to_bytes(src), dst=ip_to_bytes(dst), p=TCP, ttl=ttl,
                         id=self.rng.getrandbits(16), data=seg)
        frame = bytes(dpkt.ethernet.Ethernet(src=mac_of(src), dst=mac_of(dst), type=ETH_IPV4,
                                             data=pkt))
        self.add(ts_us, frame, TCP, src, dst, sport, dport, pkt.len, flags)

    def udp(self, ts_us: int, src: str, dst: str, sport: int, dport: int,
            payload: bytes, ttl: int = 64) -> None:
        seg = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
        seg.ulen = 8 + len(payload)
        pkt = dpkt.ip.IP(src=ip_to_bytes(src), dst=ip_to_bytes(dst), p=UDP, ttl=ttl,
                         id=self.rng.getrandbits(16), data=seg)
        frame = bytes(dpkt.ethernet.Ethernet(src=mac_of(src), dst=mac_of(dst), type=ETH_IPV4,
                                             data=pkt))
        self.add(ts_us, frame, UDP, src, dst, sport, dport, pkt.len, 0)

    def finish(self) -> tuple[list[tuple[int, bytes]], list[dict]]:
        order = sorted(range(len(self.events)), key=lambda i: (self.events[i]["ts_us"], i))
        last = -1
        for i in order:
            ev = self.events[i]
            if ev["ts_us"] <= last:
                ev["ts_us"] = last + MIN_GAP_US
            last = ev["ts_us"]
        self.packets = [(self.events[i]["ts_us"], self.events[i]["frame"]) for i in order]
        self.records = self._aggregate(order)
        return self.packets, self.records

    def _aggregate(self, order: list[int]) -> list[dict]:
        open_recs: dict[tuple, dict] = {}
        done: list[dict] = []
        for i in order:
            ev = self.events[i]
            ts = ev["ts_us"]
            key = (ev["proto"], ev["src_ip"], ev["dst_ip"], ev["src_port"], ev["dst_port"])
            rec = open_recs.get(key)
            if rec is not None and (ts - rec["ts_end_us"] > IDLE_TIMEOUT_US
                                    or ts - rec["ts_start_us"] > ACTIVE_TIMEOUT_US):
                done.append(rec)
                rec = None
            if rec is None:
                hint = ("egress" if is_internal(ev["src_ip"])
                        else ("ingress" if is_internal(ev["dst_ip"]) else ""))
                rec = {"ts_start_us": ts, "ts_end_us": ts, "src_ip": ev["src_ip"],
                       "dst_ip": ev["dst_ip"], "src_port": ev["src_port"],
                       "dst_port": ev["dst_port"], "proto": ev["proto"], "packets": 0,
                       "bytes": 0, "tcp_flags": 0, "direction_hint": hint}
                open_recs[key] = rec
            rec["ts_end_us"] = ts
            rec["packets"] += 1
            rec["bytes"] += ev["bytes"]
            rec["tcp_flags"] |= ev["tcp_flags"]
        done.extend(open_recs.values())
        done.sort(key=lambda r: (r["ts_start_us"], r["src_ip"], r["dst_ip"],
                                 r["src_port"], r["dst_port"], r["proto"]))
        return done


def tls_client_hello(rng: random.Random, sni: str, profile_name: str) -> bytes:
    p = TLS_PROFILES[profile_name]
    ext_blob = b""
    for etype in p["exts"]:
        body = _ext_body(etype, p, sni)
        ext_blob += _u16(etype) + _u16(len(body)) + body
    hs_body = (_u16(0x0303) + rng.randbytes(32) + _u8(32) + rng.randbytes(32)
               + _u16(len(p["ciphers"]) * 2) + b"".join(_u16(c) for c in p["ciphers"])
               + _u8(1) + b"\x00")
    pad_to = p["pad_to"]
    if pad_to:
        fixed = 5 + 4 + len(hs_body) + 2 + len(ext_blob)
        need = pad_to - fixed - 4
        if need > 0:
            ext_blob += _u16(21) + _u16(need) + b"\x00" * need
    hs_body += _u16(len(ext_blob)) + ext_blob
    hs = b"\x01" + _u24(len(hs_body)) + hs_body
    return b"\x16\x03\x01" + _u16(len(hs)) + hs


def _ext_body(etype: int, p: dict, sni: str) -> bytes:
    if etype == 0:
        host = sni.encode()
        return _u16(len(host) + 3) + b"\x00" + _u16(len(host)) + host
    if etype == 10:
        return _u16(len(p["groups"]) * 2) + b"".join(_u16(g) for g in p["groups"])
    if etype == 11:
        return b"\x01\x00"
    if etype == 13:
        return _u16(len(p["sigalgs"]) * 2) + b"".join(_u16(a) for a in p["sigalgs"])
    if etype == 16:
        body = b"".join(_u8(len(a)) + a.encode() for a in p["alpn"])
        return _u16(len(body)) + body
    if etype == 5:
        return b"\x01\x00\x00\x00\x00"
    if etype == 43:
        vers = [GREASE, 0x0304, 0x0303] if GREASE in p["exts"] else [0x0304, 0x0303]
        return _u8(len(vers) * 2) + b"".join(_u16(v) for v in vers)
    if etype == 45:
        return b"\x01\x01"
    if etype == 51:
        key = b"\x00" * 32
        return _u16(38) + _u16(0x001D) + _u16(32) + key
    if etype == 27:
        return b"\x02\x00\x02"
    if etype == 28:
        return _u16(16385)
    if etype == 34:
        return b"\x02\x04\x03"
    if etype == 21:
        return b""
    return b""


def tls_server_hello(rng: random.Random, cipher: int) -> bytes:
    exts = _u16(43) + _u16(2) + _u16(0x0304)
    exts += _u16(51) + _u16(36) + _u16(0x001D) + _u16(32) + b"\x00" * 32
    body = (_u16(0x0303) + rng.randbytes(32) + _u8(32) + rng.randbytes(32)
            + _u16(cipher) + b"\x00" + _u16(len(exts)) + exts)
    hs = b"\x02" + _u24(len(body)) + body
    return b"\x16\x03\x03" + _u16(len(hs)) + hs


def dns_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if label:
            out += _u8(len(label)) + label.encode()
    return out + b"\x00"


def dns_query(txid: int, qname: str, qtype: int) -> bytes:
    return (_u16(txid) + _u16(0x0100) + _u16(1) + _u16(0) + _u16(0) + _u16(0)
            + dns_name(qname) + _u16(qtype) + _u16(1))


def dns_response(txid: int, qname: str, qtype: int, rdatas: list[bytes], rcode: int = 0,
                 ttl: int = 300) -> bytes:
    head = (_u16(txid) + _u16(0x8180 | rcode) + _u16(1) + _u16(len(rdatas)) + _u16(0) + _u16(0)
            + dns_name(qname) + _u16(qtype) + _u16(1))
    for rd in rdatas:
        head += dns_name(qname) + _u16(qtype) + _u16(1) + struct.pack("!I", ttl) + _u16(len(rd)) + rd
    return head


def txt_rdata(text: bytes) -> bytes:
    out = b""
    while text:
        chunk, text = text[:255], text[255:]
        out += _u8(len(chunk)) + chunk
    return out


class Env:
    def __init__(self, rng: random.Random) -> None:
        self.rng = rng
        self.resolver = "10.20.0.53"
        self.web = "10.20.4.17"
        self.app = "10.20.4.25"
        self.hosts: list[dict] = []
        for i in range(40):
            ip = f"10.20.{1 + i // 12}.{10 + i % 12}"
            roll = rng.random()
            osname = "windows" if roll < 0.6 else ("linux" if roll < 0.9 else "macos")
            self.hosts.append({"ip": ip, "os": osname, "tls": OS_PROFILES[osname]["tls"]})
        self.servers = []
        for block in ("93.184.216", "151.101.65", "142.250.183", "104.18.22", "13.107.42", "23.45.109"):
            for k in range(10):
                self.servers.append(f"{block}.{3 + k * 7}")
        self.domains = []
        for k in range(120):
            host = HOSTNAMES[k % len(HOSTNAMES)]
            brand = BRANDS[(k * 7) % len(BRANDS)]
            tld = TLDS[(k * 3) % len(TLDS)]
            self.domains.append((f"{host}.{brand}{tld}", self.servers[k % len(self.servers)]))
        for h in self.hosts:
            picks = sorted(rng.sample(range(len(self.domains)), 9))
            h["sites"] = [self.domains[i] for i in picks]

    def host_by_ip(self, ip: str) -> dict:
        for h in self.hosts:
            if h["ip"] == ip:
                return h
        raise KeyError(ip)


class Conn:
    def __init__(self, cap: Capture, client: str, server: str, dport: int, osname: str,
                 hops: int = 12) -> None:
        self.cap = cap
        self.client = client
        self.server = server
        self.dport = dport
        self.sport = cap.rng.randint(32768, 60999)
        self.prof = OS_PROFILES[osname]
        self.cseq = cap.rng.getrandbits(31)
        self.sseq = cap.rng.getrandbits(31)
        self.ttl_out = self.prof["ttl"]
        self.ttl_in = 64 - hops
        self.opts = encode_tcp_opts(self.prof["opts"], tsval=cap.rng.getrandbits(30))
        self.win = self.prof["win"]

    def handshake(self, t: int, rtt: int) -> int:
        self.cap.tcp(t, self.client, self.server, self.sport, self.dport, SYN, self.cseq, 0,
                     self.win, opts=self.opts, ttl=self.ttl_out)
        t += rtt // 2
        self.cap.tcp(t, self.server, self.client, self.dport, self.sport, SYN | ACK, self.sseq,
                     self.cseq + 1, 64240,
                     opts=encode_tcp_opts(OS_PROFILES["linux"]["opts"], tsval=self.cap.rng.getrandbits(30)),
                     ttl=self.ttl_in)
        t += rtt // 2
        self.cseq += 1
        self.sseq += 1
        self.cap.tcp(t, self.client, self.server, self.sport, self.dport, ACK, self.cseq,
                     self.sseq, self.win, ttl=self.ttl_out)
        return t

    def up(self, t: int, nbytes: int, payload: bytes | None = None, flags: int = PSH | ACK) -> int:
        self.cap.tcp(t, self.client, self.server, self.sport, self.dport, flags, self.cseq,
                     self.sseq, self.win, payload_len=nbytes, payload=payload, ttl=self.ttl_out)
        self.cseq += len(payload) if payload is not None else nbytes
        return t

    def down(self, t: int, nbytes: int, payload: bytes | None = None,
             flags: int = PSH | ACK) -> int:
        self.cap.tcp(t, self.server, self.client, self.dport, self.sport, flags, self.sseq,
                     self.cseq, 64240, payload_len=nbytes, payload=payload, ttl=self.ttl_in)
        self.sseq += len(payload) if payload is not None else nbytes
        return t

    def ack_up(self, t: int) -> int:
        self.cap.tcp(t, self.client, self.server, self.sport, self.dport, ACK, self.cseq,
                     self.sseq, self.win, ttl=self.ttl_out)
        return t

    def close(self, t: int, rtt: int) -> int:
        self.cap.tcp(t, self.client, self.server, self.sport, self.dport, FIN | ACK, self.cseq,
                     self.sseq, self.win, ttl=self.ttl_out)
        self.cseq += 1
        t += rtt // 2
        self.cap.tcp(t, self.server, self.client, self.dport, self.sport, FIN | ACK, self.sseq,
                     self.cseq, 64240, ttl=self.ttl_in)
        self.sseq += 1
        t += rtt // 2
        self.cap.tcp(t, self.client, self.server, self.sport, self.dport, ACK, self.cseq,
                     self.sseq, self.win, ttl=self.ttl_out)
        return t


def tls_session(cap: Capture, host: dict, server: str, sni: str, t: int,
                exchanges: int, tls_profile: str | None = None,
                tcp_os: str | None = None) -> int:
    rng = cap.rng
    rtt = rng.randint(9000, 42000)
    conn = Conn(cap, host["ip"], server, 443, tcp_os or host["os"], hops=rng.randint(6, 17))
    t = conn.handshake(t, rtt)
    t += rng.randint(1000, 9000)
    ch = tls_client_hello(rng, sni, tls_profile or host["tls"])
    conn.up(t, len(ch), payload=ch)
    t += rtt
    sh = tls_server_hello(rng, 0x1301)
    conn.down(t, len(sh), payload=sh)
    t += rng.randint(400, 3000)
    conn.down(t, rng.randint(700, 1400))
    t += rng.randint(200, 1500)
    conn.down(t, rng.randint(300, 900))
    t += rtt // 2
    conn.up(t, rng.randint(70, 130))
    t += rtt // 2
    conn.down(t, rng.randint(60, 110))
    for _ in range(exchanges):
        t += rng.randint(15000, 260000)
        conn.up(t, rng.randint(180, 900))
        t += rtt
        chunks = rng.randint(1, 3)
        for _c in range(chunks):
            t += rng.randint(600, 6000)
            conn.down(t, rng.choice([1400, rng.randint(180, 1100), rng.randint(180, 700)]))
        t += rng.randint(2000, 12000)
        conn.ack_up(t)
    t += rng.randint(20000, 180000)
    return conn.close(t, rtt)


def http_session(cap: Capture, host: dict, server: str, t: int) -> int:
    rng = cap.rng
    rtt = rng.randint(9000, 42000)
    conn = Conn(cap, host["ip"], server, 80, host["os"], hops=rng.randint(6, 17))
    t = conn.handshake(t, rtt)
    t += rng.randint(500, 6000)
    conn.up(t, rng.randint(320, 620))
    t += rtt
    for _c in range(rng.randint(2, 6)):
        conn.down(t, rng.choice([1400, rng.randint(200, 1300), rng.randint(180, 800)]))
        t += rng.randint(500, 5000)
    conn.ack_up(t)
    t += rng.randint(30000, 200000)
    return conn.close(t, rtt)


def bulk_session(cap: Capture, host: dict, server: str, t: int) -> int:
    rng = cap.rng
    rtt = rng.randint(9000, 42000)
    conn = Conn(cap, host["ip"], server, 443, host["os"], hops=rng.randint(6, 17))
    t = conn.handshake(t, rtt)
    ch = tls_client_hello(rng, host["sites"][0][0], host["tls"])
    t += rng.randint(1000, 6000)
    conn.up(t, len(ch), payload=ch)
    t += rtt
    conn.down(t, len(tls_server_hello(rng, 0x1301)))
    t += rng.randint(3000, 20000)
    conn.up(t, rng.randint(200, 500))
    down = rng.randint(16, 28)
    for i in range(down):
        t += rng.randint(700, 4000)
        conn.down(t, 1400)
        if i % 3 == 2:
            conn.ack_up(t + 300)
    t += rng.randint(20000, 90000)
    return conn.close(t, rtt)


def dns_lookup(cap: Capture, env: Env, host: dict, t: int, qname: str, answer: str) -> int:
    rng = cap.rng
    txid = rng.getrandbits(16)
    sport = rng.randint(32768, 60999)
    cap.udp(t, host["ip"], env.resolver, sport, 53, dns_query(txid, qname, 1),
            ttl=OS_PROFILES[host["os"]]["ttl"])
    t += rng.randint(1200, 26000)
    cap.udp(t, env.resolver, host["ip"], 53, sport,
            dns_response(txid, qname, 1, [ip_to_bytes(answer)]), ttl=64)
    return t


def ntp_sync(cap: Capture, env: Env, host: dict, t: int) -> int:
    rng = cap.rng
    sport = rng.randint(32768, 60999)
    cap.udp(t, host["ip"], "162.159.200.1", sport, 123, b"\x23" + b"\x00" * 47,
            ttl=OS_PROFILES[host["os"]]["ttl"])
    t += rng.randint(4000, 40000)
    cap.udp(t, "162.159.200.1", host["ip"], 123, sport, b"\x24" + b"\x00" * 47, ttl=52)
    return t


def background(cap: Capture, env: Env, t0: int, t1: int, scale: float = 1.0) -> None:
    rng = cap.rng
    rate = 2.0 * scale
    t = t0
    while t < t1:
        t += int(rng.expovariate(rate) * US)
        if t >= t1:
            break
        host = rng.choice(env.hosts)
        roll = rng.random()
        site = rng.choice(host["sites"])
        if roll < 0.32:
            dns_lookup(cap, env, host, t, site[0], site[1])
        elif roll < 0.74:
            tls_session(cap, host, site[1], site[0], t, rng.randint(1, 5))
        elif roll < 0.90:
            http_session(cap, host, site[1], t)
        elif roll < 0.93:
            bulk_session(cap, host, site[1], t)
        else:
            ntp_sync(cap, env, host, t)


def scenario_benign(cap: Capture, env: Env, dur: int) -> list[dict]:
    background(cap, env, 0, dur * US, scale=1.0)
    return []


def scenario_syn_flood(cap: Capture, env: Env, dur: int) -> list[dict]:
    rng = cap.rng
    background(cap, env, 0, dur * US, scale=0.6)
    start, end = 60 * US, 120 * US
    victim, vport = env.web, 443
    pools = ["45.132", "77.83", "103.216", "185.220", "200.108"]
    sources = sorted({f"{pools[i % len(pools)]}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
                      for i in range(3600)})
    rng.shuffle(sources)
    sources = sources[:3000]
    n = 9600
    step = (end - start) // n
    for i in range(n):
        t = start + i * step + rng.randint(0, max(1, step // 2))
        src = sources[rng.randrange(len(sources))]
        cap.tcp(t, src, victim, rng.randint(1024, 65535), vport, SYN, rng.getrandbits(31), 0,
                rng.choice([512, 1024, 8192, 29200]),
                opts=encode_tcp_opts([("mss", 1460)]), ttl=rng.choice([46, 51, 57, 118, 240]))
        if i % 12 == 0:
            cap.tcp(t + rng.randint(300, 3000), victim, src, vport, rng.randint(1024, 65535),
                    SYN | ACK, rng.getrandbits(31), 1, 64240,
                    opts=encode_tcp_opts(OS_PROFILES["linux"]["opts"]), ttl=64)
    return [{
        "threat_class": "volumetric-ddos",
        "subtype": "syn-flood-spoofed-source",
        "start_ts": start / US, "end_ts": end / US,
        "attackers": sorted(set(sources)),
        "attacker_note": "source addresses are spoofed, attribution confidence is zero",
        "victims": [victim], "victim_ports": [vport], "protocol": "tcp",
        "expected_signal": "src_entropy_1s explosion, syn_synack_ratio_1s around 12:1",
    }]


def scenario_udp_reflection(cap: Capture, env: Env, dur: int) -> list[dict]:
    rng = cap.rng
    background(cap, env, 0, dur * US, scale=0.6)
    start, end = 60 * US, 105 * US
    victim = env.app
    reflectors = []
    for block in ("208.67.222", "64.6.64", "156.154.70", "80.80.80", "162.159.200", "199.85.126"):
        for k in range(8):
            reflectors.append(f"{block}.{2 + k * 5}")
    reflectors = sorted(set(reflectors))
    vports = [rng.randint(20000, 60000) for _ in range(6)]
    n = 1575
    step = (end - start) // n
    for i in range(n):
        t = start + i * step + rng.randint(0, max(1, step // 3))
        refl = reflectors[i % len(reflectors)]
        vport = vports[i % len(vports)]
        ntp = i % 3 == 0
        if ntp:
            cap.udp(t, victim, refl, vport, 123, b"\x17\x00\x03\x2a" + b"\x00" * 4, ttl=64)
        else:
            cap.udp(t, victim, refl, vport, 53, dns_query(rng.getrandbits(16), "isc.org", 255),
                    ttl=64)
        for j in range(2):
            rt = t + rng.randint(4000, 30000) + j * rng.randint(200, 2500)
            size = rng.randint(420, 540)
            cap.udp(rt, refl, victim, 123 if ntp else 53, vport, b"\x00" * size,
                    ttl=rng.choice([44, 48, 51, 56]))
    return [{
        "threat_class": "volumetric-ddos",
        "subtype": "udp-reflection-amplification",
        "start_ts": start / US, "end_ts": end / US,
        "attackers": reflectors,
        "attacker_note": "reflectors are the observed sources, the real origin spoofed the victim",
        "victims": [victim], "victim_ports": sorted(vports), "protocol": "udp",
        "expected_signal": "src_entropy collapse to 48 sources, amplification ratio near 20x",
    }]


def scenario_slowloris(cap: Capture, env: Env, dur: int) -> list[dict]:
    rng = cap.rng
    background(cap, env, 0, dur * US, scale=0.30)
    start, end = 90 * US, 570 * US
    victim, vport = env.web, 80
    attackers = [f"91.240.118.{20 + i}" for i in range(14)]
    conns = []
    for i in range(400):
        src = attackers[i % len(attackers)]
        t = start + int((i / 400.0) * 90 * US) + rng.randint(0, 400000)
        conn = Conn(cap, src, victim, vport, "linux", hops=rng.randint(8, 16))
        conn.handshake(t, rng.randint(20000, 90000))
        t += rng.randint(20000, 120000)
        conn.up(t, rng.randint(150, 210))
        conns.append((conn, t))
    for conn, t0 in conns:
        t = t0
        while True:
            t += int((22 + rng.random() * 8) * US)
            if t >= end:
                break
            conn.up(t, rng.randint(24, 44))
            if rng.random() < 0.5:
                conn.down(t + rng.randint(2000, 20000), 0, flags=ACK)
    return [{
        "threat_class": "volumetric-ddos",
        "subtype": "slowloris-connection-exhaustion",
        "start_ts": start / US, "end_ts": end / US,
        "attackers": attackers,
        "victims": [victim], "victim_ports": [vport], "protocol": "tcp",
        "expected_signal": "400 concurrent flows, no FIN, tiny payloads, low packets per second",
    }]


def _checkin(cap: Capture, host: dict, dst: str, sni: str, t: int, up_bytes: tuple,
             down_bytes: tuple) -> None:
    rng = cap.rng
    rtt = rng.randint(30000, 70000)
    conn = Conn(cap, host["ip"], dst, 443, host["os"], hops=11)
    tt = conn.handshake(t, rtt)
    ch = tls_client_hello(rng, sni, host["tls"])
    tt += rng.randint(2000, 8000)
    conn.up(tt, len(ch), payload=ch)
    tt += rtt
    conn.down(tt, len(tls_server_hello(rng, 0x1301)))
    tt += rng.randint(4000, 15000)
    conn.up(tt, rng.randint(*up_bytes))
    tt += rtt
    conn.down(tt, rng.randint(*down_bytes))
    tt += rng.randint(10000, 60000)
    conn.close(tt, rtt)


def scenario_beacon_jitter(cap: Capture, env: Env, dur: int) -> list[dict]:
    rng = cap.rng
    background(cap, env, 0, dur * US, scale=0.06)
    c2 = "203.0.113.77"
    infected = ["10.20.1.14", "10.20.2.11", "10.20.2.18", "10.20.3.13", "10.20.4.10", "10.20.1.19"]
    period, jitter = 45.0, 0.30
    start = 30 * US
    end = (dur - 20) * US
    for ip in infected:
        host = env.host_by_ip(ip)
        t = start + int(rng.random() * period * US)
        while t < end:
            _checkin(cap, host, c2, "cdn-sync.example-updates.net", t, (200, 240), (340, 420))
            t += int(period * (1.0 + rng.uniform(-jitter, jitter)) * US)
    decoys = ["10.20.1.10", "10.20.2.13", "10.20.4.11"]
    dperiod, djitter = 300.0, 0.45
    updater = "10.20.0.80"
    for ip in decoys:
        host = env.host_by_ip(ip)
        t = start + int(rng.random() * dperiod * US)
        while t < end:
            _checkin(cap, host, updater, "updates.internal-patch.corp", t, (300, 1400), (600, 1400))
            t += int(dperiod * (1.0 + rng.uniform(-djitter, djitter)) * US)
    return [{
        "threat_class": "c2-beaconing",
        "subtype": "jittered-https-beacon",
        "start_ts": start / US, "end_ts": end / US,
        "attackers": sorted(infected),
        "victims": [c2], "victim_ports": [443], "protocol": "tcp",
        "period_s": period, "jitter_fraction": jitter,
        "benign_decoys": {
            "hosts": sorted(decoys), "destination": updater, "period_s": dperiod,
            "jitter_fraction": djitter,
            "note": "software update pollers, semi-regular on purpose, must not raise an alert",
        },
        "expected_signal": "lomb-scargle peak at 45 s with low false-alarm probability",
    }]


def _dga_algorithmic(rng: random.Random, n: int) -> list[str]:
    out = []
    while len(out) < n:
        ln = rng.randint(12, 19)
        name = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(ln))
        out.append(f"{name}{rng.choice(['.com', '.net', '.info', '.top', '.xyz'])}")
    return out


def _dga_dictionary(rng: random.Random, n: int) -> list[str]:
    out = []
    while len(out) < n:
        a, b = rng.choice(WORDS), rng.choice(WORDS)
        if a == b:
            continue
        out.append(f"{a}{b}{rng.choice(['.com', '.net', '.org'])}")
    return out


def scenario_dga_burst(cap: Capture, env: Env, dur: int) -> list[dict]:
    rng = cap.rng
    background(cap, env, 0, dur * US, scale=0.4)
    algo_host, dict_host = "10.20.2.15", "10.20.3.11"
    algo_names = _dga_algorithmic(rng, 550)
    dict_names = _dga_dictionary(rng, 380)
    for host_ip, names, w0, w1 in ((algo_host, algo_names, 120, 480),
                                   (dict_host, dict_names, 150, 520)):
        host = env.host_by_ip(host_ip)
        span = (w1 - w0) * US
        for i, name in enumerate(names):
            t = w0 * US + int(span * i / len(names)) + rng.randint(0, 200000)
            txid = rng.getrandbits(16)
            sport = rng.randint(32768, 60999)
            cap.udp(t, host_ip, env.resolver, sport, 53, dns_query(txid, name, 1),
                    ttl=OS_PROFILES[host["os"]]["ttl"])
            t += rng.randint(3000, 40000)
            if rng.random() < 0.03:
                cap.udp(t, env.resolver, host_ip, 53, sport,
                        dns_response(txid, name, 1, [ip_to_bytes("185.53.178.9")]), ttl=64)
            else:
                cap.udp(t, env.resolver, host_ip, 53, sport,
                        dns_response(txid, name, 1, [], rcode=3), ttl=64)
    return [
        {
            "threat_class": "dga-dns-tunnelling",
            "subtype": "dga-high-entropy",
            "start_ts": 120.0, "end_ts": 480.0,
            "attackers": [algo_host], "victims": [env.resolver], "victim_ports": [53],
            "protocol": "udp", "sample_domains": algo_names[:12], "domain_count": len(algo_names),
            "expected_signal": "high qname_char_entropy and very poor bigram log-likelihood",
        },
        {
            "threat_class": "dga-dns-tunnelling",
            "subtype": "dga-dictionary",
            "start_ts": 150.0, "end_ts": 520.0,
            "attackers": [dict_host], "victims": [env.resolver], "victim_ports": [53],
            "protocol": "udp", "sample_domains": dict_names[:12], "domain_count": len(dict_names),
            "expected_signal": "near-normal character entropy, only the bigram model separates it",
        },
    ]


def scenario_dns_tunnel(cap: Capture, env: Env, dur: int) -> list[dict]:
    rng = cap.rng
    background(cap, env, 0, dur * US, scale=0.30)
    src = "10.20.1.19"
    host = env.host_by_ip(src)
    registered = "dnsc2-relay.net"
    start, end = 60 * US, 540 * US
    n = 2200
    step = (end - start) // n
    names = []
    for i in range(n):
        t = start + i * step + rng.randint(0, max(1, step // 2))
        l1 = "".join(rng.choice(BASE32) for _ in range(rng.randint(44, 58)))
        l2 = "".join(rng.choice(BASE32) for _ in range(rng.randint(40, 56)))
        qname = f"{l1}.{l2}.t.{registered}"
        qtype = 16 if rng.random() < 0.7 else 10
        txid = rng.getrandbits(16)
        sport = rng.randint(32768, 60999)
        cap.udp(t, src, env.resolver, sport, 53, dns_query(txid, qname, qtype),
                ttl=OS_PROFILES[host["os"]]["ttl"])
        payload = "".join(rng.choice(BASE32) for _ in range(rng.randint(150, 210))).encode()
        rd = txt_rdata(payload) if qtype == 16 else payload
        cap.udp(t + rng.randint(6000, 45000), env.resolver, src, 53, sport,
                dns_response(txid, qname, qtype, [rd]), ttl=64)
        if i < 8:
            names.append(qname)
    return [{
        "threat_class": "dga-dns-tunnelling",
        "subtype": "dns-tunnel-txt-null",
        "start_ts": start / US, "end_ts": end / US,
        "attackers": [src], "victims": [env.resolver], "victim_ports": [53], "protocol": "udp",
        "registered_domain": registered, "query_count": n, "sample_qnames": names,
        "expected_signal": "subdomain cardinality near 2200 under one registered domain, txt/null heavy",
    }]


def scenario_ja4_spoof(cap: Capture, env: Env, dur: int) -> list[dict]:
    rng = cap.rng
    background(cap, env, 0, dur * US, scale=0.4)
    spoofers = ["10.20.5.31", "10.20.5.32", "10.20.5.33"]
    dests = ["198.51.100.24", "198.51.100.61", "198.51.100.98"]
    snis = ["static.content-delivery-edge.net", "api.telemetry-sync.io", "cdn.assets-mirror.co"]
    start, end = 40 * US, (dur - 30) * US
    for k, ip in enumerate(spoofers):
        host = {"ip": ip, "os": "linux", "tls": "chrome-windows",
                "sites": [(snis[k], dests[k])]}
        for frac in sorted(rng.uniform(0.0, 1.0) for _ in range(14)):
            t = start + int((end - start) * frac)
            tls_session(cap, host, dests[k], snis[k], t, rng.randint(2, 4),
                        tls_profile="chrome-windows", tcp_os="linux")
    return [{
        "threat_class": "encrypted-malware",
        "subtype": "ja4-tcp-fingerprint-disagreement",
        "start_ts": start / US, "end_ts": end / US,
        "attackers": sorted(spoofers), "victims": sorted(dests), "victim_ports": [443],
        "protocol": "tcp",
        "claimed_tls_profile": "chrome-windows", "actual_tcp_family": "linux",
        "expected_signal": "clienthello claims chrome on windows, the syn is ttl 64 with linux option order",
    }]


def scenario_port_scan(cap: Capture, env: Env, dur: int) -> list[dict]:
    rng = cap.rng
    background(cap, env, 0, dur * US, scale=0.4)
    fast_src, slow_src, sweep_src = "91.203.44.18", "45.77.180.9", "5.188.62.140"
    open_ports = {22, 53, 80, 443, 445, 3389}
    fast_start, fast_end = 120 * US, 129 * US
    step = (fast_end - fast_start) // 1024
    for i in range(1024):
        port = i + 1
        t = fast_start + i * step
        sport = 44000 + (i % 3000)
        cap.tcp(t, fast_src, env.web, sport, port, SYN, rng.getrandbits(31), 0, 1024,
                opts=encode_tcp_opts([("mss", 1460)]), ttl=54)
        rt = t + rng.randint(500, 4000)
        if port in open_ports:
            cap.tcp(rt, env.web, fast_src, port, sport, SYN | ACK, rng.getrandbits(31), 1, 64240,
                    opts=encode_tcp_opts(OS_PROFILES["linux"]["opts"]), ttl=64)
        elif rng.random() < 0.92:
            cap.tcp(rt, env.web, fast_src, port, sport, RST | ACK, 0, 1, 0, ttl=64)
    slow_start, slow_end = 100 * US, 520 * US
    slow_ports = sorted(rng.sample(range(1, 9000), 300))
    sstep = (slow_end - slow_start) // 300
    for i, port in enumerate(slow_ports):
        t = slow_start + i * sstep + rng.randint(0, sstep // 2)
        sport = rng.randint(32768, 60999)
        cap.tcp(t, slow_src, env.app, sport, port, SYN, rng.getrandbits(31), 0, 29200,
                opts=encode_tcp_opts(OS_PROFILES["linux"]["opts"]), ttl=49)
        if rng.random() < 0.9:
            cap.tcp(t + rng.randint(2000, 30000), env.app, slow_src, port, sport, RST | ACK,
                    0, 1, 0, ttl=64)
    sweep_start, sweep_end = 300 * US, 480 * US
    live = {10 + i % 12 for i in range(12)}
    wstep = (sweep_end - sweep_start) // 254
    for i in range(254):
        octet = i + 1
        t = sweep_start + i * wstep + rng.randint(0, wstep // 2)
        dst = f"10.20.1.{octet}"
        sport = rng.randint(32768, 60999)
        cap.tcp(t, sweep_src, dst, sport, 445, SYN, rng.getrandbits(31), 0, 8192,
                opts=encode_tcp_opts([("mss", 1460), ("sok",), ("nop",), ("nop",)]), ttl=112)
        if octet in live:
            cap.tcp(t + rng.randint(2000, 20000), dst, sweep_src, 445, sport, RST | ACK,
                    0, 1, 0, ttl=128)
    return [
        {
            "threat_class": "recon-scanning", "subtype": "vertical-scan-fast",
            "start_ts": fast_start / US, "end_ts": fast_end / US,
            "attackers": [fast_src], "victims": [env.web],
            "victim_ports": list(range(1, 1025)), "protocol": "tcp",
            "expected_signal": "1024 distinct destination ports on one host in nine seconds",
        },
        {
            "threat_class": "recon-scanning", "subtype": "vertical-scan-slow",
            "start_ts": slow_start / US, "end_ts": slow_end / US,
            "attackers": [slow_src], "victims": [env.app],
            "victim_ports": slow_ports, "protocol": "tcp",
            "expected_signal": "300 ports at 0.7 per second, invisible to a one-second window",
        },
        {
            "threat_class": "recon-scanning", "subtype": "horizontal-sweep",
            "start_ts": sweep_start / US, "end_ts": sweep_end / US,
            "attackers": [sweep_src], "victims": [f"10.20.1.{i + 1}" for i in range(254)],
            "victim_ports": [445], "protocol": "tcp",
            "expected_signal": "one port across 254 hosts, the strobe shape not the vertical one",
        },
    ]


def scenario_exfil_drip(cap: Capture, env: Env, dur: int) -> list[dict]:
    rng = cap.rng
    background(cap, env, 0, dur * US, scale=0.10)
    src = "10.20.2.19"
    host = env.host_by_ip(src)
    dst = "185.244.25.61"
    start, end = 120 * US, (dur - 60) * US
    t = start
    chunks = 0
    total_out = 0
    while t < end:
        rtt = rng.randint(28000, 60000)
        conn = Conn(cap, src, dst, 443, host["os"], hops=13)
        tt = conn.handshake(t, rtt)
        ch = tls_client_hello(rng, "sync.backup-relay-node.net", host["tls"])
        tt += rng.randint(2000, 9000)
        conn.up(tt, len(ch), payload=ch)
        tt += rtt
        conn.down(tt, len(tls_server_hello(rng, 0x1301)))
        tt += rng.randint(5000, 20000)
        for i in range(9):
            conn.up(tt, 1400)
            total_out += 1400
            tt += rng.randint(900, 5000)
            if i % 3 == 2:
                conn.down(tt, 0, flags=ACK)
        tt += rtt
        conn.down(tt, rng.randint(120, 220))
        tt += rng.randint(10000, 50000)
        conn.close(tt, rtt)
        chunks += 1
        t += int((20.0 + rng.uniform(-3.0, 3.0)) * US)
    return [{
        "threat_class": "data-exfiltration",
        "subtype": "slow-drip-https-upload",
        "start_ts": start / US, "end_ts": end / US,
        "attackers": [src], "victims": [dst], "victim_ports": [443], "protocol": "tcp",
        "chunks": chunks, "outbound_bytes": total_out,
        "chunk_interval_s": 20.0,
        "expected_signal": "sustained outbound:inbound ratio near 20:1 with no single large window",
    }]


def _upload_session(cap: Capture, host: dict, dst: str, sni: str, t: int, chunks: int) -> int:
    rng = cap.rng
    rtt = rng.randint(20000, 55000)
    conn = Conn(cap, host["ip"], dst, 443, host["os"], hops=14)
    tt = conn.handshake(t, rtt)
    ch = tls_client_hello(rng, sni, host["tls"])
    tt += rng.randint(2000, 8000)
    conn.up(tt, len(ch), payload=ch)
    tt += rtt
    conn.down(tt, len(tls_server_hello(rng, 0x1301)))
    tt += rng.randint(4000, 15000)
    step = max(MIN_GAP_US * 4, int(25.0 * US / max(1, chunks)))
    for i in range(chunks):
        conn.up(tt, 1400)
        tt += rng.randint(step // 2, step)
        if i % 4 == 3:
            conn.down(tt, 0, flags=ACK)
    tt += rtt
    conn.down(tt, rng.randint(100, 200))
    return conn.close(tt + rng.randint(8000, 40000), rtt)


def scenario_exfil_bulk(cap: Capture, env: Env, dur: int) -> list[dict]:
    rng = cap.rng
    background(cap, env, 0, dur * US, scale=0.06)
    src = "10.20.3.16"
    host = env.host_by_ip(src)
    dst = "91.219.238.44"
    sni = "archive.storage-vault-eu.net"
    start, end = 120 * US, (dur - 90) * US
    burst_at = 400 * US
    burst_chunks = 3700
    stage_chunks = 14
    sessions = 0
    t = start
    while t < end:
        _upload_session(cap, host, dst, sni, t, stage_chunks)
        sessions += 1
        t += int(rng.uniform(20.0, 80.0) * US)
    _upload_session(cap, host, dst, sni, burst_at, burst_chunks)
    staged = sessions * stage_chunks * 1400
    return [{
        "threat_class": "data-exfiltration",
        "subtype": "bulk-https-upload",
        "start_ts": start / US, "end_ts": end / US,
        "attackers": [src], "victims": [dst], "victim_ports": [443], "protocol": "tcp",
        "sessions": sessions + 1,
        "outbound_bytes": staged + burst_chunks * 1400,
        "burst_offset_s": burst_at / US,
        "burst_bytes": burst_chunks * 1400,
        "expected_signal": "one 60 s window carries about 5 megabytes out against kilobytes in, "
                           "which is the burst shape the drip scenario deliberately does not have",
    }]


BUILDERS = {
    "benign": scenario_benign,
    "syn_flood": scenario_syn_flood,
    "udp_reflection": scenario_udp_reflection,
    "slowloris": scenario_slowloris,
    "beacon_jitter": scenario_beacon_jitter,
    "dga_burst": scenario_dga_burst,
    "dns_tunnel": scenario_dns_tunnel,
    "ja4_spoof": scenario_ja4_spoof,
    "port_scan": scenario_port_scan,
    "exfil_drip": scenario_exfil_drip,
    "exfil_bulk": scenario_exfil_bulk,
}


def write_pcap(path: str, packets: list[tuple[int, bytes]]) -> None:
    with open(path, "wb") as fh:
        w = dpkt.pcap.Writer(fh, snaplen=2048)
        for ts_us, frame in packets:
            w.writepkt_time(frame, (BASE_TS_US + ts_us) / US)


def write_flows(path: str, records: list[dict]) -> int:
    lines = [",".join(catalogue.FLOW_COLUMNS)]
    for r in records:
        lines.append(",".join([
            f"{(BASE_TS_US + r['ts_start_us']) / US:.6f}",
            f"{(BASE_TS_US + r['ts_end_us']) / US:.6f}",
            r["src_ip"], r["dst_ip"], str(r["src_port"]), str(r["dst_port"]),
            str(r["proto"]), str(r["packets"]), str(r["bytes"]), str(r["tcp_flags"]),
            r["direction_hint"],
        ]))
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    return len(records)


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 16), b""):
            h.update(block)
    return h.hexdigest()


def build(spec: dict, output_directory: str | None = None) -> dict:
    sid = spec["id"]
    cap = Capture(spec["seed"])
    env = Env(random.Random(spec["seed"] ^ 0x5EED))
    attacks = BUILDERS[sid](cap, env, int(spec["nominal_duration_s"]))
    packets, records = cap.finish()

    directory = OUT_DIR if output_directory is None else output_directory
    pcap_path = os.path.join(directory, f"{sid}.pcap")
    flow_path = os.path.join(directory, f"{sid}.flows.csv")
    label_path = os.path.join(directory, f"{sid}.labels.json")
    write_pcap(pcap_path, packets)
    write_flows(flow_path, records)

    emul = next(e for e in catalogue.EMULATION if e["id"] == sid)
    first_ts = (BASE_TS_US + packets[0][0]) / US
    last_ts = (BASE_TS_US + packets[-1][0]) / US
    labels = {
        "scenario": sid,
        "name": spec["name"],
        "threat_class": spec["threat_class"],
        "seed": spec["seed"],
        "generated_by": "training/generate_scenarios.py",
        "synthesised": True,
        "synthesis_note": catalogue.SYNTHESIS_NOTE,
        "emulates": emul["emulates"],
        "stands_in_for": emul["stands_in_for"],
        "capture": {
            "base_ts": BASE_TS_US / US,
            "first_ts": first_ts,
            "last_ts": last_ts,
            "duration_s": round(last_ts - first_ts, 6),
            "packets": len(packets),
            "bytes": sum(r["bytes"] for r in records),
            "flow_records": len(records),
        },
        "internal_prefix": "10.20.0.0/16",
        "benign_only": not attacks,
        "attacks": [],
    }
    for a in attacks:
        item = dict(a)
        item["start_ts"] = round(BASE_TS_US / US + a["start_ts"], 6)
        item["end_ts"] = round(BASE_TS_US / US + a["end_ts"], 6)
        item["start_offset_s"] = a["start_ts"]
        item["end_offset_s"] = a["end_ts"]
        labels["attacks"].append(item)
    labels["attackers"] = sorted({x for a in labels["attacks"] for x in a["attackers"]})
    labels["victims"] = sorted({x for a in labels["attacks"] for x in a["victims"]})
    with open(label_path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(labels, fh, indent=2, sort_keys=True)
        fh.write("\n")

    return {
        "packets": len(packets),
        "bytes": labels["capture"]["bytes"],
        "flow_records": len(records),
        "duration_s": labels["capture"]["duration_s"],
        "pcap_size": os.path.getsize(pcap_path),
        "flow_size": os.path.getsize(flow_path),
        "pcap_sha256": sha256_of(pcap_path),
        "seed": spec["seed"],
    }


def write_tls_profiles() -> None:
    payload = {
        "note": "exact clienthello construction used by the synthetic scenarios, so the "
                "ja4 to tcp-fingerprint reference table can be derived without guessing",
        "grease_value": GREASE,
        "profiles": TLS_PROFILES,
        "os_profiles": {k: {"ttl": v["ttl"], "win": v["win"], "mss": v["mss"],
                            "opts": [list(o) for o in v["opts"]], "tls": v["tls"]}
                        for k, v in OS_PROFILES.items()},
    }
    with open(os.path.join(OUT_DIR, "tls_profiles.json"), "w", encoding="utf-8",
              newline="\n") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
        fh.write("\n")


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    write_tls_profiles()
    index = {}
    for spec in catalogue.SCENARIOS:
        info = build(spec)
        index[spec["id"]] = info
        print(f"{spec['id']:<15} {info['packets']:>7} pkts  "
              f"{info['flow_records']:>6} flows  {info['pcap_size'] / 1e6:>6.2f} MB  "
              f"{info['duration_s']:>8.1f} s")
    with open(os.path.join(OUT_DIR, "index.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(index, fh, indent=2, sort_keys=True)
        fh.write("\n")
    total = sum(v["pcap_size"] for v in index.values())
    print(f"total pcap bytes {total / 1e6:.2f} MB across {len(index)} scenarios")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
