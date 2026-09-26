"""Offline benign challenge traffic, never used as training input or sent on a network."""
from __future__ import annotations

from dataclasses import replace
import random

from engine.types import ACK, SYN, TCP, UDP, DNSMeta, PacketMeta, TLSMeta

BASE = 1_720_000_000_000_000_000
CLIENT = 0x0A140101
SERVER = 0xC6336411


def download(seed=20260908, *, proto=TCP, service=443, count=4000):
    rng = random.Random(seed)
    for i in range(count):
        yield PacketMeta(BASE + i * 2_500_000, proto, SERVER + i % 8, CLIENT,
                         service, 40000 + i % 8, rng.randint(900, 1450), tcp_flags=ACK)


def dns_query(index, name, qtype=1):
    return PacketMeta(BASE + index * 100_000_000, UDP, CLIENT, SERVER, 40000, 53, 80 + len(name),
                      dns=DNSMeta(name, qtype, len(name), False, 0))


def dns_cross_zone(seed=20260908):
    for i in range(600):
        yield dns_query(i, "_dmarc.mail.example.net", 16)
    for i in range(600, 1000):
        yield dns_query(i, f"asset{i}.assets.example.org", 1)


def dns_mixed(seed=20260908):
    rng = random.Random(seed)
    domains = ["contoso.com", "northwind.com", "fabrikam.com", "woodgrove.com"]
    for i in range(1000):
        name = rng.choice(["www", "mail", "cdn", "_dmarc"]) + "." + rng.choice(domains)
        query = dns_query(i, name, rng.choice([1, 28, 15, 16, 65]))
        yield query
        yield replace(query, ts_ns=query.ts_ns + 1_000_000, src_ip=SERVER, dst_ip=CLIENT,
                      src_port=53, dst_port=40000, dns=replace(query.dns, is_response=True, answer_count=1))


def dns_long_cdn(seed=20260908):
    rng = random.Random(seed)
    for i in range(1000):
        label = "".join(rng.choices("abcdef0123456789", k=60))
        yield dns_query(i, label + ".edge.akamaiedge.net", rng.choice([1, 28, 65]))


def browser_connections(seed=20260908):
    rng = random.Random(seed)
    for i in range(400):
        now = BASE + i * 100_000_000
        packet = PacketMeta(now, TCP, CLIENT, SERVER + i % 80, 40000 + i, 443, 60,
                            tcp_flags=SYN, ttl=64, tcp_window=65535, tcp_mss=1460,
                            tcp_opts=(2, 4, 8, 1, 3))
        yield packet
        yield replace(packet, ts_ns=now + 1_000_000, src_ip=packet.dst_ip, dst_ip=CLIENT,
                      src_port=443, dst_port=packet.src_port, tcp_flags=SYN | ACK)
        yield replace(packet, ts_ns=now + 2_000_000, tcp_flags=ACK)
        yield replace(packet, ts_ns=now + 3_000_000, tcp_flags=ACK, length=rng.randint(100, 700))
        yield replace(packet, ts_ns=now + 4_000_000, src_ip=packet.dst_ip, dst_ip=CLIENT,
                      src_port=443, dst_port=packet.src_port, tcp_flags=ACK, length=1400)


def regular_encrypted_session(seed=20260908, *, proto=TCP, count=200):
    # A single regular application session is not evidence of maliciousness.
    for i in range(count):
        yield PacketMeta(BASE + i * 100_000_000, proto,
                         CLIENT if i % 2 == 0 else SERVER, SERVER if i % 2 == 0 else CLIENT,
                         40000 if i % 2 == 0 else 443, 443 if i % 2 == 0 else 40000,
                         200 if i % 2 == 0 else 400, tcp_flags=ACK,
                         tls=TLSMeta("unseen-benign-library", 0x304, "h2", True, 10, True)
                         if proto == TCP and i == 0 else None)


CASES = {
    "tcp_large_download": download,
    "udp443_large_download": lambda seed: download(seed, proto=UDP),
    "dns_mixed_record_types": dns_mixed,
    "dns_txt_other_domain": dns_cross_zone,
    "dns_long_cdn_names": dns_long_cdn,
    "browser_connection_burst": browser_connections,
    "regular_tls_session": regular_encrypted_session,
    "regular_udp443_session": lambda seed: regular_encrypted_session(seed, proto=UDP),
}
