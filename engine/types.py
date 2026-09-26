from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Protocol

TCP = 6
UDP = 17
ICMP = 1

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20

THREAT_CLASSES = [
    "benign",
    "volumetric-ddos",
    "c2-beaconing",
    "dga-dns-tunnelling",
    "encrypted-malware",
    "recon-scanning",
    "data-exfiltration",
]

# Alert taxonomy is deliberately separate from the fixed trained-model class order.
ALERT_CLASSES = THREAT_CLASSES + ["unknown-suspicious"]

ATTACK_TECHNIQUE = {
    "volumetric-ddos": ("T1498.001", "Direct Network Flood"),
    "c2-beaconing": ("T1071.001", "Application Layer Protocol: Web Protocols"),
    "dga-dns-tunnelling": ("T1568.002", "Dynamic Resolution: Domain Generation Algorithms"),
    "encrypted-malware": ("T1573", "Encrypted Channel"),
    "recon-scanning": ("T1046", "Network Service Discovery"),
    "data-exfiltration": ("T1048", "Exfiltration Over Alternative Protocol"),
}


@dataclass(frozen=True, slots=True)
class TLSMeta:
    ja4: str
    version: int
    alpn: str
    sni_present: bool
    ext_count: int
    is_client_hello: bool


@dataclass(frozen=True, slots=True)
class DNSMeta:
    qname: str
    qtype: int
    qname_len: int
    is_response: bool
    answer_count: int
    rcode: int = 0


@dataclass(frozen=True, slots=True)
class PacketMeta:
    ts_ns: int
    proto: int
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    length: int
    tcp_flags: int = 0
    ttl: int = 0
    tcp_window: int = 0
    tcp_mss: int = 0
    tcp_opts: tuple[int, ...] = ()
    packets: int = 1
    from_flow_record: bool = False
    tls: TLSMeta | None = None
    dns: DNSMeta | None = None
    icmp_type: int = 0
    icmp_code: int = 0

    @property
    def ts(self) -> float:
        return self.ts_ns / 1e9


@dataclass(frozen=True, slots=True)
class FlowKey:
    proto: int
    lo_ip: int
    lo_port: int
    hi_ip: int
    hi_port: int

    @staticmethod
    def of(meta: PacketMeta) -> tuple["FlowKey", bool]:
        a = (meta.src_ip, meta.src_port)
        b = (meta.dst_ip, meta.dst_port)
        forward = a <= b
        lo, hi = (a, b) if forward else (b, a)
        return FlowKey(meta.proto, lo[0], lo[1], hi[0], hi[1]), forward


@dataclass(slots=True)
class FlowState:
    key: FlowKey
    first_ts_ns: int
    last_ts_ns: int
    pkts_fwd: int = 0
    pkts_rev: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0
    flags_seen: int = 0
    saw_syn: bool = False
    saw_synack: bool = False
    saw_fin: bool = False
    saw_rst: bool = False
    initiator_ip: int = 0
    initiator_port: int = 0
    responder_ip: int = 0
    responder_port: int = 0
    orientation_confidence: float = 0.0
    ja4: str = ""
    tcp_fp: str = ""
    tls_alpn: str = ""
    splt: list[tuple[int, int]] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return (self.last_ts_ns - self.first_ts_ns) / 1e9

    @property
    def packets(self) -> int:
        return self.pkts_fwd + self.pkts_rev

    @property
    def bytes_total(self) -> int:
        return self.bytes_fwd + self.bytes_rev

    @property
    def completeness_flag(self) -> bool:
        return self.pkts_fwd > 0 and self.pkts_rev > 0


@dataclass(slots=True)
class Evidence:
    feature: str
    value: float
    contribution: float


@dataclass(slots=True)
class Detection:
    ts_ns: int
    threat_class: str
    subtype: str
    confidence: float
    severity: str
    source: str
    flow: dict
    evidence: list[Evidence]
    summary: str
    context: dict = field(default_factory=dict)


class ReplaySource(Protocol):
    def __iter__(self) -> Iterator[PacketMeta]: ...

    @property
    def name(self) -> str: ...
