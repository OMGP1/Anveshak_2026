from __future__ import annotations

import math
import sys
from dataclasses import dataclass, field

from engine.decode.packet import format_ip
from engine.detect.protocol_flood import ProtocolFloodMonitor
from engine.detect.base import (
    Context,
    Detector,
    LruMap,
    RotatingHLL,
    clamp01,
    confidence_from_margins,
    evidence,
    flow_identifier,
    margin,
    severity_for,
)
from engine.state.entropy import EwmaDeviation, SlidingEntropy
from engine.types import ACK, FIN, RST, SYN, TCP, UDP, Detection, FlowState, PacketMeta

THREAT = "volumetric-ddos"

SUB_SPOOFED = "syn-flood-spoofed-source"
SUB_UDP_SPOOFED = "udp-flood-suspected-spoofed-source"
SUB_REFLECTION = "udp-reflection-amplification"
SUB_EXHAUSTION = "connection-exhaustion"

HOT_SLOTS = 512
HOT_BUCKETS = 8
WINDOW_S = 60

DEFAULTS = {
    "pps_sigma": 4.0,
    "pps_floor": 25.0,
    "syn_synack_ratio": 4.0,
    "amplification_ratio": 5.0,
    "explosion_score": 0.5,
    "collapse_score": 0.5,
    "half_open_min": 120.0,
    "teardown_ratio_max": 0.1,
    "exhaustion_bytes_per_pkt": 200.0,
    "exhaustion_pps_max": 60.0,
    "exhaustion_min_sources": 4.0,
    "min_reflectors": 3.0,
    "pps_warmup": 5,
    "cooldown_s": 60.0,
    "growth_full": 8.0,
    "entropy_ratio_floor": 0.55,
    "reflection_bytes": 120.0,
    "monitor_capacity": 4096,
    "udp_share_min": 0.8,
    "reflection_service_share_min": 0.8,
    "reflection_ports": [17, 19, 53, 123, 161, 389, 1900, 3283, 3389, 3702, 5353, 11211],
}


@dataclass(slots=True)
class HotState:
    entropy: SlidingEntropy
    wide: RotatingHLL
    ports: RotatingHLL


@dataclass(slots=True)
class DstMonitor:
    sec: int = -1
    win_sec: int = -1
    pkts: int = 0
    bytes_in: int = 0
    udp_pkts: int = 0
    service_pkts: int = 0
    last_udp: int = 0
    last_service: int = 0
    udp_bytes_in: int = 0
    udp_bytes_out: int = 0
    syn_to: int = 0
    synack_from: int = 0
    last_pkts: int = 0
    last_bytes: int = 0
    last_syn: int = 0
    last_synack: int = 0
    win_syn: int = 0
    win_fin: int = 0
    win_rst: int = 0
    win_bytes_in: int = 0
    win_bytes_out: int = 0
    last_alert_ns: int | None = None
    pps_dev: EwmaDeviation = field(default_factory=lambda: EwmaDeviation(0.1, warmup=5))
    hot: HotState | None = None


_MONITOR_BYTES = sys.getsizeof(DstMonitor()) + sys.getsizeof(EwmaDeviation()) + 140
_HOT_BYTES = HOT_BUCKETS * HOT_SLOTS * 4 + HOT_SLOTS * 8 + 4 * (1 << 10) + 320


class DdosDetector(Detector):
    name = "ddos"
    classes = [THREAT]

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        cfg = dict(DEFAULTS)
        cfg.update(self.config)
        self.config = cfg
        self.hot_allocated = 0
        self.pending: set[int] = set()
        self.reflection_ports = frozenset(int(p) for p in cfg["reflection_ports"])
        self.table = LruMap(int(cfg["monitor_capacity"]), DstMonitor, _MONITOR_BYTES, self._released)
        self.population = EwmaDeviation(0.01, warmup=0)
        self.baseline_basis = "population"
        self.protocol_flood = ProtocolFloodMonitor(cfg.get("protocol_flood"))

    def _released(self, key: int, mon: DstMonitor) -> None:
        self.pending.discard(key)
        if mon.hot is not None:
            mon.hot = None
            self.hot_allocated -= 1

    def observe(self, meta: PacketMeta, flow: FlowState, ctx: Context) -> list[Detection]:
        now_ns = meta.ts_ns
        sec = now_ns // 1_000_000_000
        mon = self.table.get(meta.dst_ip)
        if sec < mon.sec:
            return []  # A late packet cannot reopen a finalized bucket.
        out: list[Detection] = []
        if mon.sec != sec:
            out = self._roll(mon, sec, meta.dst_ip, ctx, now_ns)
        mon.pkts += meta.packets
        mon.bytes_in += meta.length
        mon.win_bytes_in += meta.length
        self.pending.add(meta.dst_ip)
        if meta.proto == UDP:
            mon.udp_pkts += meta.packets
            mon.udp_bytes_in += meta.length
            if meta.src_port in self.reflection_ports:
                mon.service_pkts += meta.packets
        if meta.proto == TCP:
            syn = bool(meta.tcp_flags & SYN)
            ack = bool(meta.tcp_flags & ACK)
            if syn and not ack:
                mon.syn_to += meta.packets
                mon.win_syn += meta.packets
            if meta.tcp_flags & FIN:
                mon.win_fin += meta.packets
            if meta.tcp_flags & RST:
                mon.win_rst += meta.packets
        peer = self.table.peek(meta.src_ip)
        if peer is not None:
            peer.win_bytes_out += meta.length
            if meta.proto == UDP:
                peer.udp_bytes_out += meta.length
            if meta.proto == TCP and (meta.tcp_flags & SYN) and (meta.tcp_flags & ACK):
                peer.synack_from += meta.packets
        hot = mon.hot
        if hot is not None:
            src = meta.src_ip.to_bytes(4, "big")
            hot.entropy.add(now_ns, src)
            hot.wide.add(now_ns, src)
            hot.ports.add(now_ns, src + meta.src_port.to_bytes(2, "big"))
        return out + self.protocol_flood.observe_packet(meta)

    def _roll(self, mon: DstMonitor, sec: int, dst_ip: int, ctx: Context, now_ns: int) -> list[Detection]:
        if mon.sec < 0:
            mon.sec = sec
            mon.win_sec = sec
            return []
        # Packets belong to one fixed one-second bucket. A later quiet gap must
        # neither dilute its rate nor expire its entropy evidence before assessment.
        bucket_end_ns = (mon.sec + 1) * 1_000_000_000
        pps = float(mon.pkts)
        mon.last_pkts = mon.pkts
        mon.last_bytes = mon.bytes_in
        mon.last_syn = mon.syn_to
        mon.last_synack = mon.synack_from
        mon.last_udp = mon.udp_pkts
        mon.last_service = mon.service_pkts
        dev = self._deviation(mon, pps)
        mon.sec = sec
        mon.pkts = 0
        mon.bytes_in = 0
        mon.syn_to = 0
        mon.synack_from = 0
        mon.udp_pkts = mon.service_pkts = 0
        self.pending.discard(dst_ip)
        detections = self._evaluate(mon, dst_ip, pps, dev, ctx, bucket_end_ns)
        if sec - mon.win_sec >= WINDOW_S:
            mon.win_sec = sec
            mon.win_syn = 0
            mon.win_fin = 0
            mon.win_rst = 0
            mon.win_bytes_in = 0
            mon.win_bytes_out = 0
            mon.udp_bytes_in = mon.udp_bytes_out = 0
        if mon.hot is None and pps >= float(ctx.config["dst_hot_pps"]):
            if self.hot_allocated < int(ctx.config["dst_hot_capacity"]):
                mon.hot = HotState(
                    SlidingEntropy(1.0, HOT_BUCKETS, HOT_SLOTS, seed=41),
                    RotatingHLL(60.0, 10, seed=42),
                    RotatingHLL(60.0, 10, seed=43),
                )
                self.hot_allocated += 1
        return detections

    def _deviation(self, mon: DstMonitor, pps: float) -> float:
        tracker = mon.pps_dev
        clip = float(self.config["pps_sigma"])
        if tracker.n >= int(self.config["pps_warmup"]):
            base_mean, base_var = tracker.mean, tracker.var
            self.baseline_basis = "destination"
        else:
            base_mean, base_var = self.population.mean, self.population.var
            self.baseline_basis = "population"
        sigma = math.sqrt(max(base_var, base_mean, 1.0))
        dev = (pps - base_mean) / sigma
        capped = pps if dev < clip else base_mean + clip * sigma
        tracker.update(capped)
        pop_sigma = math.sqrt(max(self.population.var, self.population.mean, 1.0))
        pop_dev = (pps - self.population.mean) / pop_sigma
        self.population.update(pps if pop_dev < clip else self.population.mean + clip * pop_sigma)
        return dev

    def _evaluate(
        self, mon: DstMonitor, dst_ip: int, pps: float, dev: float, ctx: Context, now_ns: int
    ) -> list[Detection]:
        cfg = self.config
        feats = self._compute(mon, pps, dev, now_ns)
        self._features = feats
        if pps < float(cfg["pps_floor"]) and feats["half_open_60s"] < float(cfg["half_open_min"]):
            return []
        if mon.last_alert_ns is not None and now_ns - mon.last_alert_ns < float(cfg["cooldown_s"]) * 1e9:
            return []
        det = self._rule(dst_ip, feats, now_ns)
        if det is None:
            return []
        mon.last_alert_ns = now_ns
        det.context["feature_snapshot"] = dict(feats)
        return [det]

    def _compute(self, mon: DstMonitor, pps: float, dev: float, now_ns: int) -> dict[str, float]:
        cfg = self.config
        pkts = float(mon.last_pkts)
        mean_bytes = float(mon.last_bytes) / pkts if pkts else 0.0
        slots = float(HOT_SLOTS)
        if mon.hot is not None:
            norm = mon.hot.entropy.entropy(now_ns)
            distinct = float(mon.hot.entropy.distinct(now_ns))
            wide = float(mon.hot.wide.count(now_ns))
            ports = float(mon.hot.ports.count(now_ns))
            slots = float(mon.hot.entropy.slots)
        else:
            norm, distinct, wide, ports = 0.0, 0.0, 0.0, 0.0
        bits = norm * math.log2(distinct) if distinct > 1.0 else 0.0
        headroom = min(pkts, slots)
        ceiling = math.log2(headroom) if headroom > 1.0 else 0.0
        ratio = bits / ceiling if ceiling > 0.0 else 0.0
        growth = wide / distinct if distinct >= 1.0 else 0.0
        if distinct < 1.0:
            explosion = 0.0
            collapse = 0.0
        else:
            explosion = clamp01((ratio - float(cfg["entropy_ratio_floor"])) / 0.35) * clamp01(
                (growth - 2.0) / (float(cfg["growth_full"]) - 2.0)
            )
            collapse = clamp01((3.0 - growth) / 2.0) * clamp01(
                (mean_bytes - float(cfg["reflection_bytes"])) / 280.0
            )
            if distinct < float(cfg["min_reflectors"]):
                collapse = 0.0
        half_open = float(mon.win_syn - mon.win_fin - mon.win_rst)
        teardown = float(mon.win_fin + mon.win_rst) / max(1.0, float(mon.win_syn))
        return {
            "pps_to_dst": float(pps),
            "pps_to_dst_ewma_dev": float(dev),
            "src_entropy_1s": float(norm),
            "src_entropy_ratio_1s": float(ratio),
            "src_cardinality_1s": float(distinct),
            "src_cardinality_60s": float(wide),
            "src_cardinality_growth": float(growth),
            "entropy_explosion_score": float(explosion),
            "entropy_collapse_score": float(collapse),
            "syn_synack_ratio_1s": float(mon.last_syn) / max(1.0, float(mon.last_synack)),
            "amplification_ratio": float(mon.udp_bytes_in) / max(1.0, float(mon.udp_bytes_out)),
            "udp_packet_share": float(mon.last_udp) / max(1.0, pkts),
            "reflection_service_share": float(mon.last_service) / max(1.0, float(mon.last_udp)),
            "udp_egress_observed": float(mon.udp_bytes_out > 0),
            "mean_pkt_bytes_1s": float(mean_bytes),
            "half_open_60s": max(0.0, half_open),
            "teardown_ratio_60s": float(teardown),
            "concurrent_src_ports_60s": float(ports),
        }

    def _rule(self, dst_ip: int, f: dict[str, float], now_ns: int) -> Detection | None:
        cfg = self.config
        end = now_ns / 1e9
        sigma = float(cfg["pps_sigma"])
        rate_ok = f["pps_to_dst_ewma_dev"] > sigma
        if rate_ok and f["entropy_explosion_score"] >= float(cfg["explosion_score"]) \
                and f["syn_synack_ratio_1s"] > float(cfg["syn_synack_ratio"]):
            return self._spoofed(dst_ip, f, now_ns, end, sigma)
        udp = f["udp_packet_share"] >= float(cfg["udp_share_min"])
        if rate_ok and udp and f["entropy_explosion_score"] >= float(cfg["explosion_score"]) \
                and f["amplification_ratio"] > float(cfg["amplification_ratio"]):
            det = self._spoofed(dst_ip, f, now_ns, end, sigma)
            det.subtype = SUB_UDP_SPOOFED
            det.flow["proto"] = "UDP"
            det.summary = ("Suspected randomized-source UDP flood against {0}: {1:.0f} packets/s, "
                           "growing source diversity and inbound byte asymmetry. Passive metadata "
                           "cannot prove source spoofing.").format(format_ip(dst_ip), f["pps_to_dst"])
            det.context["extended_detection"] = True
            det.context["sub_type_basis"] = "UDP rate, source-diversity growth and inbound byte asymmetry"
            margins = [margin(f["pps_to_dst_ewma_dev"], sigma, sigma),
                       margin(f["entropy_explosion_score"], float(cfg["explosion_score"]), 0.5),
                       margin(f["amplification_ratio"], float(cfg["amplification_ratio"]), 20.0)]
            det.context["rule_margins"] = [round(value, 4) for value in margins]
            det.confidence = confidence_from_margins(margins)
            det.severity = severity_for(det.confidence)
            det.evidence = evidence([
                ("pps_to_dst_ewma_dev", f["pps_to_dst_ewma_dev"], margins[0]),
                ("entropy_explosion_score", f["entropy_explosion_score"], margins[1]),
                ("amplification_ratio", f["amplification_ratio"], margins[2]),
                ("src_cardinality_growth", f["src_cardinality_growth"], 0.0),
                ("udp_packet_share", f["udp_packet_share"], 0.0),
            ])
            return det
        if rate_ok and udp and f["reflection_service_share"] >= float(cfg["reflection_service_share_min"]) \
                and f["entropy_collapse_score"] >= float(cfg["collapse_score"]) \
                and f["amplification_ratio"] > float(cfg["amplification_ratio"]):
            return self._reflection(dst_ip, f, now_ns, end, sigma)
        if f["half_open_60s"] >= float(cfg["half_open_min"]) \
                and f["teardown_ratio_60s"] <= float(cfg["teardown_ratio_max"]) \
                and f["pps_to_dst"] <= float(cfg["exhaustion_pps_max"]) \
                and f["src_cardinality_60s"] >= float(cfg["exhaustion_min_sources"]) \
                and 0.0 < f["mean_pkt_bytes_1s"] <= float(cfg["exhaustion_bytes_per_pkt"]):
            return self._exhaustion(dst_ip, f, now_ns, end)
        return None

    def _basis_phrase(self) -> str:
        if self.baseline_basis == "destination":
            return "this destination's own rate baseline"
        return "the enclave-wide per-destination rate prior, this destination having no history yet"

    def _spoofed(self, dst_ip: int, f: dict, now_ns: int, end: float, sigma: float) -> Detection:
        cfg = self.config
        margins = [
            margin(f["pps_to_dst_ewma_dev"], sigma, sigma),
            margin(f["entropy_explosion_score"], float(cfg["explosion_score"]), 0.5),
            margin(f["syn_synack_ratio_1s"], float(cfg["syn_synack_ratio"]), 16.0),
        ]
        flow = flow_identifier(
            TCP, "<spoofed: attribution confidence 0>", dst_ip, 0, 0, end - 1.0, end, "FWD_ONLY", False
        )
        return self._emit(
            now_ns, THREAT, SUB_SPOOFED, margins, flow,
            evidence([
                ("pps_to_dst_ewma_dev", f["pps_to_dst_ewma_dev"], margins[0]),
                ("entropy_explosion_score", f["entropy_explosion_score"], margins[1]),
                ("syn_synack_ratio_1s", f["syn_synack_ratio_1s"], margins[2]),
                ("src_cardinality_growth", f["src_cardinality_growth"], 0.0),
                ("src_entropy_1s", f["src_entropy_1s"], 0.0),
            ]),
            "spoofed-source flood against {0}: {1:.0f} packets per second, {2:.1f} sigma above {3}, "
            "{4:.0f} distinct sources in one second and {5:.0f} over a minute, syn to syn-ack "
            "{6:.1f} to 1".format(
                format_ip(dst_ip), f["pps_to_dst"], f["pps_to_dst_ewma_dev"], self._basis_phrase(),
                f["src_cardinality_1s"], f["src_cardinality_60s"], f["syn_synack_ratio_1s"]),
            {
                "sub_type_basis": "source cardinality keeps growing with the window, so nearly every "
                                  "packet carries a fresh source address",
                "response_note": "investigate destination rate and source authenticity; observed "
                                 "source addresses may be forged and are not reliable attribution",
                "rate_baseline": self.baseline_basis,
                "attribution_confidence": 0.0,
                "visibility_note": "Source diversity is consistent with spoofing but does not prove it.",
            },
        )

    def _reflection(self, dst_ip: int, f: dict, now_ns: int, end: float, sigma: float) -> Detection:
        cfg = self.config
        margins = [
            margin(f["pps_to_dst_ewma_dev"], sigma, sigma),
            margin(f["entropy_collapse_score"], float(cfg["collapse_score"]), 0.5),
            margin(f["amplification_ratio"], float(cfg["amplification_ratio"]), 20.0),
        ]
        flow = flow_identifier(
            UDP, "<{0:.0f} reflectors>".format(f["src_cardinality_60s"]), dst_ip, 0, 0,
            end - 1.0, end, "REV_ONLY", False,
        )
        return self._emit(
            now_ns, THREAT, SUB_REFLECTION, margins, flow,
            evidence([
                ("pps_to_dst_ewma_dev", f["pps_to_dst_ewma_dev"], margins[0]),
                ("entropy_collapse_score", f["entropy_collapse_score"], margins[1]),
                ("amplification_ratio", f["amplification_ratio"], margins[2]),
                ("src_cardinality_growth", f["src_cardinality_growth"], 0.0),
                ("mean_pkt_bytes_1s", f["mean_pkt_bytes_1s"], 0.0),
            ]),
            "reflection or amplification against {0}: {1:.0f} packets per second arriving from a "
            "saturated set of about {2:.0f} sources, {3:.0f} byte replies, {4:.1f} times more bytes "
            "arriving than this host sent".format(
                format_ip(dst_ip), f["pps_to_dst"], f["src_cardinality_60s"],
                f["mean_pkt_bytes_1s"], f["amplification_ratio"]),
            {
                "sub_type_basis": "source cardinality saturates instead of growing, so a small fixed "
                                  "reflector set is carrying the whole rate",
                "response_note": "the observed sources are victims as well. rate limit the reflected "
                                 "service ports rather than blocking the reflectors",
                "rate_baseline": self.baseline_basis,
                "attribution_confidence": 0.0,
                "udp_packet_share": f["udp_packet_share"],
                "reflection_service_share": f["reflection_service_share"],
                "udp_egress_observed": bool(f["udp_egress_observed"]),
                "visibility_note": "The ratio is observed UDP ingress/egress, not a matched request/reply "
                                   "amplification factor. Missing return traffic can inflate it.",
            },
        )

    def _exhaustion(self, dst_ip: int, f: dict, now_ns: int, end: float) -> Detection:
        cfg = self.config
        margins = [
            margin(f["half_open_60s"], float(cfg["half_open_min"]), 240.0),
            margin(float(cfg["teardown_ratio_max"]) - f["teardown_ratio_60s"], 0.0, 0.1),
            margin(float(cfg["exhaustion_bytes_per_pkt"]) - f["mean_pkt_bytes_1s"], 0.0, 120.0),
        ]
        flow = flow_identifier(
            TCP, "<{0:.0f} concurrent sources>".format(max(1.0, f["src_cardinality_60s"])),
            dst_ip, 0, 0, end - float(WINDOW_S), end, "FWD_ONLY", False,
        )
        return self._emit(
            now_ns, THREAT, SUB_EXHAUSTION, margins, flow,
            evidence([
                ("half_open_60s", f["half_open_60s"], margins[0]),
                ("teardown_ratio_60s", f["teardown_ratio_60s"], margins[1]),
                ("mean_pkt_bytes_1s", f["mean_pkt_bytes_1s"], margins[2]),
                ("concurrent_src_ports_60s", f["concurrent_src_ports_60s"], 0.0),
                ("pps_to_dst", f["pps_to_dst"], 0.0),
            ]),
            "suspected connection exhaustion against {0}: {1:.0f} excess observed SYNs over "
            "teardowns in the last minute, {2:.0f} bytes per packet, {3:.0f} packets per second. "
            "Missing return traffic or retransmissions can produce this shape; actual open "
            "connections and HTTP behavior are not established".format(
                format_ip(dst_ip), f["half_open_60s"], f["mean_pkt_bytes_1s"], f["pps_to_dst"]),
            {
                "sub_type_basis": "low rate with excess observed SYNs and few observed teardowns. "
                                  "This is consistent with exhaustion, not proof of Slowloris or live connection occupancy",
                "response_note": "cap concurrent connections per source. a packet rate limit will not "
                                 "help here",
                "rate_baseline": self.baseline_basis,
            },
        )

    def tick(self, now_ns: int, ctx: Context) -> list[Detection]:
        out = []
        sec = now_ns // 1_000_000_000
        for destination in list(self.pending):
            mon = self.table.peek(destination)
            if mon is not None and mon.sec < sec:
                out.extend(self._roll(mon, sec, destination, ctx, now_ns))
        return out + self.protocol_flood.tick(now_ns, ctx)

    def stats(self) -> dict:
        return {
            "name": self.name,
            "alerts": self.alerts,
            "monitors": len(self.table),
            "hot_monitors": self.hot_allocated,
            "monitors_evicted": self.table.evicted,
            "extended": self.protocol_flood.stats(),
        }

    @property
    def nbytes(self) -> int:
        return int(self.table.nbytes + self.hot_allocated * _HOT_BYTES + self.protocol_flood.nbytes
                   + sys.getsizeof(self.pending) + len(self.pending) * 32)
