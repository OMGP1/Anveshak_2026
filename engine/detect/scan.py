from __future__ import annotations

import sys
from dataclasses import dataclass

from engine.decode.packet import format_ip
from engine.detect.base import (
    Context,
    Detector,
    LruMap,
    clamp01,
    evidence,
    flow_identifier,
    margin,
)
from engine.types import ACK, RST, SYN, TCP, UDP, Detection, FlowState, PacketMeta

THREAT = "recon-scanning"

SUB_VERTICAL_FAST = "vertical-scan-fast"
SUB_VERTICAL_SLOW = "vertical-scan-slow"
SUB_HORIZONTAL = "horizontal-sweep"
SUB_STROBE = "strobe-scan"

FAST_S = 60.0
SLOW_S = 3600.0
WINDOW_S = 60

DEFAULTS = {
    "vertical_ports": 30.0,
    "fast_ports_1s": 10.0,
    "horizontal_hosts": 30.0,
    "strobe_hosts": 30.0,
    "strobe_ports_min": 2.0,
    "strobe_ports_max": 20.0,
    "min_probes": 20.0,
    "max_bytes_per_probe": 120.0,
    "max_completion_ratio": 0.30,
    "cooldown_s": 60.0,
    "source_capacity": 8192,
}


@dataclass(slots=True)
class SrcScan:
    win_sec: int = -1
    eval_sec: int = -1
    probes: int = 0
    bytes_sum: int = 0
    synack_back: int = 0
    rst_back: int = 0
    last_alert_ns: int = 0
    last_subtype: str = ""


_SRC_BYTES = sys.getsizeof(SrcScan()) + 140


class ScanDetector(Detector):
    name = "scan"
    classes = [THREAT]

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        cfg = dict(DEFAULTS)
        cfg.update(self.config)
        self.config = cfg
        self.probes = 0
        self.sources = LruMap(int(cfg["source_capacity"]), SrcScan, _SRC_BYTES)

    def observe(self, meta: PacketMeta, flow: FlowState, ctx: Context) -> list[Detection]:
        if meta.proto not in (TCP, UDP):
            return []
        if meta.proto == TCP:
            syn = bool(meta.tcp_flags & SYN)
            ack = bool(meta.tcp_flags & ACK)
            if syn and ack:
                mon = self.sources.peek(meta.dst_ip)
                if mon is not None:
                    mon.synack_back += meta.packets
                return []
            if (meta.tcp_flags & RST) and not syn:
                mon = self.sources.peek(meta.dst_ip)
                if mon is not None:
                    mon.rst_back += meta.packets
                return []
            if not syn:
                return []
        elif flow.packets > meta.packets:
            return []
        return self._probe(meta, ctx)

    def _probe(self, meta: PacketMeta, ctx: Context) -> list[Detection]:
        now_ns = meta.ts_ns
        src = meta.src_ip.to_bytes(4, "big")
        dst = meta.dst_ip.to_bytes(4, "big")
        port = meta.dst_port.to_bytes(2, "big")
        pair_ports = b"P" + src + dst
        pair_hosts = b"P" + src + port
        source_group = b"S" + src
        for window in ctx.scan_ports.values():
            window.add(now_ns, pair_ports, port)
        for window in ctx.scan_hosts.values():
            window.add(now_ns, pair_hosts, dst)
        ctx.scan_ports[SLOW_S].add(now_ns, source_group, port)
        ctx.scan_hosts[SLOW_S].add(now_ns, source_group, dst)
        self.probes += 1
        mon = self.sources.get(meta.src_ip)
        self._roll(mon, now_ns)
        mon.probes += meta.packets
        mon.bytes_sum += meta.length
        sec = now_ns // 1_000_000_000
        if mon.eval_sec == sec:
            return []
        mon.eval_sec = sec
        feats = self._compute(mon, ctx, now_ns, pair_ports, pair_hosts, source_group)
        self._features = feats
        if mon.probes < float(self.config["min_probes"]):
            return []
        if now_ns - mon.last_alert_ns < float(self.config["cooldown_s"]) * 1e9:
            return []
        det = self._rule(meta, mon, feats, now_ns)
        if det is None:
            return []
        mon.last_alert_ns = now_ns
        return [det]

    def _roll(self, mon: SrcScan, now_ns: int) -> None:
        sec = now_ns // 1_000_000_000
        if mon.win_sec < 0:
            mon.win_sec = sec
            return
        if sec - mon.win_sec < WINDOW_S:
            return
        mon.win_sec = sec
        mon.probes = 0
        mon.bytes_sum = 0
        mon.synack_back = 0
        mon.rst_back = 0

    def _compute(
        self, mon: SrcScan, ctx: Context, now_ns: int, pair_ports: bytes,
        pair_hosts: bytes, source_group: bytes
    ) -> dict[str, float]:
        probes = float(mon.probes)
        vertical = {w: ctx.scan_ports[w].count(now_ns, pair_ports) for w in ctx.scan_ports}
        horizontal = {w: ctx.scan_hosts[w].count(now_ns, pair_hosts) for w in ctx.scan_hosts}
        src_ports = ctx.scan_ports[SLOW_S].count(now_ns, source_group)
        src_hosts = ctx.scan_hosts[SLOW_S].count(now_ns, source_group)
        cfg = self.config
        strobe = 0.0
        if float(cfg["strobe_ports_min"]) <= src_ports <= float(cfg["strobe_ports_max"]):
            strobe = clamp01((src_hosts - float(cfg["strobe_hosts"])) / float(cfg["strobe_hosts"]))
        return {
            "vertical_fanout_1s": float(vertical[1.0]),
            "vertical_fanout_60s": float(vertical[FAST_S]),
            "vertical_fanout_3600s": float(vertical[SLOW_S]),
            "horizontal_fanout_1s": float(horizontal[1.0]),
            "horizontal_fanout_60s": float(horizontal[FAST_S]),
            "horizontal_fanout_3600s": float(horizontal[SLOW_S]),
            "source_distinct_ports_3600s": float(src_ports),
            "source_distinct_hosts_3600s": float(src_hosts),
            "strobe_score": float(strobe),
            "rst_response_ratio": float(mon.rst_back) / max(1.0, probes),
            "probe_completion_ratio": float(mon.synack_back) / max(1.0, probes),
            "mean_bytes_per_probe": float(mon.bytes_sum) / probes if probes else 0.0,
            "scan_probe_count_60s": probes,
        }

    def _rule(self, meta: PacketMeta, mon: SrcScan, f: dict, now_ns: int) -> Detection | None:
        cfg = self.config
        if f["mean_bytes_per_probe"] > float(cfg["max_bytes_per_probe"]):
            return None
        if f["probe_completion_ratio"] > float(cfg["max_completion_ratio"]):
            return None
        vertical = max(f["vertical_fanout_60s"], f["vertical_fanout_3600s"])
        horizontal = max(f["horizontal_fanout_60s"], f["horizontal_fanout_3600s"])
        if vertical >= float(cfg["vertical_ports"]) and vertical >= horizontal:
            return self._vertical(meta, f, now_ns, vertical)
        if horizontal >= float(cfg["horizontal_hosts"]):
            if f["strobe_score"] > 0.0 and f["source_distinct_ports_3600s"] > 1.0:
                return self._strobe(meta, f, now_ns)
            return self._horizontal(meta, f, now_ns, horizontal)
        return None

    def _vertical(self, meta: PacketMeta, f: dict, now_ns: int, vertical: float) -> Detection:
        cfg = self.config
        fast = f["vertical_fanout_1s"] >= float(cfg["fast_ports_1s"])
        subtype = SUB_VERTICAL_FAST if fast else SUB_VERTICAL_SLOW
        scale = "1 s" if fast else ("60 s" if f["vertical_fanout_60s"] >= vertical else "3600 s")
        margins = [
            margin(vertical, float(cfg["vertical_ports"]), 300.0),
            margin(float(cfg["max_bytes_per_probe"]) - f["mean_bytes_per_probe"], 0.0, 80.0),
            margin(float(cfg["max_completion_ratio"]) - f["probe_completion_ratio"], 0.0, 0.3),
        ]
        end = now_ns / 1e9
        flow = flow_identifier(
            meta.proto, meta.src_ip, meta.dst_ip, 0, 0, end - FAST_S, end, "FWD_ONLY", False
        )
        return self._emit(
            now_ns, THREAT, subtype, margins, flow,
            evidence([
                ("vertical_fanout_60s", f["vertical_fanout_60s"], margins[0]),
                ("vertical_fanout_1s", f["vertical_fanout_1s"], 0.0),
                ("vertical_fanout_3600s", f["vertical_fanout_3600s"], 0.0),
                ("mean_bytes_per_probe", f["mean_bytes_per_probe"], margins[1]),
                ("probe_completion_ratio", f["probe_completion_ratio"], margins[2]),
                ("horizontal_fanout_60s", f["horizontal_fanout_60s"], 0.0),
            ]),
            "vertical scan: {0} probed about {1:.0f} distinct ports on {2}, first visible in the {3} "
            "window, "
            "{4:.0f} bytes per probe and only {5:.0f} percent of probes answered. horizontal fan-out "
            "stays at {6:.0f} hosts, so this is many ports on one host, not one port across "
            "many".format(
                format_ip(meta.src_ip), vertical, format_ip(meta.dst_ip), scale,
                f["mean_bytes_per_probe"], 100.0 * f["probe_completion_ratio"],
                f["horizontal_fanout_60s"]),
            {
                "pattern": "vertical",
                "scale": scale,
                "multi_scale_note": "the same source is counted at 1 s, 60 s and 3600 s. a fast "
                                    "sweep puts tens of ports inside a single second, a slow one "
                                    "spreads them so thinly that only the wide windows see it, and "
                                    "reporting which scale carried it is what separates the two",
            },
        )

    def _horizontal(self, meta: PacketMeta, f: dict, now_ns: int, horizontal: float) -> Detection:
        cfg = self.config
        margins = [
            margin(horizontal, float(cfg["horizontal_hosts"]), 200.0),
            margin(float(cfg["max_bytes_per_probe"]) - f["mean_bytes_per_probe"], 0.0, 80.0),
            margin(float(cfg["max_completion_ratio"]) - f["probe_completion_ratio"], 0.0, 0.3),
        ]
        end = now_ns / 1e9
        flow = flow_identifier(
            meta.proto, meta.src_ip, "<{0:.0f} hosts swept>".format(horizontal),
            0, int(meta.dst_port), end - FAST_S, end, "FWD_ONLY", False,
        )
        return self._emit(
            now_ns, THREAT, SUB_HORIZONTAL, margins, flow,
            evidence([
                ("horizontal_fanout_60s", f["horizontal_fanout_60s"], margins[0]),
                ("horizontal_fanout_3600s", f["horizontal_fanout_3600s"], 0.0),
                ("mean_bytes_per_probe", f["mean_bytes_per_probe"], margins[1]),
                ("probe_completion_ratio", f["probe_completion_ratio"], margins[2]),
                ("vertical_fanout_60s", f["vertical_fanout_60s"], 0.0),
            ]),
            "horizontal sweep: {0} probed port {1} on about {2:.0f} distinct hosts, {3:.0f} bytes per "
            "probe and {4:.0f} percent answered. it touches only {5:.0f} ports per host, so this is "
            "one service across a subnet, not a port sweep of one machine".format(
                format_ip(meta.src_ip), meta.dst_port, horizontal, f["mean_bytes_per_probe"],
                100.0 * f["probe_completion_ratio"], f["vertical_fanout_60s"]),
            {
                "pattern": "horizontal",
                "multi_scale_note": "counted at 1 s, 60 s and 3600 s so a slow sweep is not lost "
                                    "between windows",
            },
        )

    def _strobe(self, meta: PacketMeta, f: dict, now_ns: int) -> Detection:
        cfg = self.config
        margins = [
            margin(f["source_distinct_hosts_3600s"], float(cfg["strobe_hosts"]), 200.0),
            margin(float(cfg["strobe_ports_max"]) - f["source_distinct_ports_3600s"], 0.0, 10.0),
            margin(float(cfg["max_completion_ratio"]) - f["probe_completion_ratio"], 0.0, 0.3),
        ]
        end = now_ns / 1e9
        flow = flow_identifier(
            meta.proto, meta.src_ip,
            "<{0:.0f} hosts>".format(f["source_distinct_hosts_3600s"]),
            0, int(meta.dst_port), end - SLOW_S, end, "FWD_ONLY", False,
        )
        return self._emit(
            now_ns, THREAT, SUB_STROBE, margins, flow,
            evidence([
                ("source_distinct_hosts_3600s", f["source_distinct_hosts_3600s"], margins[0]),
                ("source_distinct_ports_3600s", f["source_distinct_ports_3600s"], margins[1]),
                ("strobe_score", f["strobe_score"], 0.0),
                ("probe_completion_ratio", f["probe_completion_ratio"], margins[2]),
                ("mean_bytes_per_probe", f["mean_bytes_per_probe"], 0.0),
            ]),
            "strobe scan: {0} touched about {1:.0f} hosts but only {2:.0f} distinct ports across all "
            "of them. a small fixed port set sprayed across a subnet is the shape a service hunt "
            "takes, and neither the vertical nor the horizontal threshold on its own describes "
            "it".format(
                format_ip(meta.src_ip), f["source_distinct_hosts_3600s"],
                f["source_distinct_ports_3600s"]),
            {
                "pattern": "strobe",
                "corpus_note": "no committed scenario contains a strobe. this path is exercised by a "
                               "synthetic unit test only and has not been validated against captured "
                               "traffic",
            },
        )

    def stats(self) -> dict:
        return {
            "name": self.name,
            "alerts": self.alerts,
            "probes": self.probes,
            "sources": len(self.sources),
            "sources_evicted": self.sources.evicted,
        }

    @property
    def nbytes(self) -> int:
        return int(self.sources.nbytes)
