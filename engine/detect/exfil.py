from __future__ import annotations

import math
import sys
from dataclasses import dataclass

from engine.decode.packet import format_ip
from engine.detect.base import (
    Context,
    Detector,
    LruMap,
    WindowedHLLFamily,
    clamp01,
    evidence,
    flow_identifier,
    margin,
)
from engine.state.flow_table import ORIENT_SERVICE_PORT
from engine.types import TCP, UDP, Detection, FlowState, PacketMeta

THREAT = "data-exfiltration"

SUB_DRIP = "slow-drip-upload"
SUB_BURST = "upload-burst"

WINDOW_S = 60
MIN_ORIENTATION = ORIENT_SERVICE_PORT

DEFAULTS = {
    "ratio_alert": 3.0,
    "ratio_alpha": 0.2,
    "min_outbound_bytes": 100_000.0,
    "min_sustained_s": 300.0,
    "burst_window_bytes": 5_000_000.0,
    "novelty_horizon": 8.0,
    "cooldown_s": 600.0,
    "peer_capacity": 20000,
    "fanout_capacity": 20000,
}


@dataclass(slots=True)
class Peer:
    first_ts_ns: int = 0
    win_sec: int = -1
    out_win: int = 0
    in_win: int = 0
    out_total: int = 0
    in_total: int = 0
    windows: int = 0
    asym_windows: int = 0
    peak_out_win: int = 0
    ratio_ewma: float = 0.0
    ratio_n: int = 0
    last_alert_ns: int = 0
    dst_port: int = 0
    orient_conf: float = 1.0


_PEER_BYTES = sys.getsizeof(Peer()) + 140


def _orientation_note(confidence: float) -> dict:
    if confidence >= 1.0:
        return {"confidence": 1.0, "guessed": False,
                "basis": "the handshake was observed, so the byte ratio is the right way round"}
    return {"confidence": round(float(confidence), 2), "guessed": True,
            "basis": "no handshake was captured for at least one flow of this pair, so the "
                     "initiator was inferred from the service port and the direction could be "
                     "inverted"}


class ExfilDetector(Detector):
    name = "exfil"
    classes = [THREAT]

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        cfg = dict(DEFAULTS)
        cfg.update(self.config)
        self.config = cfg
        self.suppressed = 0
        self.one_way = 0
        self.unoriented = 0
        self.peers = LruMap(int(cfg["peer_capacity"]), Peer, _PEER_BYTES)
        self.dst_fanout = WindowedHLLFamily(3600.0, 8, int(cfg["fanout_capacity"]), seed=81)

    def observe(self, meta: PacketMeta, flow: FlowState, ctx: Context) -> list[Detection]:
        if meta.proto not in (TCP, UDP):
            return []
        if flow.orientation_confidence < MIN_ORIENTATION:
            self.unoriented += 1
            return []
        client = flow.initiator_ip
        server = flow.responder_ip
        if meta.src_ip == client:
            direction = 1
        elif meta.src_ip == server:
            direction = -1
        else:
            return []
        self.dst_fanout.add(meta.ts_ns, server.to_bytes(4, "big"), client.to_bytes(4, "big"))
        peer = self.peers.get((client, server))
        peer.orient_conf = min(peer.orient_conf, float(flow.orientation_confidence))
        if peer.first_ts_ns == 0:
            peer.first_ts_ns = meta.ts_ns
            peer.win_sec = meta.ts_ns // 1_000_000_000
            peer.dst_port = flow.responder_port
        if direction > 0:
            peer.out_win += meta.length
            peer.out_total += meta.length
        else:
            peer.in_win += meta.length
            peer.in_total += meta.length
        return self._roll(peer, client, server, meta, ctx)

    def _roll(
        self, peer: Peer, client: int, server: int, meta: PacketMeta, ctx: Context
    ) -> list[Detection]:
        sec = meta.ts_ns // 1_000_000_000
        if sec - peer.win_sec < WINDOW_S:
            return []
        peer.win_sec = sec
        ratio = float(peer.out_win) / max(1.0, float(peer.in_win))
        alpha = float(self.config["ratio_alpha"])
        peer.ratio_ewma = ratio if peer.ratio_n == 0 else peer.ratio_ewma + alpha * (ratio - peer.ratio_ewma)
        peer.ratio_n += 1
        peer.windows += 1
        if ratio >= float(self.config["ratio_alert"]):
            peer.asym_windows += 1
        peer.peak_out_win = max(peer.peak_out_win, peer.out_win)
        peer.out_win = 0
        peer.in_win = 0
        feats = self._compute(peer, server, meta, ctx)
        self._features = feats
        det = self._rule(peer, client, server, meta, feats, ctx)
        if det is None:
            return []
        peer.last_alert_ns = meta.ts_ns
        return [det]

    def _compute(self, peer: Peer, server: int, meta: PacketMeta, ctx: Context) -> dict[str, float]:
        fanout = self.dst_fanout.count(meta.ts_ns, server.to_bytes(4, "big"))
        novelty = clamp01(1.0 - math.log1p(max(0.0, fanout - 1.0)) / math.log1p(
            float(self.config["novelty_horizon"])))
        total_out = float(peer.out_total)
        return {
            "out_in_byte_ratio": float(peer.out_total) / max(1.0, float(peer.in_total)),
            "out_in_ratio_ewma": float(peer.ratio_ewma),
            "sustained_asymmetry_s": float(peer.asym_windows * WINDOW_S),
            "outbound_bytes_total": total_out,
            "inbound_bytes_total": float(peer.in_total),
            "peak_window_out_bytes": float(peer.peak_out_win),
            "upload_burst_score": float(peer.peak_out_win) / total_out if total_out > 0 else 0.0,
            "dst_source_fanout_3600s": float(fanout),
            "dst_novelty_score": float(novelty),
            "peer_age_s": float(meta.ts_ns - peer.first_ts_ns) / 1e9,
            "reverse_direction_observed": 1.0 if peer.in_total > 0 else 0.0,
        }

    def _rule(
        self, peer: Peer, client: int, server: int, meta: PacketMeta, f: dict, ctx: Context
    ) -> Detection | None:
        cfg = self.config
        if f["out_in_ratio_ewma"] < float(cfg["ratio_alert"]):
            return None
        if f["outbound_bytes_total"] < float(cfg["min_outbound_bytes"]):
            return None
        if f["sustained_asymmetry_s"] < float(cfg["min_sustained_s"]):
            return None
        if meta.ts_ns - peer.last_alert_ns < float(cfg["cooldown_s"]) * 1e9:
            return None
        reason = ctx.reference.exfil_reason(server, peer.dst_port)
        if reason:
            self.suppressed += 1
            ctx.suppress(self.name, "exfil-allowlist", "{0}:{1}".format(format_ip(server), peer.dst_port))
            return None
        if f["reverse_direction_observed"] == 0.0:
            self.one_way += 1
            ctx.suppress(self.name, "reverse-direction-never-observed", format_ip(server))
        burst = f["peak_window_out_bytes"] >= float(cfg["burst_window_bytes"])
        margins = [
            margin(f["out_in_ratio_ewma"], float(cfg["ratio_alert"]), 20.0),
            margin(f["sustained_asymmetry_s"], float(cfg["min_sustained_s"]), 900.0),
            margin(f["dst_novelty_score"], 0.0, 1.0),
        ]
        end = meta.ts_ns / 1e9
        flow = flow_identifier(
            meta.proto, client, server, 0, int(peer.dst_port),
            peer.first_ts_ns / 1e9, end, "BIDIRECTIONAL" if peer.in_total else "FWD_ONLY",
            bool(peer.in_total),
        )
        if burst:
            return self._emit(
                meta.ts_ns, THREAT, SUB_BURST, margins, flow,
                evidence([
                    ("out_in_ratio_ewma", f["out_in_ratio_ewma"], margins[0]),
                    ("sustained_asymmetry_s", f["sustained_asymmetry_s"], margins[1]),
                    ("dst_novelty_score", f["dst_novelty_score"], margins[2]),
                    ("peak_window_out_bytes", f["peak_window_out_bytes"], 0.0),
                    ("upload_burst_score", f["upload_burst_score"], 0.0),
                ]),
                "bulk outbound transfer from {0} to {1}:{2}: {3:.1f} megabytes out against {4:.1f} in, "
                "ratio {5:.1f} to 1, with {6:.1f} megabytes inside a single {7} s window".format(
                    format_ip(client), format_ip(server), peer.dst_port,
                    f["outbound_bytes_total"] / 1e6, f["inbound_bytes_total"] / 1e6,
                    f["out_in_ratio_ewma"], f["peak_window_out_bytes"] / 1e6, WINDOW_S),
                {
                    "pattern": "burst",
                    "allowlist": "checked against data/reference/exfil_allowlist.json, no match",
                    "reverse_direction_observed": bool(peer.in_total),
                    "orientation": _orientation_note(peer.orient_conf),
                },
            )
        return self._emit(
            meta.ts_ns, THREAT, SUB_DRIP, margins, flow,
            evidence([
                ("out_in_ratio_ewma", f["out_in_ratio_ewma"], margins[0]),
                ("sustained_asymmetry_s", f["sustained_asymmetry_s"], margins[1]),
                ("dst_novelty_score", f["dst_novelty_score"], margins[2]),
                ("upload_burst_score", f["upload_burst_score"], 0.0),
                ("peak_window_out_bytes", f["peak_window_out_bytes"], 0.0),
            ]),
            "slow-drip upload from {0} to {1}:{2}: {3:.0f} kilobytes out against {4:.0f} in, an "
            "outbound to inbound ratio of {5:.1f} to 1 held for {6:.0f} s. the busiest single {7} s "
            "window carried only {8:.0f} kilobytes, which is {9:.1f} percent of the transfer, so a "
            "single-window byte threshold would never have seen it".format(
                format_ip(client), format_ip(server), peer.dst_port,
                f["outbound_bytes_total"] / 1e3, f["inbound_bytes_total"] / 1e3,
                f["out_in_ratio_ewma"], f["sustained_asymmetry_s"], WINDOW_S,
                f["peak_window_out_bytes"] / 1e3, 100.0 * f["upload_burst_score"]),
            {
                "pattern": "slow-drip",
                "why_ewma": "the alert is raised on an exponentially weighted mean of the per-window "
                            "ratio, not on any single window. that is the whole point: the transfer "
                            "never puts enough bytes into one window to trip a volume threshold",
                "allowlist": "checked against data/reference/exfil_allowlist.json, no match",
                "reverse_direction_observed": bool(peer.in_total),
                "orientation": _orientation_note(peer.orient_conf),
                "novelty_note": "novelty is the inverse of how many distinct internal hosts have "
                                "reached this destination in the last hour. a destination one host "
                                "talks to is more suspicious than a shared content network",
            },
        )

    def stats(self) -> dict:
        return {
            "name": self.name,
            "alerts": self.alerts,
            "peers": len(self.peers),
            "suppressed": self.suppressed,
            "unoriented_flows": self.unoriented,
            "one_way_peers": self.one_way,
            "peers_evicted": self.peers.evicted,
        }

    @property
    def nbytes(self) -> int:
        return int(self.peers.nbytes + self.dst_fanout.nbytes)
