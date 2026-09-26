from __future__ import annotations

import math

import numpy as np

from engine.analysis.lombscargle import MAX_EVENT_BINS, N_FREQS, PeriodogramBudgetExceeded, peak_period_from_iats
from engine.decode.packet import format_ip
from engine.detect.base import (
    Context,
    Detector,
    evidence,
    flow_identifier,
    margin,
)
from engine.detect.base import LruMap
from engine.state.welford import Moments
from engine.types import ACK, SYN, TCP, UDP, Detection, FlowKey, FlowState, PacketMeta

THREAT = "c2-beaconing"
SUB_BEACON = "periodic-c2-checkin"

CHANNEL_BYTES = 420

DEFAULTS = {
    "fap_max": 1e-3,
    "min_power": 8.0,
    "min_stability": 0.5,
    "min_period_s": 2.0,
    "cv_max": 0.75,
    "regular_cv_max": 0.35,
    "regular_min_samples": 20,
    "regular_period_agreement": 0.15,
    "n_freqs": N_FREQS,
    "channel_capacity": 20000,
    "alert_cooldown_s": 900.0,
    "busy_source_min_samples": 0,
    "busy_source_cv_max": 0.25,
    "busy_source_min_span_s": 600.0,
    "max_assessments_per_tick": 0,
}


def coverage(ring: int, min_samples: int, ttl_s: float) -> dict[str, float]:
    return {
        "min_samples": float(min_samples),
        "ring_samples": float(ring),
        "max_period_s": float(ttl_s),
        "min_observation_s_for_max_period": float(min_samples) * float(ttl_s),
        "observation_multiple": float(min_samples),
    }


COVERAGE_NOTE = (
    "a period is only assessable after min_samples gaps have been observed, so the time to first "
    "decision is min_samples times the period. with 12 samples a 45 s beacon is assessable after "
    "about 9 minutes and a 30 minute beacon after about 6 hours. the beacon table drops a candidate "
    "whose gap exceeds the 21600 s ttl, so 21600 s is the longest period this build can represent "
    "at all. nothing here detects a beacon whose period exceeds the capture length"
)


def _clause_text(significant: bool, power: float, fap: float, moments: Moments) -> str:
    if significant:
        return ("the lomb-scargle peak has normalised power {0:.1f} and a false alarm probability "
                "of {1:.1e}".format(power, fap))
    return ("the periodogram peak is not significant on its own (power {0:.1f}, false alarm "
            "probability {1:.1e}), so this is carried by gap regularity instead: the recovered "
            "period agrees with the mean gap of {2:.1f} s".format(power, fap, moments.mean))


class BeaconDetector(Detector):
    name = "beaconing"
    classes = [THREAT]

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        cfg = dict(DEFAULTS)
        cfg.update(self.config)
        self.config = cfg
        self.evaluated = 0
        self.rejected_fap = 0
        self.carried_by_regularity = 0
        self.rejected_stability = 0
        self.resource_budget_skipped = 0
        self.coverage: dict[str, float] = {}
        self.sessions = 0
        self.channels: LruMap = LruMap(int(cfg["channel_capacity"]), lambda: None, CHANNEL_BYTES)
        self.last_alert: LruMap = LruMap(4096, lambda: 0, 120)

    def observe(self, meta: PacketMeta, flow: FlowState, ctx: Context) -> list[Detection]:
        if meta.proto not in (TCP, UDP):
            return []
        if flow.orientation_confidence > 0.0:
            client, server, port = flow.initiator_ip, flow.responder_ip, flow.responder_port
        else:
            client, server, port = meta.src_ip, meta.dst_ip, meta.dst_port
        key = (meta.proto, client, server, port)
        channel = self.channels.peek(key)
        if channel is None:
            channel = FlowState(
                key=FlowKey(meta.proto, client, 0, server, port),
                first_ts_ns=meta.ts_ns,
                last_ts_ns=meta.ts_ns,
                initiator_ip=client,
                initiator_port=0,
                responder_ip=server,
                responder_port=port,
                orientation_confidence=1.0,
            )
            self.channels.put(key, channel)
        else:
            self.channels.get(key)
        if meta.src_ip == client:
            channel.pkts_fwd += meta.packets
            channel.bytes_fwd += meta.length
        else:
            channel.pkts_rev += meta.packets
            channel.bytes_rev += meta.length
        channel.last_ts_ns = max(channel.last_ts_ns, meta.ts_ns)
        if self._session_start(meta, flow):
            self.sessions += 1
            ctx.beacons.observe(meta, channel)
        return []

    def _regular(self, moments: Moments, period: float, samples: int) -> bool:
        cfg = self.config
        if samples < int(cfg["regular_min_samples"]) or moments.mean <= 0.0:
            return False
        if moments.cv > float(cfg["regular_cv_max"]):
            return False
        return abs(period - moments.mean) / moments.mean < float(cfg["regular_period_agreement"])

    @staticmethod
    def _session_start(meta: PacketMeta, flow: FlowState) -> bool:
        if meta.proto == TCP:
            return bool(meta.tcp_flags & SYN) and not bool(meta.tcp_flags & ACK)
        return flow.packets <= meta.packets

    def tick(self, now_ns: int, ctx: Context) -> list[Detection]:
        table = ctx.beacons
        if not self.coverage:
            self.coverage = coverage(table.ring, table.min_samples, table.ttl_ns / 1e9)
        out: list[Detection] = []
        for key, iats, stability in table.ready(now_ns, int(self.config["max_assessments_per_tick"])):
            try:
                det = self._assess(key, iats, stability, now_ns)
            except PeriodogramBudgetExceeded:
                self.resource_budget_skipped += 1
                ctx.suppress(self.name, "periodogram-event-bin-budget", str(key))
                continue
            if det is not None:
                out.append(det)
        return out

    def _assess(self, key, iats: np.ndarray, stability: float, now_ns: int) -> Detection | None:
        cfg = self.config
        self.evaluated += 1
        gaps = np.asarray(iats, dtype=np.float64)
        if gaps.size < 4:
            return None
        moments = Moments()
        for gap in gaps:
            moments.add(float(gap))
        period, power, fap = peak_period_from_iats(gaps, int(cfg["n_freqs"]))
        span = float(gaps.sum())
        feats = {
            "iat_mean": float(moments.mean),
            "iat_std": float(moments.std),
            "iat_cv": float(moments.cv),
            "iat_skew": float(moments.skew),
            "iat_kurtosis": float(moments.kurtosis),
            "ls_peak_period_s": float(period),
            "ls_peak_power": float(power),
            "ls_fap": float(fap),
            "dst_stability": float(stability),
            "beacon_sample_count": float(gaps.size),
            "beacon_span_s": span,
        }
        self._features = feats
        if period < float(cfg["min_period_s"]):
            return None
        significant = fap < float(cfg["fap_max"]) and power >= float(cfg["min_power"])
        regular = self._regular(moments, period, int(gaps.size))
        if not significant and not regular:
            self.rejected_fap += 1
            return None
        # A host can beacon while also browsing, scanning, or uploading. A
        # lifetime host-wide fanout must not veto a strongly periodic channel.
        # The live preset enables this stricter, explicitly uncalibrated branch;
        # retain the original measured stability feature rather than inventing 1.
        busy_min = int(cfg["busy_source_min_samples"])
        busy_channel = (stability < float(cfg["min_stability"]) and busy_min > 0
                        and gaps.size >= busy_min and span >= float(cfg["busy_source_min_span_s"])
                        and moments.cv <= float(cfg["busy_source_cv_max"]) and regular)
        if stability < float(cfg["min_stability"]) and not busy_channel:
            self.rejected_stability += 1
            return None
        if moments.cv > float(cfg["cv_max"]):
            return None
        if now_ns - int(self.last_alert.get(key)) < float(cfg["alert_cooldown_s"]) * 1e9:
            return None
        self.last_alert.put(key, now_ns)
        stability_margin = margin(stability, float(cfg["min_stability"]), 0.5)
        if significant:
            margins = [
                margin(-math.log10(max(fap, 1e-30)), 3.0, 3.0),
                margin(power, float(cfg["min_power"]), 20.0),
                stability_margin,
            ]
            rows = [
                ("ls_fap", fap, margins[0]),
                ("ls_peak_power", power, margins[1]),
                ("dst_stability", stability, margins[2]),
                ("ls_peak_period_s", period, 0.0),
                ("iat_cv", moments.cv, 0.0),
                ("beacon_sample_count", float(gaps.size), 0.0),
            ]
        else:
            self.carried_by_regularity += 1
            margins = [
                margin(float(cfg["regular_cv_max"]) - moments.cv, 0.0, float(cfg["regular_cv_max"])),
                margin(float(gaps.size), float(cfg["regular_min_samples"]), 60.0),
                stability_margin,
            ]
            rows = [
                ("iat_cv", moments.cv, margins[0]),
                ("beacon_sample_count", float(gaps.size), margins[1]),
                ("dst_stability", stability, margins[2]),
                ("ls_peak_period_s", period, 0.0),
                ("ls_peak_power", power, 0.0),
                ("ls_fap", fap, 0.0),
            ]
        proto, src_ip, dst_ip, dst_port = key
        flow = flow_identifier(
            int(proto), src_ip, dst_ip, 0, int(dst_port), (now_ns / 1e9) - span, now_ns / 1e9,
            "FWD_ONLY", False,
        )
        return self._emit(
            now_ns, THREAT, "busy-source-periodic-channel" if busy_channel else SUB_BEACON, margins, flow,
            evidence(rows),
            "periodic check-in from {0} to {1}:{2} every {3:.1f} s. {4}. this source contacts "
            "effectively one destination (stability {5:.2f}) and the inter-arrival coefficient of "
            "variation is {6:.2f} over {7:.0f} gaps".format(
                format_ip(src_ip), format_ip(dst_ip), int(dst_port), period,
                _clause_text(significant, power, fap, moments), stability, moments.cv,
                float(gaps.size)) if not busy_channel else
            (f"Periodic channel from {format_ip(src_ip)} to {format_ip(dst_ip)}:{dst_port}: "
             f"mean gap {moments.mean:.1f} s, variability {moments.cv:.3f}, {gaps.size} gaps. "
             f"This host also contacts other destinations (stability {stability:.3f}). "
             "Strong channel regularity warrants review; legitimate automated polling can look similar."),
            {
                **({"extended_detection": True, "busy_source_channel": True} if busy_channel else {}),
                "carried_by": "periodogram significance" if significant else "gap regularity",
                "clauses": {
                    "periodogram": {"passed": bool(significant), "power": round(float(power), 2),
                                    "fap": float(fap)},
                    "regularity": {"passed": bool(regular), "iat_cv": round(float(moments.cv), 3),
                                   "period_vs_mean_gap": round(
                                       abs(period - moments.mean) / moments.mean, 3)
                                   if moments.mean > 0.0 else None,
                                   "samples": int(gaps.size)},
                },
                "method": "classical lomb-scargle periodogram over a log-spaced grid of {0} trial "
                          "frequencies, run on the binned arrival train rather than the raw gap "
                          "series, because a jittered beacon's gap series is noise while its arrival "
                          "times are not".format(int(cfg["n_freqs"])),
                "cost": "{0} trial frequencies by {1} samples, evaluated once per candidate per "
                        "recheck interval and only on the pre-filtered subset".format(
                            int(cfg["n_freqs"]), int(gaps.size)),
                "coverage": self.coverage,
                "coverage_note": COVERAGE_NOTE,
                "limit_note": "a periodogram recovers a period only when jitter is around a fixed "
                              "schedule. if the implant sleeps for period times a random factor the "
                              "phase is a random walk and no periodogram holds coherence, which is "
                              "why the regularity clause exists: a tight coefficient of variation "
                              "over enough gaps, with the recovered period agreeing with the mean "
                              "gap, is accepted on its own and is labelled as such",
            },
        )

    def stats(self) -> dict:
        return {
            "name": self.name,
            "alerts": self.alerts,
            "evaluated": self.evaluated,
            "rejected_fap": self.rejected_fap,
            "carried_by_regularity": self.carried_by_regularity,
            "rejected_stability": self.rejected_stability,
            "resource_budget_skipped": self.resource_budget_skipped,
            "event_bin_limit": MAX_EVENT_BINS,
            "max_assessments_per_tick": int(self.config["max_assessments_per_tick"]),
            "sessions": self.sessions,
            "channels": len(self.channels),
            "coverage": self.coverage,
        }

    @property
    def nbytes(self) -> int:
        return int(self.channels.nbytes)
