"""Bounded, independent novelty windows for passive flow observations."""
from __future__ import annotations

import heapq
import math
import os
import statistics
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any

from engine.detect.base import flow_identifier_of
from engine.models.novelty import NOVELTY_FEATURES, NoveltyModel
from engine.types import FIN, RST, Evidence, FlowKey, FlowState, PacketMeta

GROUP_NAMESPACE = uuid.UUID("c7d1b815-98aa-4a40-9ec7-8fc5c7b26145")


@dataclass(slots=True)
class Window:
    key: FlowKey
    start_ns: int
    due_ns: int
    last_ns: int
    generation: int
    identity: dict
    packets_fwd: int = 0
    packets_rev: int = 0
    bytes_fwd: int = 0
    bytes_rev: int = 0
    gaps_us: list[float] = field(default_factory=list)
    previous_packet_ns: int = 0
    sequence_samples: int = 0


class NoveltyMonitor:
    """Owns cadence, capacity, calibration decisions, grouping, and coverage counters."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        cfg = dict(config or {})
        self.enabled = bool(cfg.get("enabled", False))
        self.shadow = bool(cfg.get("shadow", True))
        self.window_ns = max(100_000_000, int(float(cfg.get("window_s", 5.0)) * 1e9))
        self.capacity = max(1, int(cfg.get("capacity", 100_000)))
        self.work_budget = max(1, int(cfg.get("work_budget", 1_000)))
        self.queue_capacity = max(1, int(cfg.get("queue_capacity", 1_000)))
        self.min_packets = max(1, int(cfg.get("min_packets", 4)))
        self.review_tail = float(cfg.get("review_tail_fraction", 0.01))
        self.suspicious_tail = float(cfg.get("suspicious_tail_fraction", 0.001))
        self.persistence = max(1, int(cfg.get("persistence_windows", 2)))
        self.drift_threshold = float(cfg.get("drift_js_threshold", 0.20))
        if not 0 < self.suspicious_tail <= self.review_tail <= 1:
            raise ValueError("novelty tail fractions must satisfy 0 < suspicious <= review <= 1")
        directory = str(cfg.get("model_dir") or "data/novelty")
        require_signature = os.environ.get("SIH_PRODUCTION") == "1" and self.enabled
        self.model = NoveltyModel.load(directory, require_signature=require_signature,
                                       public_key=os.environ.get("SIH_NOVELTY_PUBLIC_KEY")) if self.enabled else None
        self.on_window = None
        self._states: OrderedDict[FlowKey, Window] = OrderedDict()
        self._due: list[tuple[int, int, FlowKey]] = []
        self._pending: deque = deque()
        self._generation = 0
        self._groups: OrderedDict[str, tuple[int, int, float, float]] = OrderedDict()
        self._drift_scores: deque[float] = deque(maxlen=max(64, int(cfg.get("drift_window", 256))))
        self._drift_js = 0.0
        self._drift_warning = False
        self.windows_eligible = 0
        self.windows_scored = 0
        self.windows_unsupported = 0
        self.windows_skipped = 0
        self.windows_evicted = 0
        self.alerts = 0

    @property
    def status(self) -> str:
        if not self.enabled:
            return "disabled"
        return "ready" if self.model is not None else "baseline-unavailable"

    def observe(self, meta: PacketMeta, flow: FlowState) -> list:
        if not self.enabled:
            return []
        key = flow.key
        state = self._states.get(key)
        if state is not None and meta.ts_ns >= state.due_ns:
            self._complete(key, state.due_ns, "cadence")
            state = None
        if state is None:
            self._generation += 1
            start = meta.ts_ns
            state = Window(key=key, start_ns=start, due_ns=start + self.window_ns, last_ns=start,
                           generation=self._generation,
                           identity=flow_identifier_of(flow, start / 1e9, start / 1e9))
            self._states[key] = state
            heapq.heappush(self._due, (state.due_ns, state.generation, key))
            if len(self._states) > self.capacity:
                old_key, old = self._states.popitem(last=False)
                self.windows_evicted += 1
                self._score(old, old.last_ns, "capacity-eviction")
        else:
            self._states.move_to_end(key)
        self._account(state, meta, flow)
        if meta.tcp_flags & (FIN | RST):
            self._complete(key, meta.ts_ns, "flow-close")
        return self.drain()

    def tick(self, now_ns: int) -> list:
        if not self.enabled:
            return []
        work = 0
        while self._due and self._due[0][0] <= now_ns and work < self.work_budget:
            _due, generation, key = heapq.heappop(self._due)
            state = self._states.get(key)
            if state is None or state.generation != generation:
                continue
            self._complete(key, min(now_ns, state.due_ns), "cadence")
            work += 1
        while self._due and self._due[0][0] <= now_ns:
            _due, generation, key = heapq.heappop(self._due)
            state = self._states.get(key)
            if state is None or state.generation != generation:
                continue
            self._states.pop(key, None)
            self.windows_skipped += 1
        return self.drain()

    def finalize(self, flow: FlowState, reason: str, *, drain: bool = True) -> list:
        if self.enabled:
            state = self._states.get(flow.key)
            if state is not None:
                self._complete(flow.key, state.last_ns, reason)
        return self.drain() if drain else []

    def drain(self) -> list:
        out = list(self._pending)
        self._pending.clear()
        return out

    def _complete(self, key: FlowKey, end_ns: int, reason: str) -> None:
        state = self._states.pop(key, None)
        if state is not None:
            self._score(state, max(state.start_ns, end_ns), reason)

    @staticmethod
    def _account(state: Window, meta: PacketMeta, flow: FlowState) -> None:
        forward = meta.src_ip == flow.initiator_ip and meta.src_port == flow.initiator_port
        if forward:
            state.packets_fwd += int(meta.packets)
            state.bytes_fwd += int(meta.length)
        else:
            state.packets_rev += int(meta.packets)
            state.bytes_rev += int(meta.length)
        if state.previous_packet_ns and meta.ts_ns >= state.previous_packet_ns and len(state.gaps_us) < 20:
            state.gaps_us.append((meta.ts_ns - state.previous_packet_ns) / 1000.0)
        state.previous_packet_ns = max(state.previous_packet_ns, meta.ts_ns)
        state.last_ns = max(state.last_ns, meta.ts_ns)
        state.sequence_samples = min(20, state.sequence_samples + (0 if meta.from_flow_record else 1))
        state.identity = flow_identifier_of(flow, state.start_ns / 1e9, state.last_ns / 1e9)
        state.identity["orientation_confidence"] = float(flow.orientation_confidence)

    def _features(self, state: Window, end_ns: int) -> dict[str, float]:
        duration = max(1e-6, (end_ns - state.start_ns) / 1e9)
        packets = state.packets_fwd + state.packets_rev
        byte_count = state.bytes_fwd + state.bytes_rev
        gaps = state.gaps_us
        return {
            "window_duration_s": duration,
            "packets_fwd": float(state.packets_fwd),
            "packets_rev": float(state.packets_rev),
            "bytes_fwd": float(state.bytes_fwd),
            "bytes_rev": float(state.bytes_rev),
            "packet_rate": packets / duration,
            "byte_rate": byte_count / duration,
            "mean_packet_size": byte_count / max(1, packets),
            "reverse_packet_share": state.packets_rev / max(1, packets),
            "completeness_flag": 1.0 if state.packets_fwd and state.packets_rev else 0.0,
            "orientation_confidence": float(state.identity.get("orientation_confidence", 0.0) or 0.0),
            "sequence_samples": float(state.sequence_samples),
            "sequence_iat_mean_us": statistics.fmean(gaps) if gaps else math.nan,
            "sequence_iat_std_us": statistics.pstdev(gaps) if len(gaps) > 1 else math.nan,
            "sequence_timing_available": 1.0 if len(gaps) > 1 else 0.0,
        }

    def _score(self, state: Window, end_ns: int, reason: str) -> None:
        packets = state.packets_fwd + state.packets_rev
        self.windows_eligible += 1
        if packets < self.min_packets:
            self.windows_unsupported += 1
            return
        values = self._features(state, end_ns)
        if self.on_window is not None:
            self.on_window({"start_ns": state.start_ns, "end_ns": end_ns, "reason": reason,
                            "identity": dict(state.identity), "values": dict(values)})
        if self.model is None:
            self.windows_unsupported += 1
            return
        if any(name not in values for name in NOVELTY_FEATURES):
            self.windows_unsupported += 1
            return
        result = self.model.score(values)
        self.windows_scored += 1
        tail = float(result["tail_fraction"])
        self._drift_scores.append(tail)
        if len(self._drift_scores) >= 64 and len(self._drift_scores) % 32 == 0:
            self._drift_js = _js_from_uniform(self._drift_scores, bins=10)
            self._drift_warning = self._drift_js >= self.drift_threshold
        if tail > self.review_tail:
            return
        subject = f"{state.identity.get('src_ip')}|{state.identity.get('dst_ip')}|{state.identity.get('dst_port')}"
        group_id = "novelty--" + str(uuid.uuid5(GROUP_NAMESPACE, subject))
        previous = self._groups.get(group_id)
        count = 1 if previous is None or state.start_ns - previous[1] > self.window_ns * 6 else previous[0] + 1
        first = state.start_ns if previous is None else previous[1] if previous[0] == 0 else previous[2]
        self._groups[group_id] = (count, end_ns, float(first), tail)
        self._groups.move_to_end(group_id)
        while len(self._groups) > 4096:
            self._groups.popitem(last=False)
        decision = "unknown-suspicious" if tail <= self.suspicious_tail and count >= self.persistence else "novelty-review"
        if self.shadow:
            return
        priority = min(0.99, max(0.01, 1.0 - tail))
        deviations = sorted(result["deviations"].items(), key=lambda item: item[1], reverse=True)
        evidence = [Evidence(name, float(values[name]) if math.isfinite(float(values[name])) else 0.0, float(weight))
                    for name, weight in deviations[:5]]
        context = {
            "detector": "novelty-companion",
            "evidence_basis": "absolute robust deviation from the approved benign novelty-v1 reference",
            "calibrated": False,
            "novelty": {
                "schema_version": "novelty-context-v1",
                "decision": decision,
                "reason_codes": ["benign-tail-exceedance", reason],
                "raw_anomaly_score": round(float(result["raw_score"]), 8),
                "benign_tail_fraction": round(tail, 8),
                "score_direction": "smaller tail fraction means rarer versus the approved benign calibration set",
                "score_meaning": "rarity, not probability of an attack or zero-day",
                "calibration_count": int(result["calibration_count"]),
                "model_hash": self.model.meta.get("model_hash", "none"),
                "baseline_hash": self.model.meta.get("baseline_hash", "none"),
                "extractor_version": "novelty-v1",
                "threshold_policy_version": "novelty-policy-v1",
                "missing_fields": [name for name, value in values.items() if not math.isfinite(value)],
                "observation_source": "packet-metadata",
                "direction_coverage": "two-sided" if state.packets_fwd and state.packets_rev else "one-sided",
                "window_start_ns": state.start_ns,
                "window_end_ns": end_ns,
                "group_id": group_id,
                "group_windows": count,
                "review_status": "unreviewed",
                "retained_evidence_ref": group_id,
            },
        }
        from engine.types import Detection
        detection = Detection(
            ts_ns=end_ns,
            threat_class="unknown-suspicious",
            subtype=decision,
            confidence=priority,
            severity="HIGH" if decision == "unknown-suspicious" else "MEDIUM",
            source="novelty-companion",
            flow=state.identity,
            evidence=evidence,
            summary=("This behaviour is unusual compared with the approved benign baseline. "
                     "It may be an unfamiliar attack or a legitimate change; analyst review is required."),
            context=context,
        )
        if len(self._pending) >= self.queue_capacity:
            self.windows_skipped += 1
            return
        self._pending.append(detection)
        self.alerts += 1

    def stats(self) -> dict:
        model_bytes = self.model.nbytes if self.model is not None else 0
        return {
            "status": self.status,
            "shadow": self.shadow,
            "feature_contract": "novelty-v1",
            "active_windows": len(self._states),
            "capacity": self.capacity,
            "queued_alerts": len(self._pending),
            "queue_capacity": self.queue_capacity,
            "eligible": self.windows_eligible,
            "scored": self.windows_scored,
            "unsupported": self.windows_unsupported,
            "skipped": self.windows_skipped,
            "evicted": self.windows_evicted,
            "alerts": self.alerts,
            "coverage_degraded": self.windows_skipped > 0,
            "drift_warning": self._drift_warning,
            "drift_js_divergence": round(self._drift_js, 6),
            "drift_note": "model-health signal only; it never changes the approved baseline or labels traffic",
            "model_bytes": model_bytes,
        }


def _js_from_uniform(values, bins: int) -> float:
    counts = [0] * bins
    for value in values:
        counts[min(bins - 1, max(0, int(float(value) * bins)))] += 1
    total = float(sum(counts))
    observed = [count / total for count in counts]
    expected = [1.0 / bins] * bins
    middle = [(left + right) / 2.0 for left, right in zip(observed, expected)]

    def kl(left, right):
        return sum(p * math.log(p / q, 2) for p, q in zip(left, right) if p > 0 and q > 0)

    return 0.5 * kl(observed, middle) + 0.5 * kl(expected, middle)
