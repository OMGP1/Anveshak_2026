from __future__ import annotations

import math
from collections import OrderedDict
import os
import time
from typing import Any, Callable

from engine.analysis.novelty import NoveltyMonitor
from engine.decode.packet import TLS_PORTS
from engine.detect.base import Context, flow_identifier_of, severity_for
from engine.metrics import Meter
from engine.models.anomaly import AnomalyModel
from engine.models.gate import PromotionGate
from engine.models.rules import RuleLayer, rule_verdict, subject_endpoint
from engine.models.support import supports_class
from engine.models.tier1 import MODEL_DIR, MODEL_FEATURES, Tier1Model
from engine.state.cms import CountMinSketch
from engine.state.entropy import SlidingEntropy
from engine.state.flow_table import FlowTable
from engine.types import UDP, Detection, Evidence, FlowState, PacketMeta

STAGES = ("flow_table", "detect", "features", "tier1", "alert")

DEFAULT_CONFIG: dict[str, Any] = {
    "flow_capacity": 200_000,
    "flow_idle_timeout_s": 120.0,
    "collect_splt": True,
    "model_dir": MODEL_DIR,
    "model_enabled": True,
    "anomaly_enabled": True,
    "ensemble_min_confidence": 0.50,
    "model_alert_confidence": 0.99,
    "model_alert_cooldown_s": 600.0,
    "model_alert_max_per_class": 3,
    "model_alert_min_evidence": 2,
    "anomaly_alert_score": 0.50,
    "entropy_window_s": 1.0,
    "gate": {},
    "detectors": {},
    "context": {},
    "novelty": {"enabled": False, "shadow": True},
}

STAGE_TIMING_NOTE = (
    "stage_timing_us is a mean per call and the stages are called different numbers of times, so "
    "the five figures must not be added. stage_timing_per_packet_us divides the same totals by the "
    "packet count, and those do add up to the per-packet cost"
)

EVIDENCE_BASIS_RULE = "rule clause weight, one entry per clause of the deterministic rule"
EVIDENCE_BASIS_MODEL = "exact treeshap contribution from the same lightgbm pred_contrib call"

ANOMALY_BASIS = (
    "a model-only alert must also sit above the median of the benign training distribution of the "
    "isolation forest, which is a stated principle rather than a threshold fitted on test data"
)

FEATURE_SET = frozenset(MODEL_FEATURES)


class Engine:
    name = "engine.pipeline"

    def __init__(self, config: dict | None = None) -> None:
        cfg = dict(DEFAULT_CONFIG)
        cfg.update(config or {})
        self.config = cfg
        self.meter = Meter()
        # The companion owns its own cadence and artifact contract. It is created
        # before FlowTable because capacity eviction calls back into it.
        self.novelty = NoveltyMonitor(cfg.get("novelty") or {})
        self.flows = FlowTable(
            capacity=int(cfg["flow_capacity"]),
            idle_timeout_s=float(cfg["flow_idle_timeout_s"]),
            collect_splt=bool(cfg["collect_splt"]),
            on_evict=self._on_evict,
        )
        self.ctx = Context(cfg.get("context") or {})
        self.rules = RuleLayer(cfg.get("detectors") or {})
        self.gate = PromotionGate(cfg.get("gate") or {})
        directory = str(cfg["model_dir"])
        self.tier1 = Tier1Model.load(directory) if cfg["model_enabled"] else None
        self.anomaly = AnomalyModel.load(directory) if cfg["anomaly_enabled"] else None
        self.src_entropy = SlidingEntropy(float(cfg["entropy_window_s"]), 20)
        self.dst_sketch = CountMinSketch()
        self.on_vector: Callable[[dict], None] | None = None
        self.packets = 0
        self.detections = 0
        self.scored = 0
        self.model_alerts = 0
        self.model_rate_limited = 0
        self.model_evidence_rejected = 0
        self.ensemble_alerts = 0
        self.high_flows = 0
        self.low_flows = 0
        self.evicted_flows = 0
        self.opaque_flows = 0
        self.quic_flows = 0
        self.no_sni_flows = 0
        self.last_values: dict[str, float] = {}
        self._cooldown: OrderedDict[tuple[str, int], int] = OrderedDict()
        self._class_window: dict[str, tuple[int, int]] = {}
        self._swept = False
        self._register()

    def _register(self) -> None:
        self.meter.track("flow_table", self.flows)
        self.meter.track("beacon_table", self.ctx.beacons)
        self.meter.track("entropy", self.src_entropy)
        self.meter.track("dst_sketch", self.dst_sketch)

    def feed(self, meta: PacketMeta) -> list[Detection]:
        self.packets += 1
        t0 = time.perf_counter_ns()
        flow = self.flows.observe(meta)
        self.src_entropy.add(meta.ts_ns, meta.src_ip.to_bytes(4, "big"))
        self.dst_sketch.add(meta.dst_ip.to_bytes(4, "big"))
        if meta.tls is not None and meta.tls.is_client_hello and not meta.tls.sni_present:
            self.no_sni_flows += 1
        t1 = time.perf_counter_ns()
        self.ctx.begin_packet(meta, flow)
        detections = self.rules.observe(meta, flow, self.ctx)
        novelty = self.novelty.observe(meta, flow)
        t2 = time.perf_counter_ns()
        self.meter.observe_stage("flow_table", t1 - t0)
        self.meter.observe_stage("detect", t2 - t1)
        if not detections and not self.rules.fresh:
            self.detections += len(novelty)
            return novelty
        out = self._decide(meta.ts_ns, flow, detections, self.rules.snapshot(flow), t2)
        out.extend(novelty)
        self.detections += len(out)
        return out

    def tick(self, now_ns: int) -> list[Detection]:
        out: list[Detection] = []
        for flow in self.flows.expire(now_ns):
            out.extend(self.novelty.finalize(flow, "idle-expiry"))
            self._classify(flow)
        out.extend(self.novelty.tick(now_ns))
        t0 = time.perf_counter_ns()
        groups = self.rules.tick_grouped(now_ns, self.ctx)
        t1 = time.perf_counter_ns()
        self.meter.observe_stage("detect", t1 - t0)
        for detections, values, ident in groups:
            out.extend(self._decide(now_ns, None, detections, values, time.perf_counter_ns(), ident))
        self.detections += len(out)
        return out

    def sweep(self) -> list[Detection]:
        if self._swept:
            return []
        self._swept = True
        out: list[Detection] = []
        for flow in list(self.flows):
            out.extend(self.novelty.finalize(flow, "end-of-stream"))
            self._classify(flow)
        self.detections += len(out)
        return out

    def _decide(self, ts_ns: int, flow: FlowState | None, detections: list[Detection],
                values: dict[str, float], t_start: int,
                ident: dict | None = None) -> list[Detection]:
        values = dict(values)
        for det in detections:
            for item in det.evidence:
                if item.feature in FEATURE_SET:
                    values[item.feature] = float(item.value)
        self.last_values = values
        t_feat = time.perf_counter_ns()
        unsupported_sequence = (flow is not None and flow.key.proto == UDP
                                and "encrypted" in self.rules.fresh)
        # Collect UDP/443 timing metadata without applying a TCP/TLS-trained model
        # to an unsupported transport and inventing a calibrated malware verdict.
        score = self.tier1.score(values) if self.tier1 is not None and not unsupported_sequence else None
        decision = self.gate.decide(score, values)
        candidate = (self._model_candidate(score, detections) and self._model_supported(score, values, flow)
                     and self._quota_ok(ts_ns, flow, score))
        anomaly = None
        if self.anomaly is not None and (decision.promote or candidate):
            anomaly = self.anomaly.score(values)
        emit_model = candidate and self._anomaly_ok(anomaly)
        if score is not None and (emit_model or self._ensemble_ready(score, detections)):
            score = self.tier1.score(values, explain=True)
        t_model = time.perf_counter_ns()
        self.scored += 1 if score is not None else 0
        if self.on_vector is not None:
            self.on_vector(self._row(ts_ns, flow, detections, values, ident))
        out = list(detections)
        for det in detections:
            self._enrich(det, score, decision, anomaly)
        if emit_model:
            extra = self._model_alert(ts_ns, flow, score, decision, anomaly)
            if extra is not None:
                out.append(extra)
        self.meter.observe_stage("features", t_feat - t_start)
        self.meter.observe_stage("tier1", t_model - t_feat)
        self.meter.observe_stage("alert", time.perf_counter_ns() - t_model)
        return out

    def _model_candidate(self, score, detections: list[Detection]) -> bool:
        if detections or score is None or score.top_class == "benign":
            return False
        return score.confidence >= float(self.config["model_alert_confidence"])

    def _model_supported(self, score, values: dict, flow: FlowState | None) -> bool:
        exfil = self.rules.by_name.get("exfil")
        minimum = float(exfil.config["min_outbound_bytes"]) if exfil else 100_000
        allowed = supports_class(score.top_class, values, minimum)
        if score.top_class == "dga-dns-tunnelling":
            dns = self.rules.by_name.get("dga")
            allowed = allowed and not getattr(dns, "model_suppressed", False)
        if score.top_class == "data-exfiltration" and flow is not None:
            allowed = allowed and not self.ctx.reference.exfil_reason(flow.responder_ip, flow.responder_port)
        if not allowed:
            self.model_evidence_rejected += 1
        return bool(allowed)

    @staticmethod
    def _subject(threat_class: str, flow: FlowState) -> tuple[str, int]:
        if subject_endpoint(threat_class) == "dst":
            return threat_class, flow.responder_ip
        return threat_class, flow.initiator_ip

    def _quota_ok(self, ts_ns: int, flow: FlowState | None, score) -> bool:
        if flow is None:
            return False
        window_ns = int(float(self.config["model_alert_cooldown_s"]) * 1e9)
        last = self._cooldown.get(self._subject(score.top_class, flow), 0)
        if last and ts_ns - last < window_ns:
            self.model_rate_limited += 1
            return False
        start, count = self._class_window.get(score.top_class, (ts_ns, 0))
        if ts_ns - start >= window_ns:
            return True
        maximum = int(self.config["model_alert_max_per_class"])
        if maximum > 0 and count >= maximum:
            self.model_rate_limited += 1
            return False
        return True

    def _anomaly_ok(self, anomaly: float | None) -> bool:
        if self.anomaly is None:
            return True
        return anomaly is not None and anomaly >= float(self.config["anomaly_alert_score"])

    def _ensemble_ready(self, score, detections: list[Detection]) -> bool:
        floor = float(self.config["ensemble_min_confidence"])
        return any(not (det.context or {}).get("extended_detection")
                   and score.top_class == det.threat_class and score.confidence >= floor
                   for det in detections)

    def _row(self, ts_ns: int, flow: FlowState | None, detections: list[Detection],
             values: dict[str, float], ident: dict | None = None) -> dict:
        rule_class, rule_conf = rule_verdict(detections)
        if flow is not None:
            ident = flow_identifier_of(flow, flow.first_ts_ns / 1e9, flow.last_ts_ns / 1e9)
        elif not ident and detections:
            ident = detections[0].flow
        ident = ident or {}
        return {
            "ts": ts_ns / 1e9,
            "ts_ns": ts_ns,
            "proto": str(ident.get("proto", "")),
            "src_ip": str(ident.get("src_ip", "")),
            "dst_ip": str(ident.get("dst_ip", "")),
            "src_port": int(ident.get("src_port", 0) or 0),
            "dst_port": int(ident.get("dst_port", 0) or 0),
            "fresh": "|".join(self.rules.fresh),
            "rule_class": rule_class,
            "rule_confidence": float(rule_conf),
            "rule_subtype": detections[0].subtype if detections else "",
            "values": values,
        }

    def _enrich(self, det: Detection, score, decision, anomaly: float | None) -> None:
        det.context = dict(det.context or {})
        det.context["gate"] = {"promoted": decision.promote, "reason": decision.reason}
        det.context["evidence_basis"] = EVIDENCE_BASIS_RULE
        det.context["calibrated"] = False
        if det.context.get("extended_detection"):
            det.context["calibration_note"] = (
                "Extended rule subtypes are not validated by the existing model's calibration. "
                "Confidence is a rule margin, not a measured probability of attack."
            )
            return
        if anomaly is not None:
            det.context["anomaly_percentile"] = round(float(anomaly), 4)
        if score is None:
            return
        det.context["model"] = {
            "top_class": score.top_class,
            "confidence": round(score.confidence, 4),
            "raw_confidence": round(score.raw_confidence, 4),
            "agrees": score.top_class == det.threat_class,
            "probs": {name: round(value, 4) for name, value in score.probs.items()},
        }
        floor = float(self.config["ensemble_min_confidence"])
        if score.top_class != det.threat_class or score.confidence < floor:
            return
        det.context["rule_evidence"] = [
            {"feature": item.feature, "value": item.value, "weight": item.contribution}
            for item in det.evidence
        ]
        shap = self._shap_evidence(score)
        if shap:
            det.evidence = shap
            det.context["evidence_basis"] = EVIDENCE_BASIS_MODEL
        det.context["rule_confidence"] = round(float(det.confidence), 4)
        det.source = "ensemble"
        det.confidence = round(float(score.confidence), 4)
        det.severity = severity_for(det.confidence)
        det.context["calibrated"] = True
        self.ensemble_alerts += 1

    @staticmethod
    def _shap_evidence(score) -> list[Evidence]:
        rows = []
        for name, value, weight in score.contributions:
            if not math.isfinite(value) or not math.isfinite(weight):
                continue
            rows.append(Evidence(feature=name, value=float(value), contribution=float(weight)))
        return rows[:5]

    def _model_alert(self, ts_ns: int, flow: FlowState, score, decision,
                     anomaly: float | None) -> Detection | None:
        evidence = self._shap_evidence(score)
        if len(evidence) < int(self.config["model_alert_min_evidence"]):
            return None
        window_ns = int(float(self.config["model_alert_cooldown_s"]) * 1e9)
        start, count = self._class_window.get(score.top_class, (ts_ns, 0))
        if ts_ns - start >= window_ns:
            start, count = ts_ns, 0
        self._class_window[score.top_class] = (start, count + 1)
        self._cooldown[self._subject(score.top_class, flow)] = ts_ns
        self._cooldown.move_to_end(self._subject(score.top_class, flow))
        if len(self._cooldown) > 4096:
            self._cooldown.popitem(last=False)
        self.model_alerts += 1
        ident = flow_identifier_of(flow, flow.first_ts_ns / 1e9, flow.last_ts_ns / 1e9)
        context = {
            "detector": "tier1",
            "evidence_basis": EVIDENCE_BASIS_MODEL,
            "calibrated": True,
            "gate": {"promoted": decision.promote, "reason": decision.reason},
            "model": {
                "top_class": score.top_class,
                "confidence": round(score.confidence, 4),
                "raw_confidence": round(score.raw_confidence, 4),
                "agrees": False,
                "probs": {name: round(value, 4) for name, value in score.probs.items()},
            },
            "model_only": True,
            "anomaly_basis": ANOMALY_BASIS,
        }
        if anomaly is not None:
            context["anomaly_percentile"] = round(float(anomaly), 4)
        confidence = round(float(score.confidence), 4)
        return Detection(
            ts_ns=ts_ns,
            threat_class=score.top_class,
            subtype="model-only",
            confidence=confidence,
            severity=severity_for(confidence),
            source="model",
            flow=ident,
            evidence=evidence,
            summary=(f"Model-supported {score.top_class} suspicion: observed class-specific metadata "
                     f"passed the evidence and anomaly gates; confidence {score.confidence:.1%}."),
            context=context,
        )

    def _classify(self, flow: FlowState) -> None:
        key = flow.key
        ports = (key.lo_port, key.hi_port)
        if key.proto == UDP and 443 in ports:
            self.quic_flows += 1
            self.opaque_flows += 1
        elif any(port in TLS_PORTS for port in ports) and flow.completeness_flag and not flow.ja4:
            self.opaque_flows += 1
        elif flow.completeness_flag and flow.orientation_confidence >= 1.0:
            self.high_flows += 1
        else:
            self.low_flows += 1

    def lineage(self) -> dict:
        base = self.tier1.lineage() if self.tier1 is not None else {
            "model_id": "rules-only",
            "model_hash": "none",
            "dataset_version": "none",
        }
        base.update(self.gate.lineage())
        return base

    def lineage_for(self, detection: Detection) -> dict:
        if detection.source == "novelty-companion":
            novelty = (detection.context or {}).get("novelty") or {}
            return {
                "model_id": "novelty-companion-v1",
                "model_hash": str(novelty.get("model_hash", "none")),
                "dataset_version": str(novelty.get("baseline_hash", "none")),
                "calibrated": False,
                "detector": "novelty-companion",
            }
        out = self.lineage()
        out["calibrated"] = bool((detection.context or {}).get("calibrated", False))
        out["detector"] = str((detection.context or {}).get("detector", detection.source))
        return out

    def memory_bytes(self) -> dict[str, int]:
        detail = self.ctx.memory_bytes()
        models = 0
        if self.tier1 is not None:
            models += int(self.tier1.nbytes)
        if self.anomaly is not None:
            models += int(self.anomaly.nbytes)
        if self.novelty.model is not None:
            models += int(self.novelty.model.nbytes)
        return {
            "flow_table": int(self.flows.nbytes),
            "beacon_table": int(detail["beacon_table"]),
            "sketches": int(detail["scan_hll"] + detail["dns_hll"] + self.src_entropy.nbytes
                            + self.dst_sketch.nbytes + self.rules.nbytes),
            "models": int(models),
        }

    def memory_caps_bytes(self) -> dict[str, int]:
        detail = self.ctx.memory_caps_bytes()
        current = self.memory_bytes()
        sketches = (detail["scan_hll"] + detail["dns_hll"] + self.src_entropy.nbytes
                    + self.dst_sketch.nbytes + self.rules.nbytes)
        return {
            "flow_table": int(self.flows.capacity_bytes),
            "beacon_table": int(detail["beacon_table"]),
            "sketches": int(max(sketches, current["sketches"])),
            "models": int(current["models"]),
        }

    def _on_evict(self, flow: FlowState) -> None:
        self.evicted_flows += 1
        # The next observe/tick drains this bounded pending queue through the
        # normal output owner; callbacks never write evidence directly.
        self.novelty.finalize(flow, "flow-table-capacity-eviction", drain=False)
        self._classify(flow)

    def stage_timing_us(self) -> dict[str, float]:
        out = {}
        for name in STAGES:
            calls = max(1, self.meter.stage_calls.get(name, 0))
            out[name] = round(self.meter.stage_ns.get(name, 0.0) / 1000.0 / calls, 3)
        return out

    def stage_timing_per_packet_us(self) -> dict[str, float]:
        packets = max(1, self.packets)
        return {name: round(self.meter.stage_ns.get(name, 0.0) / 1000.0 / packets, 3)
                for name in STAGES}

    def stage_calls(self) -> dict[str, int]:
        return {name: int(self.meter.stage_calls.get(name, 0)) for name in STAGES}

    def stats(self) -> dict:
        return {
            "engine": self.name,
            "packets": self.packets,
            "detections": self.detections,
            "scored_observations": self.scored,
            "model_alerts": self.model_alerts,
            "model_alerts_rate_limited": self.model_rate_limited,
            "model_candidates_without_support": self.model_evidence_rejected,
            "ensemble_alerts": self.ensemble_alerts,
            "flow_table_entries": len(self.flows),
            "flows_created": self.flows.created,
            "flows_evicted": self.flows.evicted,
            "flows_expired": self.flows.expired,
            "memory_bytes": self.memory_bytes(),
            "memory_caps_bytes": self.memory_caps_bytes(),
            "stage_timing_us": self.stage_timing_us(),
            "stage_timing_per_packet_us": self.stage_timing_per_packet_us(),
            "stage_calls": self.stage_calls(),
            "stage_timing_note": STAGE_TIMING_NOTE,
            "coverage_counts": {
                "high": self.high_flows,
                "low": self.low_flows,
                "opaque": self.opaque_flows,
                "quic": self.quic_flows,
                "no_sni": self.no_sni_flows,
                "evicted": self.evicted_flows,
                "flows": self.high_flows + self.low_flows + self.opaque_flows,
            },
            "gate": self.gate.stats(),
            "rules": self.rules.stats(),
            "model_lineage": self.lineage(),
            "novelty": self.novelty.stats(),
            "suppressions": self.ctx.suppression_summary(),
        }


def run_source(source, config: dict | None = None, tick_interval_s: float = 5.0):
    engine = Engine(config)
    alerts: list[Detection] = []
    last_tick = 0
    for meta in source:
        alerts.extend(engine.feed(meta))
        if meta.ts_ns - last_tick > tick_interval_s * 1e9:
            last_tick = meta.ts_ns
            alerts.extend(engine.tick(meta.ts_ns))
    if last_tick:
        alerts.extend(engine.tick(last_tick + int(tick_interval_s * 1e9)))
    alerts.extend(engine.sweep())
    return engine, alerts


if __name__ == "__main__":
    import sys

    from engine.sources.pcap_source import PcapSource

    path = sys.argv[1] if len(sys.argv) > 1 else os.path.join("data", "scenarios", "benign.pcap")
    engine, found = run_source(PcapSource(path))
    stats = engine.stats()
    print(path, stats["packets"], "packets", len(found), "detections")
    for det in found:
        print("  ", det.threat_class, det.subtype, round(det.confidence, 3), det.source)
