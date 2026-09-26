from __future__ import annotations

from engine.detect import DETECTOR_CLASSES
from engine.detect.base import Context, Detector, flow_features, flow_identifier
from engine.detect.beaconing import BeaconDetector
from engine.features.registry import FEATURES_BY_GROUP
from engine.types import Detection, FlowState, PacketMeta

DETECTOR_GROUPS = {
    "ddos": "ddos",
    "beaconing": "beaconing",
    "dga": "dga-dns",
    "encrypted": "encrypted",
    "scan": "scan",
    "exfil": "exfil",
}

GROUP_FEATURES = {
    group: [row["name"] for row in FEATURES_BY_GROUP[group]] for group in DETECTOR_GROUPS.values()
}


def subject_endpoint(threat_class: str) -> str:
    return "dst" if threat_class == "volumetric-ddos" else "src"


def rule_verdict(detections: list[Detection]) -> tuple[str, float]:
    best_class, best_conf = "benign", 0.0
    for det in detections:
        if det.confidence > best_conf:
            best_class, best_conf = det.threat_class, det.confidence
    return best_class, best_conf


class TracedBeaconDetector(BeaconDetector):
    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self.assessed: list[tuple[tuple, dict, Detection | None]] = []

    def tick(self, now_ns: int, ctx: Context) -> list[Detection]:
        self.assessed = []
        return super().tick(now_ns, ctx)

    def _assess(self, key, iats, stability, now_ns):
        before = getattr(self, "_features", None)
        det = super()._assess(key, iats, stability, now_ns)
        current = getattr(self, "_features", None)
        if current is not None and current is not before:
            self.assessed.append((key, dict(current), det))
        return det


def beacon_class() -> type[Detector]:
    return TracedBeaconDetector if hasattr(BeaconDetector, "_assess") else BeaconDetector


def beacon_identifier(key: tuple, values: dict[str, float], now_ns: int) -> dict:
    proto, src_ip, dst_ip, dst_port = key
    span = float(values.get("beacon_span_s", 0.0))
    return flow_identifier(
        int(proto), src_ip, dst_ip, 0, int(dst_port), (now_ns / 1e9) - span, now_ns / 1e9,
        "FWD_ONLY", False,
    )


class RuleLayer:
    def __init__(self, config: dict | None = None) -> None:
        per_detector = dict(config or {})
        classes = [beacon_class() if cls is BeaconDetector else cls for cls in DETECTOR_CLASSES]
        self.detectors: list[Detector] = [cls(per_detector.get(cls.name)) for cls in classes]
        self.by_name: dict[str, Detector] = {det.name: det for det in self.detectors}
        self.detections = 0
        self.fresh: tuple[str, ...] = ()
        self._seen: dict[str, dict] = {}

    def _collect_fresh(self) -> tuple[str, ...]:
        fresh = []
        for det in self.detectors:
            current = getattr(det, "_features", None)
            if current and self._seen.get(det.name) is not current:
                self._seen[det.name] = current
                fresh.append(det.name)
        return tuple(fresh)

    def observe(self, meta: PacketMeta, flow: FlowState, ctx: Context) -> list[Detection]:
        out: list[Detection] = []
        for det in self.detectors:
            out.extend(det.observe(meta, flow, ctx))
        self.fresh = self._collect_fresh()
        self.detections += len(out)
        return out

    def tick(self, now_ns: int, ctx: Context) -> list[Detection]:
        out: list[Detection] = []
        for detections, _, _ in self.tick_grouped(now_ns, ctx):
            out.extend(detections)
        return out

    def tick_grouped(self, now_ns: int, ctx: Context) -> list[tuple[list[Detection], dict, dict]]:
        groups: list[tuple[list[Detection], dict, dict]] = []
        for det in self.detectors:
            detections = det.tick(now_ns, ctx)
            self.detections += len(detections)
            traced = getattr(det, "assessed", None)
            if traced:
                for key, values, produced in traced:
                    ident = beacon_identifier(key, values, now_ns)
                    rows = [produced] if produced is not None else []
                    groups.append((rows, self._group_values(det.name, values), ident))
                self._seen[det.name] = getattr(det, "_features", None)
                self.fresh = ()
                continue
            self.fresh = self._collect_fresh()
            if detections:
                # Each tick alert can concern a different destination/window. Never merge
                # their evidence into a single model vector or calibration decision.
                for detection in detections:
                    snapshot = detection.context.get("feature_snapshot")
                    values = self._group_values(det.name, snapshot) if snapshot else self.snapshot(None)
                    groups.append(([detection], values, detection.flow))
            elif self.fresh:
                groups.append(([], self.snapshot(None), {}))
        return groups

    def _group_values(self, name: str, emitted: dict[str, float]) -> dict[str, float]:
        allowed = GROUP_FEATURES.get(DETECTOR_GROUPS[name], ())
        return {key: float(emitted[key]) for key in allowed if key in emitted}

    def snapshot(self, flow: FlowState | None) -> dict[str, float]:
        values: dict[str, float] = flow_features(flow) if flow is not None else {}
        for name in self.fresh:
            values.update(self._group_values(name, self.by_name[name].features()))
        return values

    def stats(self) -> dict:
        return {
            "detections": self.detections,
            "detectors": [det.stats() for det in self.detectors],
        }

    @property
    def nbytes(self) -> int:
        return sum(int(det.nbytes) for det in self.detectors)
