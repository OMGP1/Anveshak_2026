from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass

DEFAULT_GATE = {
    "uncertain_low": 0.35,
    "uncertain_high": 0.85,
    "qa_sample_rate": 0.005,
    "encrypted_prob_min": 0.10,
    "fingerprint_consistency_max": 0.60,
    "seed": 26145,
}

REASONS = ("uncertain-band", "encrypted-candidate", "qa-sample")


@dataclass(slots=True)
class GateDecision:
    promote: bool
    reason: str
    confidence: float


class PromotionGate:
    def __init__(self, config: dict | None = None) -> None:
        cfg = dict(DEFAULT_GATE)
        cfg.update(config or {})
        self.config = cfg
        self.low = float(cfg["uncertain_low"])
        self.high = float(cfg["uncertain_high"])
        self.qa_rate = float(cfg["qa_sample_rate"])
        self.encrypted_min = float(cfg["encrypted_prob_min"])
        self.fp_max = float(cfg["fingerprint_consistency_max"])
        self.rng = random.Random(int(cfg["seed"]))
        self.considered = 0
        self.promoted = 0
        self.by_reason: Counter = Counter()

    def decide(self, score, values: dict[str, float]) -> GateDecision:
        self.considered += 1
        confidence = float(getattr(score, "confidence", 0.0)) if score is not None else 0.0
        reason = ""
        if score is not None and self.low <= confidence < self.high:
            reason = "uncertain-band"
        elif self._encrypted_candidate(score, values):
            reason = "encrypted-candidate"
        elif self.qa_rate > 0.0 and self.rng.random() < self.qa_rate:
            reason = "qa-sample"
        if not reason:
            return GateDecision(False, "", confidence)
        self.promoted += 1
        self.by_reason[reason] += 1
        return GateDecision(True, reason, confidence)

    def _encrypted_candidate(self, score, values: dict[str, float]) -> bool:
        if "fingerprint_consistency_score" not in values:
            return False
        if float(values["fingerprint_consistency_score"]) <= self.fp_max:
            return True
        if score is None:
            return False
        return float(score.probs.get("encrypted-malware", 0.0)) >= self.encrypted_min

    def lineage(self) -> dict:
        return {
            "gate_uncertain_low": self.low,
            "gate_uncertain_high": self.high,
            "gate_qa_sample_rate": self.qa_rate,
            "gate_encrypted_prob_min": self.encrypted_min,
            "gate_fingerprint_consistency_max": self.fp_max,
            "gate_seed": int(self.config["seed"]),
        }

    def stats(self) -> dict:
        return {
            "considered": self.considered,
            "promoted": self.promoted,
            "by_reason": {name: int(self.by_reason.get(name, 0)) for name in REASONS},
            "config": self.lineage(),
        }
