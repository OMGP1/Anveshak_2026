from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field

import numpy as np

from engine.features.registry import FEATURES
from engine.models.calibration import calibrate_matrix

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_DIR = os.environ.get("SIH_MODEL_DIR", os.path.join(ROOT, "data", "models"))

MODEL_FEATURES: list[str] = [row["name"] for row in FEATURES
                           if row["group"] != "context" and row.get("model_input", True)]

BOOSTER_FILE = "tier1_lgbm.txt"
CALIBRATION_FILE = "tier1_calibration.json"
META_FILE = "tier1_meta.json"

RAW_SPACE = "raw_margin"
PROBA_SPACE = "probability"


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def softmax(raw: np.ndarray) -> np.ndarray:
    shifted = raw - raw.max()
    exp = np.exp(shifted)
    return exp / exp.sum()


@dataclass(slots=True)
class Tier1Score:
    top_class: str
    confidence: float
    raw_confidence: float
    probs: dict[str, float]
    contributions: list[tuple[str, float, float]] = field(default_factory=list)
    margin: float = 0.0


class Tier1Model:
    def __init__(self, booster, classes: list[str], feature_names: list[str],
                 calibration: dict[str, dict], meta: dict, space: str = RAW_SPACE) -> None:
        self.booster = booster
        self.classes = list(classes)
        self.feature_names = list(feature_names)
        self.calibration = calibration
        self.space = space
        self.meta = dict(meta)
        self.index = {name: i for i, name in enumerate(self.feature_names)}
        self._buf = np.full((1, len(self.feature_names)), np.nan, dtype=np.float64)
        self._curves = [self._curve(name) for name in self.classes]
        self.calls = 0
        self.explained = 0

    def _curve(self, cls: str) -> tuple[np.ndarray, np.ndarray] | None:
        row = self.calibration.get(cls)
        if not row or not row.get("x"):
            return None
        return np.asarray(row["x"], dtype=np.float64), np.asarray(row["y"], dtype=np.float64)

    @classmethod
    def load(cls, directory: str = MODEL_DIR) -> "Tier1Model | None":
        from engine.models.integrity import require_verified_bundle
        require_verified_bundle(directory)
        booster_path = os.path.join(directory, BOOSTER_FILE)
        meta_path = os.path.join(directory, META_FILE)
        if not (os.path.exists(booster_path) and os.path.exists(meta_path)):
            return None
        import lightgbm as lgb

        with open(meta_path, "r", encoding="ascii") as fh:
            meta = json.load(fh)
        calibration = {}
        space = RAW_SPACE
        cal_path = os.path.join(directory, CALIBRATION_FILE)
        if os.path.exists(cal_path):
            with open(cal_path, "r", encoding="ascii") as fh:
                blob = json.load(fh)
            calibration = blob.get("classes", {})
            space = str(blob.get("input_space", RAW_SPACE))
        booster = lgb.Booster(model_file=booster_path)
        meta["model_hash"] = sha256_file(booster_path)
        meta["artefact_bytes"] = sum(
            os.path.getsize(os.path.join(directory, name))
            for name in (BOOSTER_FILE, CALIBRATION_FILE, META_FILE)
            if os.path.exists(os.path.join(directory, name))
        )
        return cls(booster, meta["classes"], meta["feature_names"], calibration, meta, space)

    def vector(self, values: dict[str, float]) -> np.ndarray:
        buf = self._buf
        buf[:] = np.nan
        index = self.index
        for name, value in values.items():
            slot = index.get(name)
            if slot is not None:
                buf[0, slot] = value
        return buf

    def calibrate(self, source: np.ndarray, fallback: np.ndarray) -> np.ndarray:
        return calibrate_matrix(source, fallback, self.calibration, self.classes)

    def score(self, values: dict[str, float], explain: bool = False) -> Tier1Score:
        self.calls += 1
        x = self.vector(values)
        contributions: list[tuple[str, float, float]] = []
        if explain:
            self.explained += 1
            contrib = np.asarray(self.booster.predict(x, pred_contrib=True), dtype=np.float64)
            table = contrib.reshape(len(self.classes), len(self.feature_names) + 1)
            raw = table.sum(axis=1)
        else:
            table = None
            raw = np.asarray(self.booster.predict(x, raw_score=True), dtype=np.float64)[0]
        probs = softmax(raw)
        calibrated = self.calibrate(raw if self.space == RAW_SPACE else probs, probs)
        top = int(np.argmax(calibrated))
        if table is not None:
            for slot in np.argsort(-np.abs(table[top, :-1]))[:8]:
                weight = float(table[top, slot])
                if weight == 0.0:
                    continue
                contributions.append((self.feature_names[slot], float(x[0, slot]), weight))
        ranked = np.sort(calibrated)
        return Tier1Score(
            top_class=self.classes[top],
            confidence=float(calibrated[top]),
            raw_confidence=float(probs[top]),
            probs={name: float(calibrated[i]) for i, name in enumerate(self.classes)},
            contributions=contributions,
            margin=float(ranked[-1] - ranked[-2]) if len(ranked) > 1 else float(ranked[-1]),
        )

    def lineage(self) -> dict:
        return {
            "model_id": str(self.meta.get("model_id", "tier1-lgbm")),
            "model_hash": str(self.meta.get("model_hash", "none")),
            "dataset_version": str(self.meta.get("dataset_version", "none")),
        }

    @property
    def nbytes(self) -> int:
        return int(self.meta.get("artefact_bytes", 0))
