from __future__ import annotations

import json
import os
import pickle

import numpy as np

from engine.models.tier1 import MODEL_DIR, MODEL_FEATURES
from engine.models.isolation import IsolationPaths

FOREST_FILE = "anomaly_iforest.pkl"
ANOMALY_META_FILE = "anomaly_meta.json"


class AnomalyModel:
    def __init__(self, forest, feature_names: list[str], medians: np.ndarray,
                 benign_scores: np.ndarray, meta: dict) -> None:
        self.forest = forest
        self.feature_names = list(feature_names)
        self.medians = np.asarray(medians, dtype=np.float64)
        self.benign_scores = np.asarray(benign_scores, dtype=np.float64)
        self.meta = dict(meta)
        self.index = {name: i for i, name in enumerate(self.feature_names)}
        self._buf = np.zeros((1, len(self.feature_names)), dtype=np.float64)
        self.calls = 0
        self._paths = IsolationPaths.from_forest(forest)

    @classmethod
    def fit(cls, rows: np.ndarray, feature_names: list[str], seed: int = 26145,
            trees: int = 200, contamination: float = 0.01) -> "AnomalyModel":
        from sklearn.ensemble import IsolationForest

        medians = np.nanmedian(rows, axis=0)
        medians = np.where(np.isfinite(medians), medians, 0.0)
        filled = cls._fill(rows, medians)
        forest = IsolationForest(
            n_estimators=trees, contamination=contamination, random_state=seed, n_jobs=1
        )
        forest.fit(filled)
        scores = -forest.score_samples(filled)
        keep = np.linspace(0, len(scores) - 1, min(4096, len(scores))).astype(int)
        meta = {
            "trees": trees,
            "contamination": contamination,
            "seed": seed,
            "train_rows": int(rows.shape[0]),
            "trained_on": "benign-labelled training rows only",
        }
        return cls(forest, feature_names, medians, np.sort(scores)[keep], meta)

    @staticmethod
    def _fill(rows: np.ndarray, medians: np.ndarray) -> np.ndarray:
        out = np.array(rows, dtype=np.float64, copy=True)
        bad = ~np.isfinite(out)
        if bad.any():
            out[bad] = np.take(medians, np.where(bad)[1])
        return out

    @classmethod
    def load(cls, directory: str = MODEL_DIR) -> "AnomalyModel | None":
        from engine.models.integrity import require_verified_bundle
        require_verified_bundle(directory)
        forest_path = os.path.join(directory, FOREST_FILE)
        meta_path = os.path.join(directory, ANOMALY_META_FILE)
        if not (os.path.exists(forest_path) and os.path.exists(meta_path)):
            return None
        with open(meta_path, "r", encoding="ascii") as fh:
            blob = json.load(fh)
        with open(forest_path, "rb") as fh:
            forest = pickle.load(fh)
        meta = dict(blob.get("meta", {}))
        meta["artefact_bytes"] = os.path.getsize(forest_path) + os.path.getsize(meta_path)
        return cls(forest, blob["feature_names"], np.asarray(blob["medians"]),
                   np.asarray(blob["benign_scores"]), meta)

    def save(self, directory: str = MODEL_DIR) -> None:
        os.makedirs(directory, exist_ok=True)
        with open(os.path.join(directory, FOREST_FILE), "wb") as fh:
            pickle.dump(self.forest, fh, protocol=4)
        blob = {
            "feature_names": self.feature_names,
            "medians": [float(v) for v in self.medians],
            "benign_scores": [float(v) for v in self.benign_scores],
            "meta": self.meta,
        }
        with open(os.path.join(directory, ANOMALY_META_FILE), "w", encoding="ascii") as fh:
            json.dump(blob, fh, indent=2, sort_keys=True)

    def vector(self, values: dict[str, float]) -> np.ndarray:
        buf = self._buf
        buf[0] = self.medians
        index = self.index
        for name, value in values.items():
            slot = index.get(name)
            if slot is not None and np.isfinite(value):
                buf[0, slot] = value
        return buf

    def score_many(self, rows: np.ndarray) -> np.ndarray:
        filled = self._fill(np.asarray(rows, dtype=np.float64), self.medians)
        raw = -np.asarray(self.forest.score_samples(filled), dtype=np.float64)
        if self.benign_scores.size == 0:
            return np.zeros(len(raw))
        rank = np.searchsorted(self.benign_scores, raw) / float(self.benign_scores.size)
        return np.clip(rank, 0.0, 1.0)

    def score(self, values: dict[str, float]) -> float:
        self.calls += 1
        vector = self.vector(values)
        raw = self._paths.score(vector) if self._paths is not None else None
        if raw is None:
            raw = float(-self.forest.score_samples(vector)[0])
        if self.benign_scores.size == 0:
            return 0.0
        rank = float(np.searchsorted(self.benign_scores, raw)) / float(self.benign_scores.size)
        return min(1.0, max(0.0, rank))

    @property
    def nbytes(self) -> int:
        return int(self.meta.get("artefact_bytes", 0)) + (self._paths.nbytes if self._paths is not None else 0)


DEFAULT_FEATURES = list(MODEL_FEATURES)
