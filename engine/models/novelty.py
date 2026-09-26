"""Separately packaged benign-baseline companion for novelty-v1 windows."""
from __future__ import annotations

import hashlib
import json
import math
import os
import pickle
from pathlib import Path

import numpy as np

from engine.models.isolation import IsolationPaths

NOVELTY_FEATURES = [
    "window_duration_s",
    "packets_fwd",
    "packets_rev",
    "bytes_fwd",
    "bytes_rev",
    "packet_rate",
    "byte_rate",
    "mean_packet_size",
    "reverse_packet_share",
    "completeness_flag",
    "orientation_confidence",
    "sequence_samples",
    "sequence_iat_mean_us",
    "sequence_iat_std_us",
    "sequence_timing_available",
]

FOREST_FILE = "novelty_iforest.pkl"
META_FILE = "novelty_meta.json"
MANIFEST_FILE = "novelty-manifest.json"
SIGNATURE_FILE = "novelty-manifest.sig"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class NoveltyModel:
    """Isolation Forest with disjoint benign calibration and explicit tail rarity."""

    def __init__(self, forest, feature_names: list[str], medians: np.ndarray,
                 scales: np.ndarray, calibration_scores: np.ndarray, meta: dict) -> None:
        self.forest = forest
        self.feature_names = list(feature_names)
        self.medians = np.asarray(medians, dtype=np.float64)
        self.scales = np.asarray(scales, dtype=np.float64)
        self.calibration_scores = np.sort(np.asarray(calibration_scores, dtype=np.float64))
        self.meta = dict(meta)
        self.index = {name: index for index, name in enumerate(self.feature_names)}
        self._buf = np.zeros((1, len(self.feature_names)), dtype=np.float64)
        self._paths = IsolationPaths.from_forest(forest)

    @staticmethod
    def _fill(rows: np.ndarray, medians: np.ndarray) -> np.ndarray:
        out = np.array(rows, dtype=np.float64, copy=True)
        bad = ~np.isfinite(out)
        if bad.any():
            out[bad] = np.take(medians, np.where(bad)[1])
        return out

    @classmethod
    def fit(cls, training_rows: np.ndarray, calibration_rows: np.ndarray,
            feature_names: list[str] | None = None, *, seed: int = 26145,
            trees: int = 200) -> "NoveltyModel":
        from sklearn.ensemble import IsolationForest

        names = list(feature_names or NOVELTY_FEATURES)
        train = np.asarray(training_rows, dtype=np.float64)
        calibration = np.asarray(calibration_rows, dtype=np.float64)
        if train.ndim != 2 or calibration.ndim != 2 or train.shape[1] != len(names) or calibration.shape[1] != len(names):
            raise ValueError("novelty training and calibration matrices must match the feature contract")
        if len(train) < 8 or len(calibration) < 8:
            raise ValueError("novelty training and calibration each require at least eight benign windows")
        medians = np.nanmedian(train, axis=0)
        medians = np.where(np.isfinite(medians), medians, 0.0)
        filled = cls._fill(train, medians)
        absolute = np.abs(filled - medians)
        scales = np.nanmedian(absolute, axis=0) * 1.4826
        scales = np.where(np.isfinite(scales) & (scales > 1e-9), scales, 1.0)
        forest = IsolationForest(n_estimators=int(trees), contamination="auto", random_state=int(seed), n_jobs=1)
        forest.fit(filled)
        calibrated = cls._fill(calibration, medians)
        calibration_scores = -np.asarray(forest.score_samples(calibrated), dtype=np.float64)
        meta = {
            "schema_version": "novelty-companion-v1",
            "feature_contract": "novelty-v1",
            "seed": int(seed),
            "trees": int(trees),
            "train_rows": int(len(train)),
            "calibration_rows": int(len(calibration)),
            "trained_on": "approved benign independent windows only",
        }
        return cls(forest, names, medians, scales, calibration_scores, meta)

    def vector(self, values: dict[str, float]) -> np.ndarray:
        self._buf[0] = self.medians
        for name, value in values.items():
            slot = self.index.get(name)
            if slot is not None and isinstance(value, (int, float)) and math.isfinite(float(value)):
                self._buf[0, slot] = float(value)
        return self._buf

    def score(self, values: dict[str, float]) -> dict:
        vector = self.vector(values)
        raw = self._paths.score(vector) if self._paths is not None else None
        if raw is None:
            raw = float(-self.forest.score_samples(vector)[0])
        count = int(self.calibration_scores.size)
        # Conservative conformal-style upper-tail fraction with finite-sample correction.
        greater_or_equal = count - int(np.searchsorted(self.calibration_scores, raw, side="left"))
        tail = (1.0 + greater_or_equal) / (count + 1.0) if count else 1.0
        deviations = np.abs((vector[0] - self.medians) / self.scales)
        return {
            "raw_score": float(raw),
            "tail_fraction": float(min(1.0, max(0.0, tail))),
            "calibration_count": count,
            "deviations": {name: float(deviations[index]) for index, name in enumerate(self.feature_names)},
        }

    def save(self, directory: str | Path) -> None:
        target = Path(directory)
        target.mkdir(parents=True, exist_ok=True)
        with (target / FOREST_FILE).open("wb") as handle:
            pickle.dump(self.forest, handle, protocol=4)
        blob = {
            "feature_names": self.feature_names,
            "medians": [float(value) for value in self.medians],
            "scales": [float(value) for value in self.scales],
            "calibration_scores": [float(value) for value in self.calibration_scores],
            "meta": self.meta,
        }
        (target / META_FILE).write_text(json.dumps(blob, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, directory: str | Path, *, require_signature: bool = False,
             public_key: str | Path | None = None) -> "NoveltyModel | None":
        target = Path(directory)
        if not (target / FOREST_FILE).exists() or not (target / META_FILE).exists():
            return None
        if require_signature:
            verify_novelty_bundle(target, public_key)
        blob = json.loads((target / META_FILE).read_text(encoding="utf-8"))
        if blob.get("feature_names") != NOVELTY_FEATURES:
            raise ValueError("Novelty feature order differs from novelty-v1")
        with (target / FOREST_FILE).open("rb") as handle:
            forest = pickle.load(handle)
        meta = dict(blob.get("meta") or {})
        meta["model_hash"] = "sha256:" + _sha256(target / FOREST_FILE)
        meta["baseline_hash"] = "sha256:" + _sha256(target / META_FILE)
        meta["artefact_bytes"] = (target / FOREST_FILE).stat().st_size + (target / META_FILE).stat().st_size
        return cls(forest, blob["feature_names"], np.asarray(blob["medians"]),
                   np.asarray(blob["scales"]), np.asarray(blob["calibration_scores"]), meta)

    @property
    def nbytes(self) -> int:
        paths = self._paths.nbytes if self._paths is not None else 0
        return int(self.meta.get("artefact_bytes", 0)) + int(paths)


def verify_novelty_bundle(directory: str | Path, public_key: str | Path | None) -> dict:
    """Verify the companion without changing the existing five-file serving manifest."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    target = Path(directory)
    if public_key is None:
        raise ValueError("SIH_NOVELTY_PUBLIC_KEY is required for a signed novelty companion")
    raw = (target / MANIFEST_FILE).read_bytes()
    signature = bytes.fromhex((target / SIGNATURE_FILE).read_text(encoding="ascii").strip())
    key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(Path(public_key).read_text(encoding="ascii").strip()))
    key.verify(signature, raw)
    manifest = json.loads(raw)
    expected = {FOREST_FILE, META_FILE}
    if manifest.get("version") != 1 or set(manifest.get("sha256") or {}) != expected:
        raise ValueError("Invalid novelty companion manifest")
    for name in expected:
        if _sha256(target / name) != manifest["sha256"][name]:
            raise ValueError(f"Novelty artifact integrity failed: {name}")
    return manifest
