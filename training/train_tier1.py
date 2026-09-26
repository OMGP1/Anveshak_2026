from __future__ import annotations

import json
import os
import sys
import warnings

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.models.anomaly import AnomalyModel
from engine.models.calibration import calibrate_matrix
from engine.models.tier1 import (BOOSTER_FILE, CALIBRATION_FILE, META_FILE, MODEL_DIR,
                                 PROBA_SPACE, RAW_SPACE, sha256_file, softmax)
from engine.types import THREAT_CLASSES

MODEL_ID = "tier1-lgbm-v1.0.0"
SEED = 26145

PARAMS = {
    "objective": "multiclass",
    "n_estimators": 140,
    "learning_rate": 0.09,
    "num_leaves": 24,
    "max_depth": -1,
    "min_child_samples": 20,
    "subsample": 0.9,
    "subsample_freq": 1,
    "colsample_bytree": 0.8,
    "reg_lambda": 1.0,
    "class_weight": "balanced",
    "random_state": SEED,
    "n_jobs": 1,
    "verbose": -1,
}

CALIBRATION_NOTE = (
    "isotonic calibration is fitted by sklearn CalibratedClassifierCV on the calibration slice, "
    "which is a temporal slice sitting after the training slice and before the test slice. the "
    "fitted per-class isotonic curves are exported as breakpoints so the engine applies them with "
    "a plain interpolation and needs no sklearn at inference. the export is verified against "
    "sklearn's own predict_proba on the calibration slice before it is written"
)


def frozen(model):
    try:
        from sklearn.frozen import FrozenEstimator
    except ImportError:
        return model
    return FrozenEstimator(model)


def load_frame(directory: str = MODEL_DIR) -> pd.DataFrame:
    path = os.path.join(directory, "dataset.parquet")
    if not os.path.exists(path):
        raise SystemExit("run training/build_dataset.py first, %s is missing" % path)
    return pd.read_parquet(path)


def curves_from(calibrated, classes: list[str]) -> dict[str, dict]:
    inner = calibrated.calibrated_classifiers_[0]
    fitted = getattr(inner, "calibrators", None) or getattr(inner, "calibrators_", None)
    out: dict[str, dict] = {}
    if not fitted:
        return out
    for name, model in zip(classes, fitted):
        if hasattr(model, "a_") and hasattr(model, "b_"):
            out[name] = {"a": float(model.a_), "b": float(model.b_)}
            continue
        x = getattr(model, "X_thresholds_", None)
        y = getattr(model, "y_thresholds_", None)
        if x is None or y is None:
            continue
        out[name] = {"x": [float(v) for v in x], "y": [float(v) for v in y]}
    return out


def reproduce(raw: np.ndarray, curves: dict[str, dict], order: list[str]) -> np.ndarray:
    return calibrate_matrix(raw, raw, curves, order)


def fit_calibrator(model, x, y, weights, method="isotonic", input_space=RAW_SPACE):
    from sklearn.base import BaseEstimator, ClassifierMixin
    from sklearn.calibration import CalibratedClassifierCV

    if method not in ("isotonic", "sigmoid") or input_space not in (RAW_SPACE, PROBA_SPACE):
        raise ValueError("Unsupported calibration method or input space")

    class ProbabilityAdapter(ClassifierMixin, BaseEstimator):
        """Expose only probabilities when calibration must include competing classes."""
        def __init__(self, estimator):
            self.estimator = estimator

        @property
        def classes_(self):
            return self.estimator.classes_

        def __sklearn_is_fitted__(self):
            return True

        def fit(self, x, y):
            raise RuntimeError("ProbabilityAdapter must wrap a frozen fitted classifier")

        def predict_proba(self, x):
            return self.estimator.predict_proba(x)

        def predict(self, x):
            return self.classes_[self.predict_proba(x).argmax(axis=1)]

    estimator = ProbabilityAdapter(model) if input_space == PROBA_SPACE else model
    calibrated = CalibratedClassifierCV(estimator=frozen(estimator), method=method, cv=None)
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Since FrozenEstimator does not appear to accept sample_weight")
        calibrated.fit(x, y, sample_weight=weights)
    return calibrated


def pick_space(model, calibrated, curves: dict[str, dict], order: list[str],
               x: pd.DataFrame) -> tuple[str, float]:
    reference = np.asarray(calibrated.predict_proba(x), dtype=np.float64)
    margins = np.asarray(model.booster_.predict(x, raw_score=True), dtype=np.float64)
    probs = np.vstack([softmax(row) for row in margins])
    best, error = RAW_SPACE, float("inf")
    for space, source in ((RAW_SPACE, margins), (PROBA_SPACE, probs)):
        gap = float(np.max(np.abs(reproduce(source, curves, order) - reference)))
        if gap < error:
            best, error = space, gap
    return best, error


def train(directory: str = MODEL_DIR, params: dict | None = None,
          anomaly_trees: int = 120, early_stopping_rounds: int = 0,
          search_candidates: list[dict] | None = None,
          calibration_prevalence: float | None = None,
          purge_calibration_flows: bool = False,
          calibration_candidates: list[dict] | None = None) -> int:
    import lightgbm as lgb
    parameters = dict(PARAMS if params is None else params)
    if calibration_candidates and len(calibration_candidates) > 1 and not early_stopping_rounds:
        raise ValueError("Multiple calibration methods require training-only selection")
    requested_parameters = dict(parameters)
    frame = load_frame(directory)
    manifest_path = os.path.join(directory, "dataset_manifest.json")
    with open(manifest_path, "r", encoding="ascii") as fh:
        manifest = json.load(fh)
    features = manifest["features"]
    classes = [name for name in THREAT_CLASSES if (frame["label"] == name).any()]

    train = frame[frame["split"] == "train"]
    calib = frame[frame["split"] == "calibration"]
    if purge_calibration_flows:
        calib = calib[~calib.flow_id.isin(set(train.flow_id))]
    if set(calib.label) != set(classes):
        raise ValueError("Independent calibration slice must contain every class")
    x_train = train[features].astype(np.float64)
    y_train = train["label"].to_numpy()
    x_calib = calib[features].astype(np.float64)
    y_calib = calib["label"].to_numpy()

    counts = {name: int((y_train == name).sum()) for name in classes}
    print("train rows", len(train), "calibration rows", len(calib))
    print("train class counts", counts)

    selection = None
    if early_stopping_rounds:
        from training.selection import select_parameters
        parameters, selection = select_parameters(train, features, parameters, search_candidates,
                                                  early_stopping_rounds,
                                                  calibration_prevalence or 0.001,
                                                  calibration_candidates)
        with open(os.path.join(directory, "selection.json"), "w", encoding="ascii") as fh:
            json.dump(selection, fh, indent=2, allow_nan=False)
    model = lgb.LGBMClassifier(**parameters)
    model.fit(x_train, y_train)
    order = [str(name) for name in model.classes_]

    calibration_weights = None
    if calibration_prevalence is not None:
        from training.selection import prevalence_weights
        calibration_weights = prevalence_weights(y_calib, calibration_prevalence)
    calibration_config = (selection or {}).get("selected_calibration",
                                               (calibration_candidates or [{}])[0])
    method = calibration_config.get("method", "isotonic")
    calibrated = fit_calibrator(model, x_calib, y_calib, calibration_weights, method,
                                calibration_config.get("input_space", RAW_SPACE))
    curves = curves_from(calibrated, order)
    if len(curves) != len(order):
        raise SystemExit("could not export a calibration curve for every class")

    space, error = pick_space(model, calibrated, curves, order, x_calib)
    if error > 1e-6:
        raise SystemExit("exported calibration does not reproduce sklearn, max gap %.3e" % error)
    print("calibration input space", space, "max reproduction gap %.2e" % error)

    booster_path = os.path.join(directory, BOOSTER_FILE)
    model.booster_.save_model(booster_path)
    with open(os.path.join(directory, CALIBRATION_FILE), "w", encoding="ascii") as fh:
        json.dump({"method": method, "note": CALIBRATION_NOTE if method == "isotonic" else
                   "Sigmoid calibration fitted on separate calibration flows; coefficients exported "
                   "and verified against sklearn. Method selected using training observations only.", "input_space": space,
                   "reproduction_max_gap": error, "classes": curves},
                  fh, indent=2, sort_keys=True)

    class_weight = parameters.get("class_weight")
    weights = {name: round(float(len(y_train)) / (len(classes) * max(1, counts[name])), 4)
               if class_weight == "balanced" else float((class_weight or {}).get(name, 1.0))
               for name in classes}
    meta = {
        "model_id": MODEL_ID,
        "model_hash": sha256_file(booster_path),
        "dataset_version": manifest["dataset_version"],
        "dataset_sha256": manifest["dataset_sha256"],
        "classes": order,
        "feature_names": list(features),
        "feature_count": len(features),
        "params": parameters,
        "requested_params": requested_parameters,
        "selection": selection,
        "calibration_target_prevalence": calibration_prevalence,
        "calibration_natural_prevalence": float((y_calib != "benign").mean()),
        "calibration_flows_purged": purge_calibration_flows,
        "calibration_method": method,
        "calibration_input_space": space,
        "anomaly_trees": anomaly_trees,
        "trees": int(model.booster_.num_trees()),
        "train_rows": int(len(train)),
        "calibration_rows": int(len(calib)),
        "train_class_counts": counts,
        "effective_class_weights": weights,
        "split_bounds": manifest["split_bounds"],
        "explanation": (
            "the engine calls booster.predict(pred_contrib=True) once per scored observation. the "
            "row of contributions sums to the raw margin for that class, so the same call produces "
            "the prediction and the exact treeshap attribution behind it and no separate shap "
            "worker exists anywhere in this repository"
        ),
    }
    with open(os.path.join(directory, META_FILE), "w", encoding="ascii") as fh:
        json.dump(meta, fh, indent=2, sort_keys=True)

    benign = train[train["label"] == "benign"]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)
        forest = AnomalyModel.fit(benign[features].to_numpy(dtype=np.float64), list(features), SEED,
                                  trees=anomaly_trees)
    forest.save(directory)

    train_acc = float((model.predict(x_train) == y_train).mean())
    calib_acc = float((model.predict(x_calib) == y_calib).mean())
    print("trees", meta["trees"], "classes", order)
    print("train accuracy %.4f  calibration accuracy %.4f" % (train_acc, calib_acc))
    print("anomaly forest trained on", len(benign), "benign training rows only")
    print("saved to", directory)
    return 0


def main() -> int:
    return train()


if __name__ == "__main__":
    raise SystemExit(main())
