"""Offline candidate evaluation. Never changes the serving model or its data."""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import pandas as pd

from engine.models.anomaly import AnomalyModel
from engine.models.tier1 import MODEL_FEATURES, Tier1Model, sha256_file
from engine.types import THREAT_CLASSES
from training.train_tier1 import train

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "config/training-quality.json"


def check_dataset(directory: Path) -> dict:
    manifest = json.loads((directory / "dataset_manifest.json").read_text())
    if sha256_file(str(directory / "dataset.parquet")) != manifest["dataset_sha256"]:
        raise ValueError("Training dataset SHA-256 mismatch")
    if manifest["features"] != MODEL_FEATURES:
        raise ValueError("Training feature order differs from the engine")
    frame = pd.read_parquet(directory / "dataset.parquet")
    if len(frame) != manifest["rows"] or set(frame["split"]) != {"train", "calibration", "test"}:
        raise ValueError("Training dataset rows or splits differ from the manifest")
    for name in ("train", "calibration", "test"):
        part = frame[frame["split"] == name]
        if set(part["label"]) != set(THREAT_CLASSES):
            raise ValueError(f"{name} must contain every class")
        if len(part) != manifest["counts"][name]["rows"]:
            raise ValueError(f"{name} row count mismatch")
    # An administrator cannot bypass chronological split invariants by renaming rows.
    augmented = manifest.get("augmentation_sessions", {})
    if not set(augmented).issubset(set(frame.scenario)):
        raise ValueError("Augmentation manifest names absent sessions")
    seeds = [info["seed"] for info in augmented.values()]
    if len(seeds) != len(set(seeds)):
        raise ValueError("Augmentation seeds overlap across sessions")
    for scenario, group in frame.groupby("scenario"):
        if scenario in augmented:
            info = augmented[scenario]
            if (info["split"] not in ("train", "calibration") or set(group.split) != {info["split"]}
                    or len(group) != info["rows"] or not group.flow_id.str.startswith(scenario + "/").all()):
                raise ValueError("Augmented capture crosses assigned roles or flow namespaces")
            continue
        parts = [group[group["split"] == name] for name in ("train", "calibration", "test")]
        if any(p.empty for p in parts) or not (
            parts[0]["ts_ns"].max() < parts[1]["ts_ns"].min()
            and parts[1]["ts_ns"].max() < parts[2]["ts_ns"].min()
        ):
            raise ValueError("Temporal split overlap or missing scenario slice")
    return manifest


def promotion_gates(report: dict, policy: dict, independent_real_holdout: bool = False) -> dict:
    failures = []
    missing = set(THREAT_CLASSES) - set(report["per_class"])
    if missing:
        failures.append("Evaluation omits required classes: " + ", ".join(sorted(missing)))
    for name, row in report["per_class"].items():
        if name == "benign":
            continue
        for key, threshold in (("precision", policy["minimum_precision_per_attack_class"]),
                               ("recall", policy["minimum_recall_per_attack_class"])):
            value = row[key]
            if not math.isfinite(value) or value < threshold:
                failures.append(f"{name}: {key} {value} below {threshold}")
        if row["rows"] < policy["minimum_test_rows_per_attack_class"]:
            failures.append(f"{name}: insufficient independent test rows")
    ece = report["reliability_weighted"]["expected_calibration_error"]
    if not math.isfinite(ece) or ece > policy["maximum_calibration_error"]:
        failures.append("Calibration error exceeds the configured limit")
    if policy["require_independent_real_holdout"] and not independent_real_holdout:
        failures.append("Independent labelled real-traffic holdout is absent")
    return {"passed": not failures, "failures": failures, "automatic_promotion": False}


def run(directory: Path) -> dict:
    # A frozen copy of the profile lives with every job.
    profile = json.loads((directory / "profile.json").read_text())
    manifest = check_dataset(directory)
    train(str(directory), profile["parameters"], profile["anomaly_trees"], profile["early_stopping_rounds"],
          profile.get("search_candidates"), profile.get("calibration_prevalence"),
          profile.get("purge_calibration_flows", False), profile.get("calibration_candidates"))
    from training.evaluate import evaluate_frame

    model = Tier1Model.load(str(directory))
    if model is None:
        raise ValueError("Candidate model did not load")
    forest = AnomalyModel.load(str(directory))
    frame = pd.read_parquet(directory / "dataset.parquet")
    train_flows = set(frame.loc[frame["split"].isin(["train", "calibration"]), "flow_id"])
    strict = frame[(frame["split"] == "test") & ~frame["flow_id"].isin(train_flows)].reset_index(drop=True)
    report = evaluate_frame(strict, model, model.classes, forest)
    gates = promotion_gates(report, profile["gates"])
    result = {"state": "candidate_ready" if gates["passed"] else "candidate_rejected",
              "dataset_sha256": manifest["dataset_sha256"], "model_hash": model.meta["model_hash"],
              "profile": profile["profile"], "gates": gates, "evaluation": report,
              "selected_parameters": model.meta["params"], "anomaly_trees": profile["anomaly_trees"],
              "strict_split_note": "Test excludes flows seen in training OR probability calibration",
              "serving_model_changed": False,
              "evaluation_note": "Strict temporal synthetic holdout. Row metrics are not live alert precision."}
    # Metrics may contain undefined PR-AUC for an absent class. JSON never emits NaN.
    def finite(value):
        if isinstance(value, float) and not math.isfinite(value):
            return None
        if isinstance(value, dict):
            return {key: finite(item) for key, item in value.items()}
        if isinstance(value, list):
            return [finite(item) for item in value]
        return value
    result = finite(result)
    (directory / "result.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    print(json.dumps({"state": run(arguments.directory)["state"]}))
