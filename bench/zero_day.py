"""Locked offline evaluation for novelty companions; never mutates serving artifacts."""
from __future__ import annotations

import argparse
import json
import math
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from engine.models.novelty import NOVELTY_FEATURES, NoveltyModel


def evaluate(model_dir: Path, dataset: Path, *, threshold: float = 0.001) -> dict:
    model = NoveltyModel.load(model_dir)
    if model is None:
        raise ValueError("novelty companion is missing")
    frame = pd.read_parquet(dataset)
    required = set(NOVELTY_FEATURES) | {"label", "family", "split"}
    missing = required - set(frame.columns)
    if missing:
        raise ValueError("evaluation dataset is missing: " + ", ".join(sorted(missing)))
    locked = frame[frame["split"] == "test"].reset_index(drop=True)
    if locked.empty:
        raise ValueError("locked test split is empty")
    rows = locked[NOVELTY_FEATURES].to_numpy(dtype=np.float64)
    started = time.perf_counter()
    scored = [model.score(dict(zip(NOVELTY_FEATURES, row))) for row in rows]
    elapsed = time.perf_counter() - started
    tail = np.asarray([row["tail_fraction"] for row in scored])
    suspicion = 1.0 - tail
    truth = (locked["label"].astype(str) != "benign").astype(int).to_numpy()
    predicted = tail <= float(threshold)
    per_family = {}
    for family, indices in locked.groupby("family").groups.items():
        positions = np.asarray(list(indices), dtype=int)
        family_truth = truth[positions]
        positives = int(family_truth.sum())
        per_family[str(family)] = {
            "rows": int(len(positions)),
            "attack_rows": positives,
            "recall": (float(predicted[positions][family_truth == 1].mean()) if positives else None),
            "alert_rows": int(predicted[positions].sum()),
        }
    tp = int(np.sum(predicted & (truth == 1)))
    fp = int(np.sum(predicted & (truth == 0)))
    fn = int(np.sum(~predicted & (truth == 1)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    report = {
        "schema_version": "zero-day-evaluation-v1",
        "dataset": str(dataset),
        "threshold_tail_fraction": threshold,
        "rows": int(len(locked)),
        "per_family": per_family,
        "precision": precision,
        "recall": recall,
        "false_alert_rows": fp,
        "pr_auc": float(average_precision_score(truth, suspicion)) if len(set(truth)) > 1 else None,
        "auroc": float(roc_auc_score(truth, suspicion)) if len(set(truth)) > 1 else None,
        "windows_per_second": len(locked) / max(elapsed, 1e-9),
        "elapsed_seconds": elapsed,
        "notes": [
            "Row results must also be reported after incident grouping and at an agreed sensor-day workload budget.",
            "A held-out family measures generalisation only to the declared behaviour; it cannot prove all future zero-days.",
            "The tail fraction is benign-reference rarity, not attack probability.",
        ],
    }
    return _finite(report)


def _finite(value):
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: _finite(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_finite(item) for item in value]
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--threshold", type=float, default=0.001)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = evaluate(args.model_dir, args.dataset, threshold=args.threshold)
    text = json.dumps(report, indent=2, allow_nan=False) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
