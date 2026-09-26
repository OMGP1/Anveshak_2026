"""Compare frozen models on identical test rows; repeated evaluations are development evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd

from engine.models.anomaly import AnomalyModel
from engine.models.tier1 import Tier1Model
from training.candidate import check_dataset
from training.evaluate import evaluate_frame


def compare(candidate: Path, serving: Path) -> dict:
    manifest = check_dataset(candidate)
    frame = pd.read_parquet(candidate / "dataset.parquet")
    seen = set(frame.loc[frame.split.isin(["train", "calibration"]), "flow_id"])
    strict = frame[(frame.split == "test") & ~frame.flow_id.isin(seen)].reset_index(drop=True)
    output = {}
    for name, directory in (("serving", serving), ("candidate", candidate)):
        model = Tier1Model.load(str(directory))
        if model is None:
            raise ValueError(f"Missing {name} model")
        forest = AnomalyModel.load(str(directory))
        output[name] = {"model_hash": model.meta["model_hash"],
                        "evaluation": evaluate_frame(strict, model, model.classes, forest)}
    prior = candidate / "serving-before.json"
    intact = None
    if prior.is_file():
        intact = all(hashlib.sha256((serving / name).read_bytes()).hexdigest() == digest
                     for name, digest in json.loads(prior.read_text()).items())
        if not intact:
            raise ValueError("Serving artifacts changed during candidate training")
    return {"dataset_sha256": manifest["dataset_sha256"], "strict_rows": len(strict),
            "serving_artifacts_unchanged": intact, "models": output,
            "scope": "Both models evaluated on identical corrected-engine feature observations. "
                     "All test flows seen in fitting or calibration excluded. Original serving metrics "
                     "used an older dataset and must not be directly compared to these numbers."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--serving", type=Path, default=Path("data/models"))
    parser.add_argument("--json", type=Path, required=True)
    args = parser.parse_args()
    report = compare(args.candidate, args.serving)
    args.json.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    for name, entry in report["models"].items():
        row = entry["evaluation"]
        print(name, "PR-AUC", row["pr_auc_attack_vs_benign"], "macro F1", row["macro_f1_attack_classes"],
              "benign false predictions", row["false_positives"]["attack_predictions"])
