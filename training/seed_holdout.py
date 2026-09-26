"""Evaluate frozen models on newly generated capture seeds; never fit on this corpus."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from engine.models.tier1 import Tier1Model, sha256_file
from engine.models.anomaly import AnomalyModel
from engine.models.integrity import ARTIFACTS
from training.build_dataset import replay
from training.evaluate import evaluate_frame
from training.generate_scenarios import build
from training.scenarios import SCENARIOS


def validate_seeds(seed_offset: int, model_directories) -> None:
    if seed_offset <= 0:
        raise ValueError("Held-out seeds must differ from the training catalogue")
    used = {spec["seed"] for spec in SCENARIOS}
    for directory in model_directories:
        manifest = json.loads((directory / "dataset_manifest.json").read_text())
        used.update(info["seed"] for info in manifest.get("augmentation_sessions", {}).values())
    planned = {spec["seed"] + seed_offset for spec in SCENARIOS}
    if used & planned:
        raise ValueError("Holdout seeds overlap fitting or calibration captures")


def run(output: Path, models: dict[str, Path], seed_offset: int = 910000) -> dict:
    validate_seeds(seed_offset, models.values())
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    captures = output / "captures"
    captures.mkdir()
    # Freeze identities before generating or looking at the holdout.
    loaded = {name: Tier1Model.load(str(directory)) for name, directory in models.items()}
    if any(model is None for model in loaded.values()):
        raise ValueError("Every named model must be fitted before holdout generation")
    manifest = {"role": "evaluation_only", "seed_offset": seed_offset,
                "model_hashes": {name: model.meta["model_hash"] for name, model in loaded.items()},
                "bundle_hashes": {name: {artifact: sha256_file(str(directory / artifact))
                                         for artifact in ARTIFACTS} for name, directory in models.items()},
                "limitation": "New random seeds of the existing synthetic templates, not new malware "
                              "families or independent real traffic. Repeated evaluations are development results."}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    rows, sources = [], []
    for original in SCENARIOS:
        spec = {**original, "seed": original["seed"] + seed_offset}
        built = build(spec, str(captures))
        labels = json.loads((captures / (spec["id"] + ".labels.json")).read_text())
        spec["file"] = str(captures / (spec["id"] + ".pcap"))
        part, summary = replay(spec, labels)
        # The whole new capture is evaluation-only. Temporal embargo intervals are
        # omitted by the shared extractor; no model was fitted on any of these rows.
        for row in part:
            row["flow_id"] = f"seed-{spec['seed']}/{row['flow_id']}"
            row["split"] = "test"
        rows.extend(part)
        sources.append({"scenario": spec["id"], "seed": spec["seed"], **built, "extraction": summary})
        print(f"holdout {spec['id']}: {len(part)} observations", flush=True)
    frame = pd.DataFrame(rows).sort_values(["ts_ns", "scenario"], kind="stable").reset_index(drop=True)
    frame.to_parquet(output / "dataset.parquet", index=False)
    manifest.update(rows=len(frame), sources=sources, dataset_sha256=sha256_file(str(output / "dataset.parquet")))
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    evaluations = {}
    for name, model in loaded.items():
        report = evaluate_frame(frame, model, model.classes, AnomalyModel.load(str(models[name])))
        evaluations[name] = report
        print(name, "F1", report["macro_f1_attack_classes"], "false positives",
              report["false_positives"]["attack_predictions"], flush=True)
    result = {"manifest": manifest, "models": evaluations}
    (output / "result.json").write_text(json.dumps(result, indent=2, allow_nan=False) + "\n")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--seed-offset", type=int, default=910000)
    args = parser.parse_args()
    run(args.output, {"baseline": args.baseline, "candidate": args.candidate}, args.seed_offset)
