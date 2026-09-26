"""Add separately seeded synthetic sessions to fitting/calibration, preserving original test rows."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from engine.models.tier1 import sha256_file
from training.build_dataset import replay
from training.generate_scenarios import build
from training.scenarios import SCENARIOS


def augment(directory: Path, plan: dict) -> dict:
    path = directory / "dataset.parquet"
    manifest_path = directory / "dataset_manifest.json"
    manifest = json.loads(manifest_path.read_text())
    original = pd.read_parquet(path)
    if "augmentation_sessions" in manifest:
        raise ValueError("This dataset has already been augmented")
    offsets = [(split, offset) for split, key in (("train", "train_seed_offsets"),
                                                ("calibration", "calibration_seed_offsets"))
               for offset in plan.get(key, [])]
    catalogue_seeds = {spec["seed"] for spec in SCENARIOS}
    all_seeds = set(catalogue_seeds)
    for _, offset in offsets:
        seeds = {spec["seed"] + offset for spec in SCENARIOS}
        if offset <= 0 or all_seeds & seeds:
            raise ValueError("Augmentation seeds must be positive offsets and disjoint across roles")
        all_seeds.update(seeds)
    root = directory / "augmentation-captures"
    root.mkdir(exist_ok=False)
    frames, sessions = [original], {}
    for split, offset in offsets:
        capture_dir = root / f"{split}-{offset}"
        capture_dir.mkdir()
        for base in SCENARIOS:
            spec = {**base, "seed": base["seed"] + offset}
            source = build(spec, str(capture_dir))
            labels = json.loads((capture_dir / (spec["id"] + ".labels.json")).read_text())
            spec["file"] = str((capture_dir / (spec["id"] + ".pcap")).resolve())
            rows, summary = replay(spec, labels)
            session = f"{spec['id']}/seed-{spec['seed']}"
            for row in rows:
                row.update(split=split, scenario=session, flow_id=f"{session}/{row['flow_id']}")
            frames.append(pd.DataFrame(rows))
            sessions[session] = {"split": split, "seed": spec["seed"], "base_scenario": spec["id"],
                                 "rows": len(rows), "source": source, "extraction": summary}
            print(f"augment {split} {session}: {len(rows)} observations", flush=True)
    combined = pd.concat(frames, ignore_index=True).sort_values(["ts_ns", "scenario"], kind="stable").reset_index(drop=True)
    # Check the actual original test content before replacing this isolated dataset.
    original_test = original[original.split == "test"].reset_index(drop=True)
    updated_test = combined[combined.split == "test"].reset_index(drop=True)
    pd.testing.assert_frame_equal(original_test, updated_test)
    combined.to_parquet(path, index=False)
    manifest.update(source_dataset_sha256=manifest["dataset_sha256"],
                    dataset_sha256=sha256_file(str(path)), rows=len(combined),
                    dataset_version=manifest["dataset_version"] + "+seed-augmentation-v1",
                    augmentation_sessions=sessions,
                    augmentation_note="Additional seeds of existing synthetic templates, assigned as whole "
                                      "sessions to train or calibration. Session-local flow IDs. Original test "
                                      "observations unchanged. This does not add independent real traffic.")
    manifest["counts"] = {split: {"rows": len(part), "by_class": part.label.value_counts().to_dict()}
                          for split, part in combined.groupby("split")}
    manifest_path.write_text(json.dumps(manifest, indent=2, allow_nan=False) + "\n")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    profile = json.loads((args.directory / "profile.json").read_text())
    augment(args.directory, profile["augmentation"])
