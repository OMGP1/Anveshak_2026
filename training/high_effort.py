"""Rebuild current-engine features and train a high-effort candidate in a new isolated directory."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

from engine.models.integrity import ARTIFACTS
from training.candidate import PROFILE, ROOT, check_dataset


def run(directory: Path, profile_path: Path = PROFILE, dataset_from: Path | None = None) -> dict:
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    profile = json.loads(profile_path.read_text())
    (directory / "profile.json").write_text(json.dumps(profile, indent=2) + "\n")
    serving = ROOT / "data/models"
    before = {name: hashlib.sha256((serving / name).read_bytes()).hexdigest()
              for name in (*ARTIFACTS, "dataset.parquet", "dataset_manifest.json")}
    (directory / "serving-before.json").write_text(json.dumps(before, indent=2) + "\n")
    environment = dict(os.environ)
    for name in ("SIH_PRODUCTION", "SIH_MODEL_DIR", "SIH_MODEL_PUBLIC_KEY", "SIH_GATEWAY_SECRET",
                 "SIH_GATEWAY_SECRET_FILE", "SIH_OPERATOR_TOKEN"):
        environment.pop(name, None)
    environment.update(OMP_NUM_THREADS="2", OPENBLAS_NUM_THREADS="2", MKL_NUM_THREADS="2")
    status = {"state": "building_dataset", "started_at": time.time(), "directory": str(directory)}
    status_path = directory / "status.json"
    status_path.write_text(json.dumps(status, indent=2) + "\n")
    try:
        if dataset_from is None:
            with (directory / "dataset-build.log").open("w", encoding="utf-8") as log:
                subprocess.run([sys.executable, "-u", "-m", "training.build_dataset"], cwd=ROOT,
                               env={**environment, "SIH_MODEL_DIR": str(directory)}, stdout=log,
                               stderr=subprocess.STDOUT, timeout=profile["timeout_s"], check=True)
        else:
            source_manifest = check_dataset(dataset_from)
            for name in ("dataset.parquet", "dataset_manifest.json"):
                shutil.copy2(dataset_from / name, directory / name)
            status.update(dataset_reused_from=str(dataset_from.resolve()),
                          dataset_sha256=source_manifest["dataset_sha256"])
            (directory / "dataset-build.log").write_text(
                f"Reused verified dataset from {dataset_from.resolve()}; augmentation was not rerun.\n")
        if profile.get("augmentation") and dataset_from is None:
            status["state"] = "augmenting_dataset"
            status_path.write_text(json.dumps(status, indent=2) + "\n")
            with (directory / "augmentation.log").open("w", encoding="utf-8") as log:
                subprocess.run([sys.executable, "-u", "-m", "training.augment_dataset", str(directory)],
                               cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT,
                               timeout=profile["timeout_s"], check=True)
        status["state"] = "training"
        status_path.write_text(json.dumps(status, indent=2) + "\n")
        with (directory / "worker.log").open("w", encoding="utf-8") as log:
            subprocess.run([sys.executable, "-u", "-m", "training.candidate", str(directory)], cwd=ROOT,
                           env=environment, stdout=log, stderr=subprocess.STDOUT,
                           timeout=profile["timeout_s"], check=True)
        result = json.loads((directory / "result.json").read_text())
        status.update(state=result["state"], model_hash=result["model_hash"], gates=result["gates"])
        if any(hashlib.sha256((serving / name).read_bytes()).hexdigest() != digest
               for name, digest in before.items()):
            raise ValueError("Serving artifacts changed during the run")
        status["serving_model_changed"] = False
    except Exception as exc:
        status.update(state="failed", error=str(exc))
        raise
    finally:
        status["finished_at"] = time.time()
        status_path.write_text(json.dumps(status, indent=2) + "\n")
    return status


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, default=PROFILE)
    parser.add_argument("--dataset-from", type=Path, help="Reuse a checksum-verified dataset without rebuilding or augmentation")
    parser.add_argument("--output", type=Path, default=ROOT / "data/training-runs" /
                        ("quality-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")))
    args = parser.parse_args()
    result = run(args.output, args.profile, args.dataset_from)
    print(json.dumps({key: result[key] for key in ("state", "directory", "serving_model_changed")}))
