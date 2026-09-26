"""Read-only inventory. Expected hashes are evidence, not an authenticity signature."""
from __future__ import annotations

import csv
import json
import os
import subprocess
from pathlib import Path

from engine.models.tier1 import MODEL_FEATURES, sha256_file
from training import scenarios
from training.problem_statement import problem_statement_inventory

ROOT = Path(scenarios.ROOT)


def inspect_datasets(root: Path = ROOT) -> dict:
    root = Path(root)
    errors: list[str] = []
    try:
        index = json.loads((root / "data/scenarios/index.json").read_text())
    except (OSError, ValueError) as exc:
        index = {}
        errors.append(f"Scenario index unavailable: {exc}")
    rows = []
    expected_ids = {s["id"] for s in scenarios.SCENARIOS}
    if set(index) != expected_ids:
        errors.append("Scenario index does not match the application catalogue")
    for spec in scenarios.SCENARIOS:
        sid = spec["id"]
        reference = index.get(sid, {})
        files = []
        row_errors = []
        for kind, field, size_field in (("pcap", "file", "pcap_size"),
                                        ("flows", "flow_file", "flow_size"),
                                        ("labels", "labels_file", None)):
            path = root / spec[field]
            item = {"kind": kind, "path": spec[field], "exists": path.is_file(),
                    "bytes": 0, "sha256": None, "hash_status": "unverified"}
            try:
                item["bytes"] = path.stat().st_size
                item["sha256"] = sha256_file(str(path))
                expected = reference.get("pcap_sha256") if kind == "pcap" else None
                item["hash_status"] = "measured_only" if not expected else (
                    "match" if item["sha256"] == "sha256:" + expected else "mismatch")
                if item["hash_status"] == "mismatch":
                    row_errors.append(f"{kind}: SHA-256 mismatch")
                if size_field and item["bytes"] != reference.get(size_field):
                    row_errors.append(f"{kind}: byte size mismatch")
                if kind == "flows":
                    with path.open(newline="") as handle:
                        reader = csv.DictReader(handle)
                        if reader.fieldnames != scenarios.FLOW_COLUMNS:
                            row_errors.append("flows: columns differ from the contract")
                        count = sum(1 for _ in reader)
                    item["records"] = count
                    if count != reference.get("flow_records"):
                        row_errors.append("flows: record count mismatch")
                elif kind == "labels":
                    labels = json.loads(path.read_text())
                    if labels.get("scenario") != sid or labels.get("capture", {}).get("packets") != spec["packets"]:
                        row_errors.append("labels: scenario or packet count mismatch")
            except (OSError, ValueError, csv.Error) as exc:
                row_errors.append(f"{kind}: {exc}")
            files.append(item)
        rows.append({"id": sid, "name": spec["name"], "provenance": "synthetic",
                     "dashboard_available": True, "packets": spec["packets"],
                     "flow_records": spec["flow_records"], "files": files,
                     "ok": not row_errors, "errors": row_errors})
    model = {"ok": False, "path": "data/models/dataset.parquet", "errors": []}
    try:
        manifest = json.loads((root / "data/models/dataset_manifest.json").read_text())
        digest = sha256_file(str(root / model["path"]))
        model.update(sha256=digest, rows=manifest["rows"], features=manifest["feature_count"],
                     counts=manifest["counts"], provenance="synthetic")
        if digest != manifest["dataset_sha256"]:
            model["errors"].append("Training dataset SHA-256 mismatch")
        if manifest["features"] != MODEL_FEATURES:
            model["errors"].append("Training feature order differs from the engine")
        model["ok"] = not model["errors"]
    except (OSError, ValueError, KeyError) as exc:
        model["errors"].append(str(exc))
    native = {"available": False, "ok": None}
    binary = root / "native/pcap-audit/target/release" / ("pcap-audit.exe" if os.name == "nt" else "pcap-audit")
    if binary.is_file():
        native["available"] = True
        try:
            command = [str(binary), *(str(root / spec["file"]) for spec in scenarios.SCENARIOS)]
            process = subprocess.run(command, capture_output=True, text=True, timeout=15)
            checks = [json.loads(line) for line in process.stdout.splitlines()]
            native["ok"] = process.returncode == 0 and len(checks) == len(rows) and all(
                check["packets"] == row["packets"] for check, row in zip(checks, rows))
            if not native["ok"]:
                errors.append("Native PCAP structure or packet count audit failed")
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
            native.update(ok=False, error=str(exc))
            errors.append("Native PCAP audit could not complete")
    return {"ok": not errors and all(row["ok"] for row in rows) and model["ok"],
            "native_audit": native,
            "scope": "Bundled files plus the generator specification supplied in PS26145. Integrity passing does not mean all real tool-generated data is present.",
            "problem_statement": problem_statement_inventory(root),
            "hash_note": "PCAP and parquet hashes have existing references. CSV and label hashes are measured only.",
            "scenarios": rows, "training_dataset": model, "errors": errors}


if __name__ == "__main__":
    result = inspect_datasets()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["ok"] else 1)
