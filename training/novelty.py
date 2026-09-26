"""Build a separately signed novelty companion from explicitly approved benign PCAPs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from engine.models.novelty import (FOREST_FILE, MANIFEST_FILE, META_FILE, NOVELTY_FEATURES,
                                   SIGNATURE_FILE, NoveltyModel)
from engine.pipeline import Engine
from engine.sources.pcap_source import PcapSource


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract(path: Path, window_s: float = 5.0) -> list[dict]:
    engine = Engine({"model_enabled": False, "anomaly_enabled": False,
                     "novelty": {"enabled": True, "shadow": True, "window_s": window_s}})
    rows: list[dict] = []
    engine.novelty.on_window = rows.append
    last = 0
    for packet in PcapSource(str(path)):
        engine.feed(packet)
        if packet.ts_ns - last >= 1_000_000_000:
            last = packet.ts_ns
            engine.tick(packet.ts_ns)
    engine.sweep()
    return rows


def train(captures: list[Path], output: Path, *, calibration_fraction: float = 0.30,
          seed: int = 26145, trees: int = 200, signing_key: Path | None = None) -> dict:
    if not captures:
        raise ValueError("at least one approved benign capture is required")
    if not 0.1 <= calibration_fraction <= 0.5:
        raise ValueError("calibration_fraction must be between 0.1 and 0.5")
    training: list[list[float]] = []
    calibration: list[list[float]] = []
    provenance = []
    for capture in captures:
        rows = extract(capture)
        if len(rows) < 16:
            raise ValueError(f"{capture} produced fewer than 16 eligible benign windows")
        rows.sort(key=lambda row: row["start_ns"])
        split = max(8, min(len(rows) - 8, int(len(rows) * (1.0 - calibration_fraction))))
        vectors = [[float(row["values"][name]) for name in NOVELTY_FEATURES] for row in rows]
        training.extend(vectors[:split])
        calibration.extend(vectors[split:])
        provenance.append({"path": str(capture), "sha256": "sha256:" + sha256_file(capture),
                           "windows": len(rows), "training_windows": split,
                           "calibration_windows": len(rows) - split,
                           "label_source": "explicitly approved benign capture"})
    model = NoveltyModel.fit(np.asarray(training), np.asarray(calibration), seed=seed, trees=trees)
    model.meta["captures"] = provenance
    model.save(output)
    manifest = {"version": 1, "schema_version": "novelty-companion-manifest-v1",
                "sha256": {name: sha256_file(output / name) for name in (FOREST_FILE, META_FILE)},
                "approved_for_automatic_promotion": False}
    raw = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    (output / MANIFEST_FILE).write_bytes(raw)
    if signing_key is not None:
        key = serialization.load_pem_private_key(signing_key.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("novelty signing key must be Ed25519")
        (output / SIGNATURE_FILE).write_text(key.sign(raw).hex() + "\n", encoding="ascii")
        manifest["signed"] = True
    else:
        manifest["signed"] = False
    report = {"state": "candidate_ready_for_review", "serving_model_changed": False,
              "feature_contract": "novelty-v1", "training_windows": len(training),
              "calibration_windows": len(calibration), "captures": provenance,
              "manifest": manifest}
    (output / "training-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benign-pcap", action="append", required=True, type=Path,
                        help="approved benign PCAP; repeat for independent captures")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--calibration-fraction", type=float, default=0.30)
    parser.add_argument("--seed", type=int, default=26145)
    parser.add_argument("--trees", type=int, default=200)
    parser.add_argument("--signing-key", type=Path)
    args = parser.parse_args()
    print(json.dumps(train(args.benign_pcap, args.output,
                           calibration_fraction=args.calibration_fraction,
                           seed=args.seed, trees=args.trees, signing_key=args.signing_key), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
