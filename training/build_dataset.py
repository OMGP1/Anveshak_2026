from __future__ import annotations

import hashlib
import json
import os
import sys
import time

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.models.tier1 import MODEL_DIR, MODEL_FEATURES
from engine.pipeline import Engine
from engine.sources.pcap_source import PcapSource
from training.scenarios import SCENARIOS, abspath, load_labels

DATASET_VERSION = "2026-09-08-scenario-replay-v2"

SPLIT_BOUNDS = {
    "train_end": 0.42,
    "calibration_start": 0.45,
    "calibration_end": 0.53,
    "test_start": 0.56,
}

SPLIT_NOTE = (
    "the split is temporal and per capture session. every row is placed by the fraction of its "
    "own session's timeline that had elapsed when the engine produced it. rows inside the two "
    "embargo bands are discarded so no observation sits adjacent to the boundary. nothing is "
    "shuffled and no row is ever assigned at random, because random splitting puts flows from the "
    "same attack burst on both sides and turns the reported accuracy into fiction"
)

META_COLUMNS = [
    "scenario", "split", "ts", "ts_ns", "session_fraction", "proto", "src_ip", "dst_ip",
    "src_port", "dst_port", "flow_id", "fresh", "rule_class", "rule_confidence", "rule_subtype",
    "label", "subtype",
    "udp_packet_share", "reflection_service_share", "udp_egress_observed",
]

TICK_INTERVAL_S = 5.0


def split_for(fraction: float) -> str:
    if fraction < SPLIT_BOUNDS["train_end"]:
        return "train"
    if fraction < SPLIT_BOUNDS["calibration_start"]:
        return "embargo"
    if fraction < SPLIT_BOUNDS["calibration_end"]:
        return "calibration"
    if fraction < SPLIT_BOUNDS["test_start"]:
        return "embargo"
    return "test"


def label_for(labels: dict, ts: float, src_ip: str, dst_ip: str) -> tuple[str, str]:
    for attack in labels.get("attacks", []):
        if not (attack["start_ts"] <= ts <= attack["end_ts"]):
            continue
        attackers = set(attack.get("attackers", []))
        victims = set(attack.get("victims", []))
        if (src_ip in attackers and dst_ip in victims) or (src_ip in victims and dst_ip in attackers):
            return attack["threat_class"], attack.get("subtype", "")
    return "benign", ""


def replay(spec: dict, labels: dict | None = None) -> tuple[list[dict], dict]:
    labels = load_labels(spec["id"]) if labels is None else labels
    capture = labels["capture"]
    first_ts = float(capture["first_ts"])
    duration = max(1e-6, float(capture["last_ts"]) - first_ts)
    rows: list[dict] = []

    def sink(row: dict) -> None:
        src_ip = row["src_ip"]
        dst_ip = row["dst_ip"]
        if not src_ip or not dst_ip or src_ip.startswith("<") or dst_ip.startswith("<"):
            return
        fraction = (row["ts"] - first_ts) / duration
        split = split_for(fraction)
        if split == "embargo":
            return
        threat, subtype = label_for(labels, row["ts"], src_ip, dst_ip)
        record = {
            "scenario": spec["id"],
            "split": split,
            "ts": row["ts"],
            "ts_ns": row["ts_ns"],
            "session_fraction": round(fraction, 6),
            "proto": row["proto"],
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": row["src_port"],
            "dst_port": row["dst_port"],
            "flow_id": "{0}|{1}:{2}|{3}:{4}".format(
                row["proto"], src_ip, row["src_port"], dst_ip, row["dst_port"]),
            "fresh": row["fresh"],
            "rule_class": row["rule_class"],
            "rule_confidence": row["rule_confidence"],
            "rule_subtype": row["rule_subtype"],
            "label": threat,
            "subtype": subtype,
        }
        values = row["values"]
        for name in ("udp_packet_share", "reflection_service_share", "udp_egress_observed"):
            record[name] = float(values.get(name, np.nan))
        for name in MODEL_FEATURES:
            record[name] = float(values.get(name, np.nan))
        rows.append(record)

    engine = Engine({"model_enabled": False, "anomaly_enabled": False})
    engine.on_vector = sink
    started = time.perf_counter()
    last_tick = 0
    for meta in PcapSource(abspath(spec["file"])):
        engine.feed(meta)
        if meta.ts_ns - last_tick > TICK_INTERVAL_S * 1e9:
            last_tick = meta.ts_ns
            engine.tick(meta.ts_ns)
    if last_tick:
        engine.tick(last_tick + int(TICK_INTERVAL_S * 1e9))
    engine.sweep()
    elapsed = time.perf_counter() - started
    summary = {
        "scenario": spec["id"],
        "packets": engine.packets,
        "rows": len(rows),
        "observations_scored": engine.scored,
        "seconds": round(elapsed, 2),
        "packets_per_s": round(engine.packets / max(elapsed, 1e-9), 1),
        "rule_detections": engine.detections,
    }
    return rows, summary


def leakage_report(frame: pd.DataFrame) -> dict:
    train = set(frame.loc[frame["split"] == "train", "flow_id"])
    test = set(frame.loc[frame["split"] == "test", "flow_id"])
    shared = train & test
    test_rows = frame[frame["split"] == "test"]
    affected = int(test_rows["flow_id"].isin(shared).sum())
    return {
        "flow_ids_train": len(train),
        "flow_ids_test": len(test),
        "flow_ids_on_both_sides": len(shared),
        "test_rows_from_a_flow_seen_in_train": affected,
        "test_rows": int(len(test_rows)),
        "note": (
            "a flow that outlives the boundary is counted here rather than hidden. these are "
            "long-lived channels such as a beacon or a drip upload, not duplicated samples of one "
            "burst. evaluate.py reports a strict variant with every one of these rows removed"
        ),
    }


def main() -> int:
    os.makedirs(MODEL_DIR, exist_ok=True)
    all_rows: list[dict] = []
    summaries = []
    for spec in SCENARIOS:
        rows, summary = replay(spec)
        all_rows.extend(rows)
        summaries.append(summary)
        print("{0:16s} {1:6d} packets {2:6d} rows {3:7.2f}s {4:9.0f} pkt/s".format(
            spec["id"], summary["packets"], summary["rows"], summary["seconds"],
            summary["packets_per_s"]))
    frame = pd.DataFrame(all_rows, columns=META_COLUMNS + MODEL_FEATURES)
    frame = frame.sort_values(["ts_ns", "scenario"], kind="stable").reset_index(drop=True)
    path = os.path.join(MODEL_DIR, "dataset.parquet")
    frame.to_parquet(path, index=False)
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    counts = {}
    for split in ("train", "calibration", "test"):
        part = frame[frame["split"] == split]
        counts[split] = {
            "rows": int(len(part)),
            "by_class": {k: int(v) for k, v in part["label"].value_counts().items()},
        }
    manifest = {
        "dataset_version": DATASET_VERSION,
        "rows": int(len(frame)),
        "features": MODEL_FEATURES,
        "feature_count": len(MODEL_FEATURES),
        "split_bounds": SPLIT_BOUNDS,
        "split_note": SPLIT_NOTE,
        "counts": counts,
        "scenarios": summaries,
        "leakage": leakage_report(frame),
        "dataset_sha256": "sha256:" + digest,
        "labelling_note": (
            "a row is an attack row only when both endpoints of its flow appear in one labelled "
            "attack window, one as an attacker and one as a victim. everything else is benign, "
            "including traffic from an infected host to a destination the label does not name"
        ),
    }
    with open(os.path.join(MODEL_DIR, "dataset_manifest.json"), "w", encoding="ascii") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
    print()
    print("rows", len(frame), "features", len(MODEL_FEATURES))
    for split, info in counts.items():
        print(" ", split, info["rows"], info["by_class"])
    print(" leakage", manifest["leakage"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
