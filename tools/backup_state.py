"""Offline snapshot/restore. Stop both services first; use a NEW destination each time."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil

import duckdb

from api.store import AlertStore
from engine.alerts.verify import verify_chain

NAMES = ("alerts.duckdb", "alerts.jsonl", "alerts.anchors.jsonl", "alerts.key", "alerts.pub", "gateway-audit.jsonl")


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            result.update(chunk)
    return result.hexdigest()


def snapshot(source: Path, destination: Path) -> dict:
    verdict = verify_chain(str(source / "alerts.jsonl"))
    if not verdict["ok"] or not verdict["anchors_ok"]:
        raise ValueError("Cannot back up an invalid ledger as a verified snapshot")
    # DuckDB's cross-process lock refuses a live writer. Never copy its live WAL.
    with duckdb.connect(str(source / "alerts.duckdb"), read_only=True):
        if (source / "alerts.duckdb.wal").exists():
            raise ValueError("Database WAL exists; cleanly stop the writer before snapshotting")
        destination.mkdir(parents=True, mode=0o700, exist_ok=False)
        hashes = {}
        for name in NAMES:
            path = source / name
            if path.is_file():
                target = destination / name
                shutil.copyfile(path, target)
                target.chmod(0o600)
                hashes[name] = digest(target)
        manifest = {"version": 1, "records": verdict["records"], "head": verdict["head"], "sha256": hashes}
        (destination / "snapshot.json").write_text(json.dumps(manifest, indent=2) + "\n")
    copied = verify_chain(str(destination / "alerts.jsonl"))
    if not copied["ok"] or not copied["anchors_ok"] or copied["head"] != verdict["head"]:
        raise ValueError("Source changed during snapshot; preserve the failed copy for investigation")
    return manifest


def restore(source: Path, destination: Path) -> dict:
    manifest = json.loads((source / "snapshot.json").read_text())
    names = set(manifest["sha256"])
    if not names.issubset(NAMES) or not {"alerts.jsonl", "alerts.key", "alerts.pub"}.issubset(names):
        raise ValueError("Invalid snapshot manifest")
    for name, expected in manifest["sha256"].items():
        if digest(source / name) != expected:
            raise ValueError("Snapshot hash mismatch: " + name)
    verdict = verify_chain(str(source / "alerts.jsonl"))
    if not verdict["ok"] or not verdict["anchors_ok"] or verdict["head"] != manifest["head"]:
        raise ValueError("Snapshot ledger verification failed")
    destination.mkdir(parents=True, mode=0o700, exist_ok=False)
    for name in names - {"alerts.duckdb"}:
        shutil.copyfile(source / name, destination / name)
        (destination / name).chmod(0o600)
    store = AlertStore(str(destination / "alerts.duckdb"), str(destination / "alerts.jsonl"))
    try:
        return {"records": store.count(), "head": store.verify_ledger()["head"], "database_rebuilt": True}
    finally:
        store.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["snapshot", "restore"])
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    print(json.dumps((snapshot if args.action == "snapshot" else restore)(args.source, args.destination), indent=2))
