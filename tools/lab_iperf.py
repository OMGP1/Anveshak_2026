"""Bounded benign lab traffic, outside the monitoring enclave. Loopback only, 1 Mbps, 3 s.

Exports actual iperf3 application counters, NOT a packet capture or NetFlow export.
No packet flags, DNS names, TLS fingerprints, or attack labels are invented.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import socket
import subprocess
import time
import uuid

from engine.models.tier1 import sha256_file
from engine.pipeline import Engine
from engine.sources.flowrecord_source import FlowRecordSource
from training.scenarios import FLOW_COLUMNS

ROOT = Path(__file__).resolve().parents[1]


def normalize(document: dict, path: Path) -> int:
    if document.get("error"):
        raise ValueError(document["error"])
    connections = {row["socket"]: row for row in document["start"]["connected"]}
    base = document["start"]["timestamp"]["timesecs"]
    count = 0
    with path.open("x", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FLOW_COLUMNS)
        writer.writeheader()
        for interval in document["intervals"]:
            for stream in interval["streams"]:
                conn = connections[stream["socket"]]
                if conn["local_host"] != "127.0.0.1" or conn["remote_host"] != "127.0.0.1":
                    raise ValueError("Only owned loopback lab endpoints may be imported by this helper")
                if stream["packets"] <= 0:
                    continue
                writer.writerow({"ts_start": base + stream["start"], "ts_end": base + stream["end"],
                    "src_ip": conn["local_host"], "dst_ip": conn["remote_host"],
                    "src_port": conn["local_port"], "dst_port": conn["remote_port"], "proto": "UDP",
                    "packets": stream["packets"], "bytes": stream["bytes"], "tcp_flags": "",
                    "direction_hint": "fwd"})
                count += 1
    if not count:
        raise ValueError("iperf3 reported no nonempty intervals")
    return count


def run(binary: str, directory: Path | None = None) -> dict:
    binary = str(Path(binary).resolve())
    folder = directory or ROOT / "data/lab-runs" / uuid.uuid4().hex
    folder.mkdir(mode=0o700, parents=True, exist_ok=False)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    # iperf3 owns the one-shot listener; no external addresses or unbounded modes are accepted.
    with (folder / "server.log").open("x") as log:
        server = subprocess.Popen([binary, "-s", "-1", "-B", "127.0.0.1", "-p", str(port)], stdout=log, stderr=log)
        try:
            time.sleep(0.4)
            if server.poll() is not None:
                raise RuntimeError("Loopback iperf3 server failed; inspect server.log")
            result = subprocess.run([binary, "-c", "127.0.0.1", "-B", "127.0.0.1", "-p", str(port),
                "-u", "-b", "1M", "-l", "1200", "-t", "3", "-i", "1", "-J"],
                capture_output=True, text=True, timeout=12, check=True)
            server.wait(timeout=3)
        finally:
            if server.poll() is None:
                server.terminate()
                try:
                    server.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    server.kill(); server.wait()
    raw_path = folder / "iperf.json"
    raw_path.write_text(result.stdout)
    document = json.loads(result.stdout)
    flow_path = folder / "intervals.flows.csv"
    rows = normalize(document, flow_path)
    engine = Engine()
    detections = []
    source = FlowRecordSource(str(flow_path))
    packets = nbytes = 0
    for meta in source:
        packets += meta.packets
        nbytes += meta.length
        detections.extend(engine.feed(meta))
        detections.extend(engine.tick(meta.ts_ns))
    engine.sweep()
    report = {"id": folder.name, "generator": "iperf3", "version": document["start"]["version"],
        "provenance": "real-local-loopback-application-counters", "packet_capture": False,
        "records": rows, "packets_reported": packets, "application_bytes": nbytes,
        "detections": [{"threat_class": d.threat_class, "confidence": d.confidence, "summary": d.summary} for d in detections],
        "hashes": {p.name: sha256_file(str(p)) for p in (raw_path, flow_path)},
        "limitations": "Three-second benign localhost UDP test. Application counters, not wire capture. No attack accuracy claim; not independent holdout data."}
    (folder / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    for path in folder.iterdir():
        path.chmod(0o600)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.binary), indent=2))
