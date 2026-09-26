"""Validate passive capture using only this process's benign local UDP exchange."""
import json
import argparse
from pathlib import Path
import socket
import tempfile
import time

from fastapi.testclient import TestClient

from api.main import create_app
from engine.sources.live_source import interfaces

ROOT = Path(__file__).resolve().parents[1]


def validate(packet_count=40, rate=50):
    if not 1 <= packet_count <= 100000 or not 1 <= rate <= 2000:
        raise ValueError("Local validation is bounded to 100000 packets and 2000 packets/s")
    listing = interfaces()
    local = next((row for row in listing["interfaces"]
                  if "loopback" in (row["id"] + row["name"]).lower() or row["id"] in {"lo", "lo0"}), None)
    if local is None:
        raise RuntimeError(listing["error"] or "A local loopback capture interface is required")
    with tempfile.TemporaryDirectory(prefix="sih-live-test-") as directory:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            receiver.bind(("127.0.0.1", 0))
            sender.bind(("127.0.0.1", 0))
            receiver.settimeout(1)
            destination, origin = receiver.getsockname()[1], sender.getsockname()[1]
            filter_text = f"udp and src host 127.0.0.1 and dst host 127.0.0.1 and src port {origin} and dst port {destination}"
            with TestClient(create_app(str(Path(directory) / "a.duckdb"), str(Path(directory) / "a.jsonl"))) as client:
                started = client.post("/api/live/start", json={"interface": local["id"], "capture_filter": filter_text})
                if started.status_code != 200:
                    raise RuntimeError(started.text)
                try:
                    begin = time.perf_counter()
                    for index in range(packet_count):
                        sender.sendto(b"SIH benign local passive capture verification", receiver.getsockname())
                        receiver.recvfrom(256)
                        time.sleep(max(0, begin + (index + 1) / rate - time.perf_counter()))
                    send_seconds = time.perf_counter() - begin
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        metrics = client.get("/api/metrics").json()
                        if metrics["packets"] >= packet_count:
                            break
                        time.sleep(0.05)
                    status = client.get("/api/live/status").json()
                    if metrics["packets"] < packet_count or status["error"]:
                        raise RuntimeError(json.dumps(status))
                    report = {"kind": "real-local-loopback-live-capture", "interface_name": local["name"],
                              "generated_packets": packet_count, "generation_seconds": round(send_seconds, 3),
                              "target_packets_per_s": rate,
                              "generated_packets_per_s": round(packet_count / send_seconds, 2),
                              "processed_packets": metrics["packets"], "alerts": metrics["alerts"],
                              "capture": status["capture"], "no_processing_error": not status["error"],
                              "limitations": "Small benign loopback exchange, not real attack validation or a saturation benchmark."}
                finally:
                    stopped = client.post("/api/live/stop")
                report["clean_stop"] = stopped.status_code == 200 and not stopped.json()["running"]
                report["json_export_valid"] = isinstance(client.get("/api/alerts/export").json(), list)
    target = ROOT / "bench/live-capture-validation-20260908.json"
    target.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packets", type=int, default=40)
    parser.add_argument("--rate", type=float, default=50)
    options = parser.parse_args()
    validate(options.packets, options.rate)
