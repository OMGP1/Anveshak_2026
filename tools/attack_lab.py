"""Local attack-pattern tests: owned loopback sockets, or offline capture fixtures.

Run from SIH2026_prototype:
    python -m tools.attack_lab live --scenario mixed
    python -m tools.attack_lab offline

This operator tool is separate from the passive monitoring engine. It cannot
target another host. Live tests require the local development API and dumpcap.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import heapq
from itertools import zip_longest
import json
import os
from pathlib import Path
import random
import socket
import time
import uuid

import dpkt
import httpx

ROOT = Path(__file__).resolve().parents[1]
LOOPBACK = "127.0.0.1"
RATE = 35  # Fixed, modest application datagrams/s; no flood or unlimited mode.
DNS_COUNT = 128
SCAN_PORTS = 96
LIVE_EXPECTED = {
    "dns-tunnel": {"dga-dns-tunnelling"},
    "scan": {"recon-scanning"},
    "mixed": {"dga-dns-tunnelling", "recon-scanning"},
    "benign": set(),
}
CAPTURES = ("benign", "syn_flood", "udp_reflection", "slowloris", "beacon_jitter",
            "dga_burst", "dns_tunnel", "ja4_spoof", "port_scan", "exfil_drip", "exfil_bulk")
ALL_CLASSES = {"volumetric-ddos", "c2-beaconing", "dga-dns-tunnelling",
               "encrypted-malware", "recon-scanning", "data-exfiltration"}


def api_json(client, method: str, path: str, **kwargs):
    response = client.request(method, path, **kwargs)
    if not response.is_success:
        try:
            reason = response.json().get("detail", response.text[:500])
        except ValueError:
            reason = response.text[:500]
        raise RuntimeError(f"API {path}: {response.status_code}: {reason}")
    return response.json()


def dns_query(index: int, seed: int, zone: str) -> bytes:
    rng = random.Random(seed + index)
    label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(52))
    question = dpkt.dns.DNS.Q(name=f"{label}.{zone}.test", type=dpkt.dns.DNS_TXT)
    return bytes(dpkt.dns.DNS(id=index, qd=[question]))


class LoopbackTraffic:
    """Hold every destination socket for the entire run; never probe other services."""
    def __init__(self, scenario: str, run_id: str, seed: int = 26145):
        if scenario not in LIVE_EXPECTED:
            raise ValueError("Unknown live scenario")
        self.scenario, self.run_id, self.seed = scenario, run_id, seed
        self.resources = ExitStack()
        self.steps = []
        self.sent = self.received = self.payload_bytes = 0

    def _socket(self, port=0):
        sock = self.resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        sock.bind((LOOPBACK, port))
        sock.settimeout(1)
        return sock

    def __enter__(self):
        try:
            self.sender = self._socket()
            dns_steps, scan_steps = [], []
            if self.scenario in {"dns-tunnel", "mixed"}:
                receiver = None
                for port in (5353, 53, 5355):
                    try:
                        receiver = self._socket(port)
                        break
                    except OSError:
                        continue
                if receiver is None:
                    raise RuntimeError("Cannot reserve an owned DNS receiver on 5353, 53 or 5355. Use the offline test.")
                zone = "lab-" + self.run_id[:12]
                dns_steps = [(receiver, dns_query(i, self.seed, zone)) for i in range(DNS_COUNT)]
            if self.scenario in {"scan", "mixed"}:
                scan_steps = [(self._socket(), b"SIH lab probe") for _ in range(SCAN_PORTS)]
            if self.scenario == "benign":
                receiver = self._socket()
                self.steps = [(receiver, b"SIH ordinary local telemetry") for _ in range(64)]
            else:
                self.steps = [step for pair in zip_longest(dns_steps, scan_steps) for step in pair if step]
            self.filter = (f"udp and src host {LOOPBACK} and dst host {LOOPBACK} "
                           f"and src port {self.sender.getsockname()[1]}")
            return self
        except BaseException:
            self.resources.close()
            raise

    def __exit__(self, *exc):
        self.resources.close()

    def send(self):
        started = time.monotonic()
        for receiver, payload in self.steps:
            endpoint = receiver.getsockname()
            if endpoint[0] != LOOPBACK or self.sender.getsockname()[0] != LOOPBACK:
                raise RuntimeError("Lab endpoints must be owned IPv4 loopback sockets")
            self.sender.sendto(payload, endpoint)
            self.sent += 1
            self.payload_bytes += len(payload)
            received, peer = receiver.recvfrom(2048)
            if received != payload or peer != self.sender.getsockname():
                raise RuntimeError("The owned lab receiver did not receive the expected datagram")
            self.received += 1
            # Sleep after every exchange: never catch up with a high-rate burst.
            time.sleep(1 / RATE)
        return time.monotonic() - started

    def stats(self):
        return {"planned_datagrams": len(self.steps), "sent_datagrams": self.sent,
                "received_by_owned_sockets": self.received, "payload_bytes": self.payload_bytes,
                "maximum_datagrams_per_s": RATE, "destination": LOOPBACK,
                "destination_ports": sorted({s.getsockname()[1] for s, _ in self.steps}),
                "capture_filter": self.filter}


def assess(expected: set[str], alerts: list[dict]) -> dict:
    counts = Counter(row["x_threat_class"] for row in alerts)
    missing = sorted(expected - counts.keys())
    return {"expected_classes": sorted(expected), "observed_counts": dict(counts),
            "missing_classes": missing, "additional_classes": sorted(counts.keys() - expected),
            "detection_check_passed": not missing and (bool(expected) or not counts)}


def run_live(client, scenario: str, report: dict, alerts: list[dict]) -> None:
    # Never interrupt an operator's existing capture or replay.
    if api_json(client, "GET", "/api/status")["running"]:
        raise RuntimeError("A capture or replay is already running. Stop it in the dashboard before running this lab test.")
    listing = api_json(client, "GET", "/api/live/interfaces")
    interface = next((row for row in listing["interfaces"]
                      if "loopback" in (row["id"] + row["name"]).lower() or row["id"] in {"lo", "lo0"}), None)
    if not listing["available"] or interface is None:
        raise RuntimeError(listing.get("error") or "No loopback capture interface is available; install Npcap/dumpcap.")
    session = None
    with LoopbackTraffic(scenario, report["run_id"]) as traffic:
        try:
            state = api_json(client, "POST", "/api/live/start", json={
                "interface": interface["id"], "capture_filter": traffic.filter})
            session = state["session_id"]
            report.update(capture_session=session, interface=interface, traffic=traffic.stats())
            print(f"Live {scenario}: sending {len(traffic.steps)} local datagrams. Watch the dashboard Alerts page.", flush=True)
            elapsed = traffic.send()
            report["send_seconds"] = round(elapsed, 3)
            deadline = time.monotonic() + 15
            expected = LIVE_EXPECTED[scenario]
            while True:
                state = api_json(client, "GET", "/api/live/status")
                if state["session_id"] != session or not state["running"] or state["error"]:
                    raise RuntimeError(state["error"] or "The lab capture session was stopped or replaced")
                metrics = api_json(client, "GET", "/api/metrics")
                # UUID filtering excludes old alerts, even when history contains
                # an identical class or an earlier test's loopback endpoints.
                rows = api_json(client, "GET", "/api/alerts", params={"limit": 1000})
                alerts[:] = [row for row in rows if row.get("x_detection_context", {}).get("capture_session") == session]
                if len(rows) == 1000 and len(alerts) == 1000:
                    raise RuntimeError("Lab alert limit exceeded; cannot verify a complete result")
                result = assess(expected, alerts)
                drained = metrics["packets"] >= traffic.sent and state["capture"]["queue_depth"] == 0
                report.update(result, processed_packets=metrics["packets"], capture=state["capture"],
                              live_latency_ms=metrics.get("live_latency_ms"))
                # Observe a quiet tail even for a negative control; idle windows
                # can emit alerts after the sender has finished.
                if (drained and result["detection_check_passed"] and time.monotonic() >= deadline - 12) or time.monotonic() >= deadline:
                    break
                time.sleep(.25)
            from engine.alerts.schema import validate_alert
            for row in alerts:
                validate_alert(row)
            capture = state["capture"]
            report["capture_check_passed"] = (drained and capture["queue_dropped"] == 0
                                               and capture["stale_dropped"] == 0 and capture["undecodable"] == 0)
            report["passed"] = report["capture_check_passed"] and report["detection_check_passed"]
        finally:
            report["traffic"] = traffic.stats()
            if session is not None:
                try:
                    stopped = api_json(client, "POST", "/api/live/stop", params={"session_id": session})
                    report["capture_stopped"] = not stopped["running"]
                except (httpx.HTTPError, RuntimeError) as exc:
                    report.update(passed=False, cleanup_error=str(exc), capture_stopped=False)


def run_offline(report: dict, folder: Path, alerts: list[dict]) -> None:
    from api.live import live_config
    from api.store import AlertStore
    from engine.alerts.schema import build_alert
    from engine.pipeline import Engine
    from engine.sources.pcap_source import PcapSource

    config_path = os.environ.get("SIH_ENGINE_CONFIG")
    overrides = json.loads(Path(config_path).read_text()) if config_path else {}
    if not isinstance(overrides, dict):
        raise ValueError("SIH_ENGINE_CONFIG must contain a JSON object")
    config = live_config(overrides)
    paths = [ROOT / "data/scenarios" / (name + ".pcap") for name in CAPTURES]
    report["input_captures"] = []
    for path in paths:
        with path.open("rb") as handle:
            report["input_captures"].append({"file": path.name, "sha256": hashlib.file_digest(handle, "sha256").hexdigest()})
    sources = [PcapSource(str(path)) for path in paths]
    engine = Engine(config)
    report["configuration"] = config
    report["first_alert_packet_index"] = {}
    packets = last_tick = 0
    started = time.monotonic()
    store = AlertStore(str(folder / "alerts.duckdb"), str(folder / "alerts.ledger.jsonl"))
    try:
        for packet in heapq.merge(*(iter(source) for source in sources), key=lambda item: item.ts_ns):
            arrival = time.perf_counter_ns()
            packets += 1
            detections = engine.feed(packet)
            if packet.ts_ns - last_tick >= 1_000_000_000:
                last_tick = packet.ts_ns
                detections += engine.tick(packet.ts_ns)
            for detection in detections:
                lineage = engine.lineage_for(detection)
                lineage.update(latency_ns=time.perf_counter_ns() - arrival, prev_hash=store.ledger.head)
                alert = build_alert(detection, lineage)
                store.append(alert)
                alerts.append(alert)
                report["first_alert_packet_index"].setdefault(detection.threat_class, packets)
            if packets % 20000 == 0:
                print(f"Offline: {packets:,} packets; {len(report['first_alert_packet_index'])}/6 classes detected", flush=True)
        engine.sweep()
        verdict = store.verify_ledger()
        report.update(assess(ALL_CLASSES, alerts), processed_packets=packets,
                      elapsed_s=round(time.monotonic() - started, 3), ledger_ok=verdict["ok"])
        report["passed"] = report["detection_check_passed"] and verdict["ok"]
    finally:
        report["processed_packets"] = packets
        store.close()


def save_result(folder: Path, report: dict, alerts: list[dict]) -> None:
    (folder / "alerts.json").write_text(json.dumps(alerts, indent=2) + "\n", encoding="utf-8")
    with (folder / "alerts.jsonl").open("w", encoding="utf-8") as handle:
        for alert in alerts:
            handle.write(json.dumps(alert) + "\n")
    report["alert_count"] = len(alerts)
    report["finished_at"] = datetime.now(timezone.utc).isoformat()
    (folder / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="mode", required=True)
    live = commands.add_parser("live", help="Send small DNS/scan patterns only to owned loopback receivers; verify API alerts")
    live.add_argument("--scenario", choices=tuple(LIVE_EXPECTED), default="mixed")
    live.add_argument("--api-port", type=int, default=8000, help="Local development API port (host is fixed to 127.0.0.1)")
    commands.add_parser("offline", help="Interleave all 11 synthetic captures; check all six classes without sending packets")
    args = parser.parse_args(argv)
    if args.mode == "live" and not 1 <= args.api_port <= 65535:
        parser.error("--api-port must be between 1 and 65535")
    run_id = uuid.uuid4().hex
    folder = ROOT / "data/attack-lab" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + run_id[:8])
    folder.mkdir(parents=True, exist_ok=False)
    report = {"run_id": run_id, "mode": args.mode, "passed": False,
              "started_at": datetime.now(timezone.utc).isoformat(), "report_directory": str(folder),
              "limitations": ("Synthetic functional check, not precision/recall or real malware validation. "
                              "Live mode checks DNS/UDP scanning and local capture; driver drops remain unknown. "
                              "Offline mode checks six classes but does not test NIC capture or show alerts in the running dashboard.")}
    alerts = []
    code = 1
    try:
        if args.mode == "live":
            report["scenario"] = args.scenario
            # No proxy environment, redirects, DNS lookup, or remote API option.
            with httpx.Client(base_url=f"http://{LOOPBACK}:{args.api_port}", timeout=15,
                              trust_env=False, follow_redirects=False) as client:
                run_live(client, args.scenario, report, alerts)
        else:
            run_offline(report, folder, alerts)
        code = 0 if report["passed"] else 1
    except KeyboardInterrupt:
        report.update(passed=False, error="Interrupted by the operator")
        code = 130
    except Exception as exc:
        report.update(passed=False, error=f"{type(exc).__name__}: {exc}")
        if isinstance(exc, httpx.ConnectError):
            report["hint"] = "Start python app.py in another terminal, then rerun this tool."
        code = 2
    finally:
        save_result(folder, report, alerts)
    print("\n" + ("PASS" if report["passed"] else "FAIL") + f" - {args.mode} lab test")
    for threat in report.get("expected_classes", []):
        count = report.get("observed_counts", {}).get(threat, 0)
        print(f"  {'FOUND' if count else 'MISSED'} {threat}: {count} alert(s)")
    if not report.get("expected_classes") and "observed_counts" in report:
        print(f"  Benign control: {len(alerts)} alert(s)")
    if report.get("error"):
        print(report["error"])
    if report.get("hint"):
        print(report["hint"])
    if report.get("cleanup_error"):
        print("Capture cleanup: " + report["cleanup_error"])
    print("Report: " + str(folder / "report.json"))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
