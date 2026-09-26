"""Offline, interleaved multi-attack validation. Never sends capture packets.

Measures decode + detectors + inference + durable JSON alert output together.
No fixture names or labels are supplied to the detection engine.
"""
import argparse
from collections import Counter
import heapq
import json
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from api.store import AlertStore
from api.live import live_config
from engine.alerts.schema import build_alert
from engine.pipeline import Engine
from engine.sources.pcap_source import PcapSource
from engine.metrics import LatencyHistogram

SCENARIOS = ["benign", "syn_flood", "udp_reflection", "slowloris", "beacon_jitter", "dga_burst",
             "dns_tunnel", "ja4_spoof", "port_scan", "exfil_drip", "exfil_bulk"]
EXPECTED = {"volumetric-ddos", "c2-beaconing", "dga-dns-tunnelling", "encrypted-malware",
            "recon-scanning", "data-exfiltration"}
CONFIG = live_config()


def run(output: Path, target_pps: float = 1000):
    sources = [PcapSource(str(ROOT / "data/scenarios" / (name + ".pcap"))) for name in SCENARIOS]
    engine = Engine(CONFIG)
    counts = Counter()
    saved_latency = LatencyHistogram()
    first_seen = {}
    packets = total_bytes = last_tick = 0
    buckets = []
    bucket_packets = 0
    with tempfile.TemporaryDirectory(prefix="sih-mixed-") as folder:
        store = AlertStore(str(Path(folder) / "alerts.duckdb"), str(Path(folder) / "alerts.jsonl"))
        started = bucket_start = time.perf_counter()
        for packet in heapq.merge(*(iter(source) for source in sources), key=lambda item: item.ts_ns):
            t0 = time.perf_counter_ns()
            packets += 1
            total_bytes += packet.length
            detections = engine.feed(packet)
            if packet.ts_ns - last_tick >= 1_000_000_000:
                last_tick = packet.ts_ns
                detections += engine.tick(packet.ts_ns)
            for detection in detections:
                lineage = engine.lineage_for(detection)
                lineage.update(latency_ns=time.perf_counter_ns() - t0, prev_hash=store.ledger.head)
                store.append(build_alert(detection, lineage))
                saved_latency.add(time.perf_counter_ns() - t0)
                counts[detection.threat_class] += 1
                first_seen.setdefault(detection.threat_class, packets)
            now = time.perf_counter()
            if now - bucket_start >= 1:
                buckets.append({"elapsed_s": round(now - started, 3),
                                "packets_per_s": round((packets - bucket_packets) / (now - bucket_start), 2)})
                bucket_start, bucket_packets = now, packets
            if packets % 20000 == 0:
                print(f"Processed {packets} interleaved packets; classes observed: {len(counts)}/6", flush=True)
        elapsed = time.perf_counter() - started
        engine.sweep()
        verdict = store.verify_ledger()
        exported = json.loads("".join(store.export_records()))
        stats = engine.stats()
        rates = [bucket["packets_per_s"] for bucket in buckets]
        report = {"kind": "offline-interleaved-multi-attack", "scenario_files": SCENARIOS,
                  "all_six_classes_before_eof": EXPECTED <= set(first_seen),
                  "counts": dict(counts), "first_alert_packet_index": first_seen,
                  "packets": packets, "elapsed_s": round(elapsed, 3),
                  "packets_per_s": round(packets / elapsed, 2), "mbps": round(total_bytes * 8 / elapsed / 1e6, 3),
                  "processing_to_saved_alert_ms": {name: round(saved_latency.quantile(q) / 1e6, 3)
                                                for name, q in (("p50", .5), ("p95", .95), ("p99", .99))},
                  "declared_target_pps": target_pps,
                  "minimum_complete_1s_bucket_pps": min(rates) if rates else None,
                  "target_met_every_complete_bucket": bool(rates) and min(rates) >= target_pps,
                  "buckets": buckets, "exported_records": len(exported), "ledger_ok": verdict["ok"],
                  "memory_bytes": stats["memory_bytes"], "configuration": CONFIG,
                  "limitations": ["Synthetic captures, interleaved at original timestamps; not independent real-attack validation.",
                                  "Offline ingestion rate includes inference and JSON persistence but is not NIC capture throughput.",
                                  "Class presence is a concurrency check, not precision or recall."]}
        store.close()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in report.items() if k not in {"buckets", "memory_bytes"}}, indent=2))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "bench/live-readiness-20260908.json")
    parser.add_argument("--target-pps", type=float, default=1000)
    args = parser.parse_args()
    run(args.output, args.target_pps)
