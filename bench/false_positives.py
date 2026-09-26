"""Replay fresh benign metadata challenges and the bundled benign PCAP offline."""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path
import platform
import time

from bench.traffic_cases import CASES
from engine.pipeline import Engine
from engine.sources.pcap_source import PcapSource


def assess(name, packets, config):
    engine = Engine(config)
    hits, first, last, tick = [], None, None, 0
    started = time.perf_counter()
    for packet in packets:
        first = packet.ts_ns if first is None else first
        last = packet.ts_ns
        hits.extend(engine.feed(packet))
        if last - tick >= 10**9:
            hits.extend(engine.tick(last))
            tick = last
    if last is not None:
        hits.extend(engine.tick(last + 10**9))
    engine.sweep()
    seconds = (last - first) / 1e9 if first is not None else 0
    return {"case": name, "packets": engine.packets, "capture_seconds": seconds,
            "wall_seconds": round(time.perf_counter() - started, 3),
            "false_alerts": len(hits), "by_class": dict(Counter(h.threat_class for h in hits)),
            "by_source": dict(Counter(h.source for h in hits)),
            "alerts": [{"class": h.threat_class, "subtype": h.subtype, "source": h.source,
                        "confidence": h.confidence, "summary": h.summary} for h in hits[:50]]}


def run(model_dir=None):
    arms = {"rules": {"model_enabled": False, "anomaly_enabled": False},
            "serving": {}}
    if model_dir:
        arms["candidate"] = {"model_dir": str(Path(model_dir).resolve())}
    output = {}
    for arm, config in arms.items():
        rows = []
        for seed in (20260908, 20260909, 20260910):
            for name, make in CASES.items():
                rows.append(assess(f"{name}/seed-{seed}", make(seed), config))
        rows.append(assess("bundled-benign", PcapSource("data/scenarios/benign.pcap"), config))
        total = sum(r["false_alerts"] for r in rows)
        seconds = sum(r["capture_seconds"] for r in rows)
        output[arm] = {"cases": rows, "packets": sum(r["packets"] for r in rows),
                       "false_alerts": total, "capture_seconds": seconds,
                       "false_alerts_per_capture_hour": total * 3600 / max(seconds, 1e-9)}
        print(f"{arm}: {total} false alerts in {len(rows)} benign cases", flush=True)
    return {"environment": platform.platform(), "arms": output,
            "scope": "Offline synthetic metadata challenges plus the bundled synthetic benign PCAP. "
                     "Challenge cases were not used for fitting, selection or calibration. Seeds diversify "
                     "some cases; deterministic cases repeat. These are not independent real-world trials."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir")
    parser.add_argument("--json", required=True)
    args = parser.parse_args()
    Path(args.json).write_text(json.dumps(run(args.model_dir), indent=2, allow_nan=False) + "\n")
