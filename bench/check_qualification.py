"""Evaluate the declared local performance policy without changing its thresholds."""
from __future__ import annotations

import json
import argparse
from pathlib import Path


def check(report: dict, policy: dict) -> dict:
    checks = {
        "duration": report["elapsed_s"] >= policy["minimum_duration_s"],
        "sustained_rate": report["sustained"]["packets_per_s"]["min"] >= policy["minimum_post_warmup_bucket_packets_per_s"],
        "latency_p99": report["latency_samples"] > 0 and report["latency_ms"]["p99"] <= policy["maximum_ingest_to_synced_alert_p99_ms"],
        "python_memory": report["peak_rss_mb"] <= policy["maximum_python_peak_rss_mb"],
        "native_source": report["config"]["source"] == policy["required_source"],
        "durable_ledger": report["config"]["ledger"] != "off",
        "models_enabled": report["config"]["engine_config"].get("model_enabled") is True
            and report["config"]["engine_config"].get("anomaly_enabled") is True,
    }
    return {"scope": policy["scope"], "passed": all(checks.values()), "checks": checks,
            "failed_checks": [name for name, passed in checks.items() if not passed],
            "production_certified": False}


if __name__ == "__main__":
    folder = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=folder / "qualification-rust.json")
    parser.add_argument("--output", type=Path, default=folder / "qualification-result.json")
    args = parser.parse_args()
    result = check(json.loads(args.report.read_text()),
                   json.loads((folder / "qualification-policy.json").read_text()))
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)
