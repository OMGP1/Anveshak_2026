from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from engine.alerts.ledger import Ledger, canonical_json, chain_hash
from engine.alerts.schema import (
    AlertSchemaError,
    GENESIS_HASH,
    REQUIRED_PS_FIELDS,
    build_alert,
    validate_alert,
)
from engine.alerts.verify import verify_chain
from engine.explain import explain, headline, top_evidence
from engine.metrics import STAGES, LatencyHistogram, Meter
from engine.types import ATTACK_TECHNIQUE, Detection, Evidence

ROOT = Path(__file__).resolve().parents[1]
LINEAGE = {
    "model_id": "tier1-lgbm-v1.2.0",
    "model_hash": "sha256:" + "ab" * 32,
    "dataset_version": "2026-09-01-synthetic-v3",
    "calibrated": True,
}
BASE_TS = 1788775472_501000000


def syn_flood_detection(ts_ns: int = BASE_TS) -> Detection:
    return Detection(
        ts_ns=ts_ns,
        threat_class="volumetric-ddos",
        subtype="syn-flood",
        confidence=0.87,
        severity="HIGH",
        source="rule.ddos",
        flow={
            "proto": 6,
            "src_ip": None,
            "src_attribution": "spoofed",
            "dst_ip": 169083409,
            "src_port": 0,
            "dst_port": 443,
            "directionality": "FWD_ONLY",
            "completeness_flag": False,
            "window_start_ns": ts_ns - 1_000_000_000,
            "window_end_ns": ts_ns,
        },
        evidence=[
            Evidence("syn_synack_ratio_1s", 41.2, 0.34),
            Evidence("src_entropy_1s", 0.97, 0.21),
            Evidence("src_cardinality_per_dst", 3100.0, 0.16),
            Evidence("completeness_flag", 0.0, 0.09),
            Evidence("mean_bytes_per_flow", 64.0, 0.04),
            Evidence("duration", 0.4, 0.001),
        ],
        summary="",
        context={"latency_ns": 4_200_000, "shedding_tier": "none"},
    )


def beacon_detection(ts_ns: int = BASE_TS) -> Detection:
    return Detection(
        ts_ns=ts_ns,
        threat_class="c2-beaconing",
        subtype="jittered",
        confidence=0.72,
        severity="MEDIUM",
        source="detector.beacon",
        flow={"proto": 6, "src_ip": 169083905, "dst_ip": 3232235777, "src_port": 51514, "dst_port": 443,
              "directionality": "BIDIRECTIONAL", "completeness_flag": True},
        evidence=[
            Evidence("ls_fap", 8e-6, 0.41),
            Evidence("ls_peak_period_s", 45.0, 0.33),
            Evidence("iat_cv", 0.17, 0.19),
            Evidence("dst_stability", 0.98, 0.05),
        ],
        summary="",
        context={},
    )


def alert_stream(count: int) -> list[dict]:
    alerts = []
    for i in range(count):
        detection = syn_flood_detection(BASE_TS + i * 1_000_000_000)
        detection.confidence = 0.5 + (i % 40) / 100.0
        alerts.append(build_alert(detection, LINEAGE))
    return alerts


def test_built_alert_carries_the_five_required_fields() -> None:
    alert = build_alert(syn_flood_detection(), LINEAGE)
    for field in REQUIRED_PS_FIELDS:
        assert field in alert
    assert alert["created"] == "2026-09-07T10:04:32.501Z"
    assert alert["x_flow_identifier"]["dst_ip"] == "10.20.2.17"
    assert alert["x_flow_identifier"]["dst_port"] == 443
    assert alert["x_threat_class"] == "volumetric-ddos"
    assert alert["confidence"] == 87
    assert alert["x_supporting_evidence"][0]["feature"] == "syn_synack_ratio_1s"


def test_built_alert_validates_against_stix() -> None:
    alert = build_alert(syn_flood_detection(), LINEAGE)
    validate_alert(alert)
    assert alert["type"] == "indicator"
    assert alert["spec_version"] == "2.1"
    assert alert["pattern_type"] == "stix"
    assert alert["id"].startswith("indicator--")
    assert alert["x_severity"] == "HIGH"
    assert alert["x_confidence_calibrated"] is True
    assert alert["x_prev_hash"] == GENESIS_HASH
    assert alert["x_latency_ms"] == pytest.approx(4.2)


def test_alert_id_is_stable_for_the_same_detection() -> None:
    first = build_alert(syn_flood_detection(), LINEAGE)
    second = build_alert(syn_flood_detection(), LINEAGE)
    assert first["id"] == second["id"]
    later = build_alert(syn_flood_detection(BASE_TS + 1), LINEAGE)
    assert later["id"] != first["id"]


def test_alert_missing_a_required_field_raises() -> None:
    for field in ("confidence", "x_flow_identifier", "x_threat_class", "x_supporting_evidence",
                  "x_model_lineage", "x_prev_hash", "pattern", "created"):
        alert = build_alert(syn_flood_detection(), LINEAGE)
        alert.pop(field)
        with pytest.raises(AlertSchemaError):
            validate_alert(alert)


def test_alert_with_a_bad_value_raises() -> None:
    cases = [
        ("x_threat_class", "not-a-class"),
        ("x_severity", "SEVERE"),
        ("confidence", 150),
        ("confidence", "high"),
        ("x_prev_hash", "deadbeef"),
        ("x_supporting_evidence", []),
        ("type", "observed-data"),
    ]
    for field, value in cases:
        alert = build_alert(syn_flood_detection(), LINEAGE)
        alert[field] = value
        with pytest.raises(AlertSchemaError):
            validate_alert(alert)


def test_flow_identifier_missing_a_key_raises() -> None:
    alert = build_alert(syn_flood_detection(), LINEAGE)
    alert["x_flow_identifier"].pop("window_start")
    with pytest.raises(AlertSchemaError):
        validate_alert(alert)


def test_evidence_is_ranked_by_contribution_and_capped_at_five() -> None:
    alert = build_alert(syn_flood_detection(), LINEAGE)
    rows = alert["x_supporting_evidence"]
    assert len(rows) == 5
    weights = [abs(row["shap"]) for row in rows]
    assert weights == sorted(weights, reverse=True)
    assert "duration" not in [row["feature"] for row in rows]


def test_negative_contributions_rank_by_magnitude() -> None:
    detection = beacon_detection()
    detection.evidence.append(Evidence("iat_mean", 45.0, -0.9))
    assert top_evidence(detection.evidence)[0].feature == "iat_mean"


def test_mitre_technique_matches_the_threat_class() -> None:
    for threat_class, (technique, name) in ATTACK_TECHNIQUE.items():
        detection = syn_flood_detection()
        detection.threat_class = threat_class
        detection.subtype = ""
        alert = build_alert(detection, LINEAGE)
        validate_alert(alert)
        ref = alert["external_references"][0]
        assert ref["source_name"] == "mitre-attack"
        assert ref["external_id"] == technique
        assert ref["description"] == name


def test_syn_flood_sentence_reads_like_a_sentence() -> None:
    text = explain(syn_flood_detection())
    assert text.startswith("Suspected spoofed-source SYN flood against 10.20.2.17:443:")
    assert "41.2 SYNs for every SYN-ACK in the last second" in text
    assert " and " in text
    assert text.endswith(".")
    assert "_" not in text
    assert text.isascii()


def test_beacon_sentence_names_the_period_and_the_fap() -> None:
    text = explain(beacon_detection())
    assert headline(beacon_detection()).startswith("Suspected jittered C2 beaconing")
    assert "false-alarm probability 8.0e-06" in text
    assert "a repeating 45 second period" in text


def test_degraded_context_is_stated_in_the_sentence() -> None:
    detection = syn_flood_detection()
    detection.context = {"shedding_tier": "2", "sampling_active": True, "sampling_ratio": 0.25}
    text = explain(detection)
    assert "shedding at tier 2" in text
    assert "sampling was active at 0.25" in text


def test_unknown_feature_falls_back_to_readable_words() -> None:
    detection = beacon_detection()
    detection.evidence = [Evidence("some_new_feature", 3.5, 1.0)]
    assert "some new feature at 3.5" in explain(detection)


def test_chain_hash_matches_a_hand_computation() -> None:
    record = {"b": 2, "a": 1}
    expected = hashlib.sha256(b'{"a":1,"b":2}' + GENESIS_HASH.encode("ascii")).hexdigest()
    assert chain_hash(record, GENESIS_HASH) == "sha256:" + expected


def test_canonical_json_sorts_keys_and_drops_whitespace() -> None:
    assert canonical_json({"b": 1, "a": [1, {"d": 4, "c": 3}]}) == b'{"a":[1,{"c":3,"d":4}],"b":1}'
    with pytest.raises(ValueError):
        canonical_json({"a": float("nan")})


def test_canonical_json_is_stable_across_process_runs(tmp_path: Path) -> None:
    alert = build_alert(syn_flood_detection(), LINEAGE)
    payload = tmp_path / "alert.json"
    payload.write_text(json.dumps(alert), encoding="utf-8")
    inline = hashlib.sha256(canonical_json(alert)).hexdigest()
    code = ("import hashlib,json,sys;from engine.alerts.ledger import canonical_json;"
            "print(hashlib.sha256(canonical_json(json.load(open(sys.argv[1],encoding='utf-8')))).hexdigest())")
    digests = set()
    for seed in ("0", "1", "12345"):
        env = dict(os.environ, PYTHONHASHSEED=seed, PYTHONPATH=str(ROOT))
        out = subprocess.run([sys.executable, "-c", code, str(payload)], cwd=str(ROOT), env=env,
                             capture_output=True, text=True, check=True)
        digests.add(out.stdout.strip())
    assert digests == {inline}


def test_ledger_chain_verifies_clean_over_250_records_with_two_anchors(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    ledger = Ledger(str(path))
    for alert in alert_stream(250):
        ledger.append(alert)
    ledger.close()
    assert ledger.records == 250
    assert ledger.anchors == 2
    result = verify_chain(str(path))
    assert result["ok"] is True
    assert result["records"] == 250
    assert result["broken_at"] is None
    assert result["anchors_ok"] is True
    assert [a["count"] for a in result["anchors"]] == [100, 200]
    assert all(a["signature_ok"] and a["head_ok"] for a in result["anchors"])
    assert result["head"] == ledger.head
    assert result["key_source"] == "sidecar"


def test_each_record_carries_the_previous_hash(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    ledger = Ledger(str(path))
    lines = [ledger.append(alert) for alert in alert_stream(3)]
    ledger.close()
    assert lines[0]["prev_hash"] == GENESIS_HASH
    assert lines[0]["record"]["x_prev_hash"] == GENESIS_HASH
    assert lines[1]["prev_hash"] == lines[0]["hash"]
    assert lines[2]["record"]["x_prev_hash"] == lines[1]["hash"]


def test_ledger_rejects_a_non_conformant_alert(tmp_path: Path) -> None:
    ledger = Ledger(str(tmp_path / "alerts.jsonl"))
    alert = build_alert(syn_flood_detection(), LINEAGE)
    alert.pop("x_supporting_evidence")
    with pytest.raises(AlertSchemaError):
        ledger.append(alert)
    ledger.close()


def tamper_one_byte(path: Path, index: int) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    assert '"x_detector":"rule.ddos"' in lines[index]
    lines[index] = lines[index].replace('"x_detector":"rule.ddos"', '"x_detector":"rule.ddoS"', 1)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def test_tampering_one_byte_in_record_eight_breaks_at_record_eight(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    ledger = Ledger(str(path))
    for alert in alert_stream(250):
        ledger.append(alert)
    ledger.close()
    before = path.read_text(encoding="utf-8")
    tamper_one_byte(path, 7)
    after = path.read_text(encoding="utf-8")
    assert sum(1 for a, b in zip(before, after) if a != b) == 1
    result = verify_chain(str(path))
    assert result["ok"] is False
    assert result["broken_at"] == 8, "line 8 of the file is record 8, counted from 1"
    assert result["records"] == 7
    assert result["reason"] == "record content does not match its hash"
    assert result["anchors_ok"] is False


def test_deleting_a_record_is_caught(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    ledger = Ledger(str(path), anchor_every=0)
    for alert in alert_stream(20):
        ledger.append(alert)
    ledger.close()
    lines = path.read_text(encoding="utf-8").splitlines()
    del lines[5]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = verify_chain(str(path))
    assert result["broken_at"] == 6
    assert result["reason"] == "prev_hash does not match the previous line"


def test_a_forged_anchor_signature_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    ledger = Ledger(str(path), anchor_every=10)
    for alert in alert_stream(10):
        ledger.append(alert)
    ledger.close()
    anchors = Path(ledger.anchors_path)
    anchor = json.loads(anchors.read_text(encoding="utf-8").strip())
    anchor["sig"] = ("00" * 64)
    anchors.write_text(json.dumps(anchor, separators=(",", ":")) + "\n", encoding="utf-8")
    result = verify_chain(str(path))
    assert result["ok"] is True
    assert result["anchors_ok"] is False
    assert result["anchors"][0]["signature_ok"] is False


def test_verify_cli_prints_pass_then_names_the_broken_record(tmp_path: Path) -> None:
    path = tmp_path / "alerts.jsonl"
    ledger = Ledger(str(path))
    for alert in alert_stream(120):
        ledger.append(alert)
    ledger.close()
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    clean = subprocess.run([sys.executable, "-m", "engine.alerts.verify", str(path)],
                           cwd=str(ROOT), env=env, capture_output=True, text=True)
    assert clean.returncode == 0
    assert clean.stdout.startswith("PASS")
    assert "120 records" in clean.stdout
    tamper_one_byte(path, 7)
    broken = subprocess.run([sys.executable, "-m", "engine.alerts.verify", str(path)],
                            cwd=str(ROOT), env=env, capture_output=True, text=True)
    assert broken.returncode == 1
    assert "FAIL" in broken.stdout
    assert "chain breaks at record 8 of 120" in broken.stdout


def test_verify_reports_a_missing_ledger() -> None:
    result = verify_chain(str(ROOT / "does-not-exist.jsonl"))
    assert result["ok"] is False
    assert result["records"] == 0


def test_meter_percentiles_for_a_known_sample() -> None:
    meter = Meter()
    for i in range(1, 1001):
        meter.observe_alert(i * 1_000_000)
    snapshot = meter.snapshot()
    assert snapshot["alerts"] == 1000
    assert snapshot["latency_ms"]["p50"] == pytest.approx(500.0, rel=0.03)
    assert snapshot["latency_ms"]["p95"] == pytest.approx(950.0, rel=0.03)
    assert snapshot["latency_ms"]["p99"] == pytest.approx(990.0, rel=0.03)
    assert snapshot["latency_ms"]["p999"] == pytest.approx(999.0, rel=0.03)
    assert snapshot["latency_mean_ms"] == pytest.approx(500.5, rel=0.001)
    assert snapshot["latency_max_ms"] == pytest.approx(1000.0)


def test_histogram_stays_bounded_and_monotonic() -> None:
    hist = LatencyHistogram()
    size = hist.nbytes
    for i in range(200_000):
        hist.add((i % 5000) * 1e5)
    assert hist.nbytes == size
    quantiles = [hist.quantile(q) for q in (0.5, 0.95, 0.99, 0.999)]
    assert quantiles == sorted(quantiles)


def test_latency_is_computed_from_the_packet_timestamp() -> None:
    meter = Meter()
    wire_ts = 1_788_775_472_000_000_000
    meter.anchor_replay(wire_ts, speed=1.0, mono_ns=0)
    fresh = meter.observe_alert_for(wire_ts + 2_000_000, now_mono_ns=50_000_000)
    stale = meter.observe_alert_for(wire_ts + 1_000_000, now_mono_ns=50_000_000)
    assert fresh == 48_000_000
    assert stale == 49_000_000
    assert stale - fresh == 1_000_000
    meter.anchor_replay(wire_ts, speed=10.0, mono_ns=0)
    assert meter.latency_for(wire_ts + 2_000_000, now_mono_ns=50_000_000) == 49_800_000


def test_latency_is_zero_before_the_first_packet_is_marked() -> None:
    assert Meter().latency_for(BASE_TS) == 0


def test_meter_reports_throughput_and_tracked_memory() -> None:
    class Bounded:
        nbytes = 4096
        capacity_bytes = 8192

    meter = Meter()
    meter.track("flow_table", Bounded())
    for _ in range(1000):
        meter.observe_packet(1000)
    meter.observe_flow()
    snapshot = meter.snapshot()
    for key in ("uptime_s", "packets_per_s", "flows_per_s", "mbps", "rss_mb", "latency_ms",
                "stage_timing_us", "memory_bytes", "memory_caps_bytes"):
        assert key in snapshot
    assert snapshot["packets"] == 1000
    assert snapshot["flows"] == 1
    assert snapshot["packets_per_s"] > 0
    assert snapshot["mbps"] > 0
    assert snapshot["rss_mb"] > 0
    assert snapshot["memory_bytes"]["flow_table"] == 4096
    assert snapshot["memory_caps_bytes"]["flow_table"] == 8192


def test_stage_timing_is_reported_per_stage() -> None:
    meter = Meter()
    meter.observe_stage("decode", 2000)
    meter.observe_stage("decode", 4000)
    meter.observe_stage("alert", 9000)
    for _ in range(6):
        meter.observe_packet(100)
    snapshot = meter.snapshot()
    timing = snapshot["stage_timing_us"]
    assert timing["decode"] == pytest.approx(3.0)
    assert timing["alert"] == pytest.approx(9.0)
    assert timing["tier1"] == 0.0
    assert set(timing) == set(STAGES)
    per_packet = snapshot["stage_timing_per_packet_us"]
    assert per_packet["decode"] == pytest.approx(1.0)
    assert per_packet["alert"] == pytest.approx(1.5)
    assert snapshot["stage_calls"]["decode"] == 2
