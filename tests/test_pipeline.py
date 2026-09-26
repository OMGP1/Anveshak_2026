from __future__ import annotations

import ast
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engine.alerts.schema import build_alert, validate_alert
from engine.features.registry import FEATURES_BY_NAME
from engine.models.gate import PromotionGate
from engine.models.tier1 import MODEL_DIR, MODEL_FEATURES, Tier1Model
from engine.pipeline import DEFAULT_CONFIG, Engine, run_source
from engine.sources.pcap_source import PcapSource
from engine.types import PacketMeta
from training.scenarios import abspath, get, load_labels

OUTBOUND = {"socket", "requests", "httpx", "urllib", "urllib3", "http", "aiohttp", "ftplib",
            "smtplib", "telnetlib"}

CLASS_SCENARIOS = [
    ("syn_flood", "volumetric-ddos"),
    ("udp_reflection", "volumetric-ddos"),
    ("slowloris", "volumetric-ddos"),
    ("dga_burst", "dga-dns-tunnelling"),
    ("dns_tunnel", "dga-dns-tunnelling"),
    ("ja4_spoof", "encrypted-malware"),
    ("port_scan", "recon-scanning"),
    ("exfil_drip", "data-exfiltration"),
    ("exfil_bulk", "data-exfiltration"),
]


def replay(scenario: str, config: dict | None = None):
    return run_source(PcapSource(abspath(get(scenario)["file"])), config)


def sample_values() -> dict[str, float]:
    return {
        "duration": 12.5,
        "pkts_fwd": 40.0,
        "pkts_rev": 2.0,
        "bytes_fwd": 48000.0,
        "bytes_rev": 900.0,
        "completeness_flag": 1.0,
        "orientation_confidence": 1.0,
        "out_in_byte_ratio": 53.3,
        "syn_synack_ratio_1s": 1.0,
        "src_entropy_1s": 0.2,
    }


class FakeScore:
    def __init__(self, confidence: float, probs: dict[str, float] | None = None) -> None:
        self.confidence = confidence
        self.top_class = "benign"
        self.probs = probs or {}


def test_the_benign_scenario_produces_no_alert_at_all():
    engine, alerts = replay("benign")
    assert engine.packets == 8150
    assert alerts == [], [(a.threat_class, a.subtype, a.source) for a in alerts]


@pytest.mark.parametrize("scenario,threat_class", CLASS_SCENARIOS)
def test_each_attack_scenario_raises_its_class_inside_the_labelled_window(scenario, threat_class):
    labels = load_labels(scenario)
    windows = [(a["start_ts"], a["end_ts"]) for a in labels["attacks"]
               if a["threat_class"] == threat_class]
    assert windows
    every = [(a["start_ts"], a["end_ts"]) for a in labels["attacks"]]
    engine, alerts = replay(scenario)
    hits = [a for a in alerts if a.threat_class == threat_class]
    assert hits, "no %s detection in %s" % (threat_class, scenario)
    for alert in hits:
        seconds = alert.ts_ns / 1e9
        assert any(start <= seconds <= end for start, end in windows), \
            "%s alert at %.1f falls outside every labelled window" % (scenario, seconds)
    for alert in alerts:
        seconds = alert.ts_ns / 1e9
        assert any(start <= seconds <= end for start, end in every), \
            "%s raised %s at %.1f outside every window" % (scenario, alert.threat_class, seconds)


def test_memory_stays_bounded_when_the_same_capture_is_replayed_again_and_again():
    engine = Engine({
        "flow_capacity": 4000,
        "model_enabled": False,
        "anomaly_enabled": False,
        "context": {"beacon_capacity": 128, "beacon_ttl_s": 300.0, "scan_hll_capacity": 1024,
                    "dns_hll_capacity": 1024, "dst_hot_capacity": 32},
    })
    source = list(PcapSource(abspath(get("port_scan")["file"])))
    span = source[-1].ts_ns - source[0].ts_ns + 1_000_000_000
    sizes = []
    live = []
    for pass_index in range(5):
        shift = pass_index * span
        for meta in source:
            engine.feed(PacketMeta(
                ts_ns=meta.ts_ns + shift, proto=meta.proto, src_ip=meta.src_ip,
                dst_ip=meta.dst_ip, src_port=meta.src_port, dst_port=meta.dst_port,
                length=meta.length, tcp_flags=meta.tcp_flags, ttl=meta.ttl,
                tcp_window=meta.tcp_window, tcp_mss=meta.tcp_mss, tcp_opts=meta.tcp_opts,
                packets=meta.packets, from_flow_record=meta.from_flow_record,
                tls=meta.tls, dns=meta.dns))
        engine.tick(source[-1].ts_ns + shift)
        sizes.append(engine.memory_bytes())
        live.append((len(engine.flows), len(engine.ctx.beacons)))
    caps = engine.memory_caps_bytes()
    for name in ("flow_table", "beacon_table", "sketches"):
        assert sizes[-1][name] <= caps[name], (name, sizes[-1][name], caps[name])
        growth = sizes[-1][name] - sizes[-2][name]
        assert growth <= 0.10 * sizes[0][name], (name, growth, sizes[0][name])
    assert live[-1] == live[-2], live
    assert live[-1][0] <= engine.flows.capacity
    assert live[-1][1] <= engine.ctx.beacons.capacity
    assert engine.packets == 5 * len(source)
    assert engine.flows.created > 5000


def test_the_trained_model_loads_and_scores_a_feature_vector():
    model = Tier1Model.load(MODEL_DIR)
    assert model is not None, "run training/train_tier1.py"
    assert model.feature_names == MODEL_FEATURES, "the trained model and the registry have drifted apart"
    assert len(model.feature_names) >= 90
    assert set(model.classes) <= set(FEATURES_BY_NAME) | set(model.classes)
    score = model.score(sample_values())
    assert score.top_class in model.classes
    assert abs(sum(score.probs.values()) - 1.0) < 1e-6
    assert 0.0 <= score.confidence <= 1.0
    explained = model.score(sample_values(), explain=True)
    assert explained.top_class == score.top_class
    assert abs(explained.confidence - score.confidence) < 1e-9
    assert explained.contributions
    for name, _, weight in explained.contributions:
        assert name in FEATURES_BY_NAME
        assert weight != 0.0


def test_the_calibration_export_reproduces_what_sklearn_fitted():
    with open(os.path.join(MODEL_DIR, "tier1_calibration.json"), "r", encoding="ascii") as fh:
        blob = json.load(fh)
    assert blob["method"] == "isotonic"
    assert blob["reproduction_max_gap"] <= 1e-6
    assert set(blob["classes"]) == set(Tier1Model.load(MODEL_DIR).classes)


def test_the_gate_promotes_the_uncertain_band_and_the_encrypted_candidates():
    gate = PromotionGate({"uncertain_low": 0.3, "uncertain_high": 0.8, "qa_sample_rate": 0.0})
    assert gate.decide(FakeScore(0.5), {}).reason == "uncertain-band"
    assert not gate.decide(FakeScore(0.95), {}).promote
    assert not gate.decide(FakeScore(0.1), {}).promote
    assert gate.decide(FakeScore(0.95), {"fingerprint_consistency_score": 0.05}).reason \
        == "encrypted-candidate"
    high = FakeScore(0.95, {"encrypted-malware": 0.4})
    assert gate.decide(high, {"fingerprint_consistency_score": 1.0}).reason == "encrypted-candidate"
    quiet = PromotionGate({"uncertain_low": 0.3, "uncertain_high": 0.8, "qa_sample_rate": 0.0})
    assert not quiet.decide(FakeScore(0.95), {"fingerprint_consistency_score": 1.0}).promote
    sampler = PromotionGate({"uncertain_low": 0.0, "uncertain_high": 0.0, "qa_sample_rate": 1.0})
    assert sampler.decide(FakeScore(0.99), {}).reason == "qa-sample"
    assert gate.lineage()["gate_uncertain_low"] == 0.3
    assert set(gate.stats()) == {"considered", "promoted", "by_reason", "config"}


def test_gate_thresholds_come_from_configuration_and_are_reported_as_lineage():
    engine = Engine({"gate": {"uncertain_low": 0.2}, "model_enabled": False,
                     "anomaly_enabled": False})
    lineage = engine.lineage()
    assert lineage["gate_uncertain_low"] == 0.2
    assert lineage["gate_qa_sample_rate"] == PromotionGate().qa_rate
    for key in ("model_id", "model_hash", "dataset_version"):
        assert key in lineage


def test_stats_reports_timing_and_the_measured_size_of_every_bounded_structure():
    engine, _ = replay("port_scan")
    stats = engine.stats()
    assert stats["engine"] == "engine.pipeline"
    assert stats["packets"] == 10194
    assert set(stats["memory_bytes"]) == {"flow_table", "beacon_table", "sketches", "models"}
    assert set(stats["memory_caps_bytes"]) == set(stats["memory_bytes"])
    for name in ("flow_table", "beacon_table", "sketches"):
        assert 0 <= stats["memory_bytes"][name] <= stats["memory_caps_bytes"][name]
    assert stats["memory_bytes"]["flow_table"] > 0
    timing = stats["stage_timing_us"]
    assert set(timing) == {"flow_table", "detect", "features", "tier1", "alert"}
    assert timing["flow_table"] > 0 and timing["detect"] > 0
    assert stats["coverage_counts"]["flows"] > 0
    assert stats["gate"]["considered"] > 0


def test_every_flow_the_table_drops_is_still_counted_in_coverage():
    engine = Engine({"flow_capacity": 64, "model_enabled": False, "anomaly_enabled": False})
    base = 1_700_000_000_000_000_000
    for i in range(500):
        engine.feed(PacketMeta(ts_ns=base + i * 1_000_000, proto=6, src_ip=0x0A000001,
                               dst_ip=0x0A000100 + i, src_port=40000 + i, dst_port=443,
                               length=100, tcp_flags=0x02))
    engine.sweep()
    stats = engine.stats()
    assert stats["flows_created"] == 500
    assert stats["flows_evicted"] == 500 - stats["flow_table_entries"]
    assert stats["coverage_counts"]["evicted"] == stats["flows_evicted"]
    assert stats["coverage_counts"]["flows"] == stats["flows_created"]


def test_stage_timings_are_reported_per_call_and_per_packet():
    engine, _ = replay("udp_reflection")
    stats = engine.stats()
    per_call = stats["stage_timing_us"]
    per_packet = stats["stage_timing_per_packet_us"]
    calls = stats["stage_calls"]
    assert set(per_packet) == set(per_call) == set(calls)
    assert calls["detect"] > calls["tier1"] > 0
    assert per_packet["tier1"] < per_call["tier1"]
    assert per_packet["flow_table"] == pytest.approx(per_call["flow_table"], rel=0.05)
    assert "must not be added" in stats["stage_timing_note"]


def test_alerts_from_the_engine_validate_against_the_standard_schema():
    engine, alerts = replay("ja4_spoof")
    assert alerts
    for detection in alerts:
        lineage = engine.lineage_for(detection)
        lineage["latency_ns"] = 1_000_000
        alert = build_alert(detection, lineage)
        validate_alert(alert)
        assert alert["x_supporting_evidence"]
        assert alert["x_confidence_calibrated"] is (detection.source != "rule")


def test_the_model_layer_marks_its_own_evidence_as_treeshap():
    _, alerts = replay("port_scan")
    scored = [a for a in alerts if a.source in ("model", "ensemble")]
    assert scored
    for detection in scored:
        assert detection.context["calibrated"] is True
        assert "treeshap" in detection.context["evidence_basis"]
        for item in detection.evidence:
            assert item.feature in FEATURES_BY_NAME


def test_the_engine_is_usable_as_a_plain_library_with_no_api_and_no_dashboard():
    engine = Engine()
    found = []
    for meta in PcapSource(abspath(get("exfil_drip")["file"])):
        found.extend(engine.feed(meta))
    found.extend(engine.tick(engine.ctx.now_ns + 1_000_000_000))
    assert any(d.threat_class == "data-exfiltration" for d in found)
    assert engine.stats()["packets"] == 6569


def test_the_model_layer_opens_no_outbound_socket():
    root = os.path.join(ROOT, "engine")
    offenders = []
    for base, _, files in os.walk(root):
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(base, name)
            with open(path, "r", encoding="ascii") as fh:
                tree = ast.parse(fh.read(), path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots = {alias.name.split(".")[0] for alias in node.names}
                elif isinstance(node, ast.ImportFrom):
                    roots = {(node.module or "").split(".")[0]}
                else:
                    continue
                if roots & OUTBOUND:
                    offenders.append((path, sorted(roots & OUTBOUND)))
    assert offenders == []


def test_default_configuration_carries_every_threshold_the_model_layer_uses():
    for key in ("model_alert_confidence", "model_alert_cooldown_s", "model_alert_max_per_class",
                "anomaly_alert_score", "ensemble_min_confidence", "gate"):
        assert key in DEFAULT_CONFIG
