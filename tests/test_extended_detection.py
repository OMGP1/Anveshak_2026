"""Offline metadata fixtures, not executions of an attack generator."""
from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from api.replay import FrameQueue, ReplayController
from api.store import AlertStore
from engine.alerts.schema import build_alert, validate_alert
from engine.detect.base import Context
from engine.detect.coverage import AMPLIFICATION_PORTS, method_coverage
from engine.detect.ddos import DdosDetector
from engine.detect.protocol_flood import ProtocolFloodMonitor
from engine.pipeline import Engine
from engine.sources.pcap_source import PcapSource
from engine.state.flow_table import FlowTable
from engine.types import ACK, ICMP, SYN, TCP, UDP, PacketMeta
from training.inventory import ROOT

NS = 10**9
CONFIG = {"enabled": True, "minimum_pps": 100, "warmup_windows": 3}


def packets(second, count, protocol=UDP, flags=0, destination=2, port=53):
    return [PacketMeta(second * NS + index * 1000, protocol, 1, destination,
                       port, 443, 64, tcp_flags=flags) for index in range(count)]


def warm(monitor, protocol=UDP, flags=0):
    for second in range(3):
        for packet in packets(second, 10, protocol, flags):
            assert monitor.observe_packet(packet) == []
        assert monitor.tick((second + 1) * NS) == []


@pytest.mark.parametrize("protocol", [TCP, UDP, ICMP])
def test_final_window_emits_once_on_tick(protocol):
    monitor = ProtocolFloodMonitor(CONFIG)
    warm(monitor, protocol)
    for packet in packets(3, 300, protocol):
        assert monitor.observe_packet(packet) == []
    assert monitor.tick(4 * NS - 1) == []
    hit, = monitor.tick(4 * NS)
    assert hit.flow["window_start"] == 3
    assert hit.flow["window_end"] == 4
    assert {item.feature: item.value for item in hit.evidence}["pps_to_dst"] == 300
    assert monitor.tick(100 * NS) == []


def test_quiet_gap_does_not_dilute_completed_one_second_burst():
    monitor = ProtocolFloodMonitor(CONFIG)
    warm(monitor)
    for packet in packets(3, 300):
        monitor.observe_packet(packet)
    hit, = monitor.observe_packet(packets(1000, 1)[0])
    assert {item.feature: item.value for item in hit.evidence}["pps_to_dst"] == 300
    assert hit.flow["window_end"] - hit.flow["window_start"] == 1
    assert monitor.buckets.peek((UDP, 2)).observations == 4


@pytest.mark.parametrize("protocol", [TCP, UDP, ICMP])
def test_absolute_limit_works_without_warmup_at_epoch_zero(protocol):
    monitor = ProtocolFloodMonitor({**CONFIG, "absolute_pps": 200})
    for packet in packets(0, 300, protocol):
        monitor.observe_packet(packet)
    hit, = monitor.tick(NS)
    assert hit.context["trigger_basis"] == "absolute-limit"
    assert hit.context["baseline_windows"] == 0
    assert "not proof" in hit.summary
    alert = build_alert(hit, {"model_id": "rules", "model_hash": "none", "dataset_version": "test"})
    validate_alert(alert)
    assert alert["x_flow_identifier"]["window_start"] == "1970-01-01T00:00:00.000Z"
    assert alert["x_flow_identifier"]["window_end"] == "1970-01-01T00:00:01.000Z"
    for packet in packets(1, 300, protocol):
        monitor.observe_packet(packet)
    assert monitor.tick(2 * NS) == []  # cooldown also covers the absolute branch


def test_syn_attempts_detect_churn_below_packet_rate_floor_without_claiming_connections():
    monitor = ProtocolFloodMonitor({**CONFIG, "minimum_pps": 1000, "minimum_syn_pps": 100})
    warm(monitor, TCP, SYN)
    for packet in packets(3, 300, TCP, SYN):
        monitor.observe_packet(packet)
    hit, = monitor.tick(4 * NS)
    assert hit.subtype == "tcp-syn-rate-anomaly"
    assert "SYN attempts" in hit.summary
    assert "completed connections" in hit.context["limitation"]
    assert {item.feature: item.value for item in hit.evidence}["syn_attempts_per_second"] == 300


def test_syn_ack_is_not_a_connection_attempt():
    monitor = ProtocolFloodMonitor({**CONFIG, "minimum_pps": 1000,
                                    "minimum_syn_pps": 100, "absolute_syn_pps": 200})
    for packet in packets(0, 300, TCP, SYN | ACK):
        monitor.observe_packet(packet)
    assert monitor.tick(NS) == []


def test_late_packets_cannot_reopen_closed_windows_or_pollute_new_bucket():
    monitor = ProtocolFloodMonitor({**CONFIG, "absolute_pps": 200})
    monitor.observe_packet(packets(3, 1)[0])
    monitor.tick(4 * NS)
    for packet in packets(3, 300):
        assert monitor.observe_packet(packet) == []
    monitor.observe_packet(packets(6, 1)[0])
    assert monitor.observe_packet(packets(5, 1)[0]) == []
    assert monitor.tick(7 * NS) == []
    assert monitor.late_packets_skipped == 301


def test_flow_export_is_never_used_as_instantaneous_packet_timing():
    monitor = ProtocolFloodMonitor({**CONFIG, "absolute_pps": 200})
    record = replace(packets(0, 1)[0], packets=10000, from_flow_record=True)
    assert monitor.observe_packet(record) == []
    assert monitor.tick(NS) == []
    assert len(monitor.buckets) == 0


@pytest.mark.parametrize("setting,value", [
    ("minimum_pps", float("nan")), ("sigma", float("inf")),
    ("absolute_pps", 99), ("absolute_pps", -1),
    ("minimum_syn_pps", -1), ("absolute_syn_pps", 100),
    ("cooldown_s", float("nan")),
])
def test_invalid_thresholds_fail_closed(setting, value):
    with pytest.raises(ValueError):
        ProtocolFloodMonitor({**CONFIG, setting: value})


def test_destination_tick_groups_do_not_mix_model_evidence():
    engine = Engine({"model_enabled": False, "anomaly_enabled": False,
                     "detectors": {"ddos": {"protocol_flood": {**CONFIG, "absolute_pps": 200}}}})
    monitor = engine.rules.by_name["ddos"].protocol_flood
    for destination, count in [(2, 300), (3, 400)]:
        for packet in packets(0, count, destination=destination):
            monitor.observe_packet(packet)
    rows = []
    engine.on_vector = rows.append
    hits = engine.tick(NS)
    assert len(hits) == len(rows) == 2
    assert {(row["dst_ip"], row["values"]["pps_to_dst"]) for row in rows} == {
        ("0.0.0.2", 300), ("0.0.0.3", 400)}


def test_extended_rule_is_not_promoted_to_calibrated_by_existing_model():
    engine = Engine({"model_enabled": False, "anomaly_enabled": False})
    monitor = ProtocolFloodMonitor({**CONFIG, "absolute_pps": 200})
    for packet in packets(0, 300):
        monitor.observe_packet(packet)
    hit, = monitor.tick(NS)
    score = SimpleNamespace(top_class="volumetric-ddos", confidence=0.999, raw_confidence=0.999,
                            probs={"volumetric-ddos": 0.999}, contributions=[])
    assert not engine._ensemble_ready(score, [hit])
    engine._enrich(hit, score, SimpleNamespace(promote=False, reason="test"), None)
    assert hit.source == "rule"
    assert not hit.context["calibrated"]
    assert hit.evidence[0].feature == "pps_to_dst"
    assert "not validated" in hit.context["calibration_note"]


def test_dashboard_replay_flushes_final_burst_into_durable_alert_store(tmp_path):
    store = AlertStore(str(tmp_path / "alerts.duckdb"), str(tmp_path / "alerts.jsonl"))
    try:
        controller = ReplayController(FrameQueue(8), store, {
            "model_enabled": False, "anomaly_enabled": False,
            "detectors": {"ddos": {"protocol_flood": {**CONFIG, "absolute_pps": 200}}}})
        controller._consume(packets(0, 300))
        assert controller.run_alerts == 1
        assert controller.finished
    finally:
        store.close()


@pytest.mark.parametrize("method,port", sorted(AMPLIFICATION_PORTS.items()))
def test_reflection_family_is_service_port_independent(method, port):
    # Only transform decoded metadata. No attack payload, network socket or tool execution.
    detector, ctx, flows = DdosDetector(), Context(), FlowTable()
    hits = []
    for meta in PcapSource(str(ROOT / "data/scenarios/udp_reflection.pcap")):
        if meta.proto == UDP:
            meta = replace(meta, src_port=port, dns=None)
        flow = flows.observe(meta)
        ctx.begin_packet(meta, flow)
        hits.extend(detector.observe(meta, flow, ctx))
    assert any(hit.subtype == "udp-reflection-amplification" for hit in hits), method
    for hit in hits:
        alert = build_alert(hit, {"model_id": "rules", "model_hash": "none", "dataset_version": "test"})
        validate_alert(alert)


def test_coverage_separates_catalogue_from_enabled_and_exact_validation():
    off = method_coverage()
    assert len({row["method"] for row in off["methods"]}) == 47
    assert off["exact_methods_validated"] == 0
    assert not any(row["exact_method_validated"] for row in off["methods"])
    assert not off["runtime"]["extended_enabled"]
    profile = {"detectors": {"ddos": {"protocol_flood": {**CONFIG, "minimum_syn_pps": 100}}}}
    on = method_coverage(profile)
    by_method = {row["method"]: row for row in on["methods"]}
    assert by_method["CPS"]["detector_enabled"]
    assert not by_method["CFB"]["detector_enabled"]
    assert not method_coverage(profile, source_kind="flows")["runtime"]["extended_enabled"]


def test_coverage_api_reports_loaded_config_and_source(tmp_path, monkeypatch):
    monkeypatch.setenv("SIH_ENGINE_CONFIG", str(ROOT / "config/engine-production.json"))
    with TestClient(create_app(str(tmp_path / "db"), str(tmp_path / "ledger.jsonl"))) as client:
        report = client.get("/api/detection-coverage").json()
        assert report["runtime"]["extended_enabled"]
        client.app.state.controller.source_kind = "flows"
        report = client.get("/api/detection-coverage").json()
        assert report["runtime"]["extended_configured"]
        assert not report["runtime"]["extended_enabled"]


def test_pending_windows_are_bounded_and_idle_ticks_do_not_scan_retained_baselines(monkeypatch):
    monitor = ProtocolFloodMonitor({**CONFIG, "capacity": 4})
    for destination in range(100):
        monitor.observe_packet(packets(0, 1, destination=destination)[0])
    assert len(monitor.pending) == len(monitor.buckets) == 4
    assert monitor.tick(NS) == []
    assert not monitor.pending
    assert len(monitor.buckets) == 4
    def forbidden(*args):
        raise AssertionError("Idle tick scanned the retained baseline table")
    monkeypatch.setattr(monitor.buckets, "items", forbidden)
    monkeypatch.setattr(monitor.buckets, "peek", forbidden)
    assert monitor.tick(2 * NS) == []


def test_pending_window_flush_preserves_lru_order_and_reopens_only_new_seconds():
    monitor = ProtocolFloodMonitor({**CONFIG, "absolute_pps": 200, "cooldown_s": 0})
    for destination in (2, 3):
        for packet in packets(0, 300, destination=destination):
            monitor.observe_packet(packet)
    monitor.observe_packet(packets(0, 1, destination=2)[0])  # destination 2 most recently seen
    assert list(monitor.pending) == [key for key, _bucket in monitor.buckets.items()]
    assert [hit.flow["dst_ip"] for hit in monitor.tick(NS)] == ["0.0.0.3", "0.0.0.2"]
    assert monitor.tick(2 * NS) == []
    for packet in packets(2, 300, destination=2):
        monitor.observe_packet(packet)
    hit, = monitor.tick(3 * NS)
    assert hit.flow["window_start"] == 2
