from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys
import time

import pytest
from fastapi.testclient import TestClient

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api.main import create_app
from api.replay import FALLBACK_LINEAGE, FrameQueue, ReplayController, resolve_alert_builder
from api.store import AlertStore, canonical_json
from engine.types import Detection, Evidence

ATTACK_SCENARIO = "syn_flood"
BENIGN_SCENARIO = "benign"
FORBIDDEN_ROOTS = {"requests", "httpx", "urllib", "urllib3", "socket", "http", "aiohttp", "ftplib", "smtplib"}


def make_client(tmp_path: pathlib.Path) -> TestClient:
    app = create_app(str(tmp_path / "alerts.duckdb"), str(tmp_path / "alerts.jsonl"))
    return TestClient(app)


def run_to_completion(client: TestClient, scenario: str, speed: float = 1.0, mode: str = "virtual") -> dict:
    response = client.post("/api/replay/start", json={"scenario": scenario, "speed": speed, "mode": mode})
    assert response.status_code == 200, response.text
    deadline = time.time() + 120
    status = response.json()
    while status["running"] and time.time() < deadline:
        time.sleep(0.05)
        status = client.get("/api/status").json()
    assert not status["running"], "replay did not finish inside the deadline"
    return status


@pytest.fixture(scope="module")
def attack_run(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("attack")
    with make_client(tmp) as client:
        status = run_to_completion(client, ATTACK_SCENARIO)
        yield client, status


@pytest.fixture()
def client(tmp_path):
    with make_client(tmp_path) as instance:
        yield instance


def test_scenarios_lists_the_committed_captures(client):
    scenarios = client.get("/api/scenarios").json()
    assert len(scenarios) == 11
    ids = {s["id"] for s in scenarios}
    assert {ATTACK_SCENARIO, BENIGN_SCENARIO, "beacon_jitter", "port_scan"} <= ids
    for spec in scenarios:
        assert set(spec) == {"id", "name", "file", "proves", "threat_class", "packets", "duration_s"}
        assert (ROOT / spec["file"]).exists()
        assert spec["packets"] > 0 and spec["duration_s"] > 0


def test_idle_status_matches_the_contract(client):
    status = client.get("/api/status").json()
    assert set(status) == {"running", "paused", "scenario", "speed", "mode", "clock_ts", "progress", "alerts"}
    assert status == {
        "running": False,
        "paused": False,
        "scenario": None,
        "speed": 1.0,
        "mode": "virtual",
        "clock_ts": None,
        "progress": 0.0,
        "alerts": 0,
    }


def test_attack_scenario_moves_the_clock_and_raises_alerts(attack_run):
    client, status = attack_run
    assert status["scenario"] == ATTACK_SCENARIO
    assert status["clock_ts"] is not None and status["clock_ts"] > 0
    assert status["progress"] == pytest.approx(1.0, abs=0.01)
    assert status["alerts"] > 0
    alerts = client.get("/api/alerts?limit=500").json()
    assert len(alerts) == status["alerts"]
    assert {a["x_threat_class"] for a in alerts} == {"volumetric-ddos"}


def test_benign_scenario_raises_no_alerts(client):
    status = run_to_completion(client, BENIGN_SCENARIO)
    assert status["alerts"] == 0
    assert client.get("/api/alerts").json() == []


def test_pause_freezes_the_clock_and_resume_continues_it(client):
    client.post("/api/replay/start", json={"scenario": BENIGN_SCENARIO, "speed": 60, "mode": "realtime"})
    time.sleep(0.6)
    paused = client.post("/api/replay/pause").json()
    assert paused["paused"] is True and paused["running"] is True
    frozen = client.get("/api/status").json()["clock_ts"]
    time.sleep(0.7)
    assert client.get("/api/status").json()["clock_ts"] == frozen
    resumed = client.post("/api/replay/resume").json()
    assert resumed["paused"] is False
    time.sleep(0.7)
    assert client.get("/api/status").json()["clock_ts"] > frozen
    stopped = client.post("/api/replay/stop").json()
    assert stopped["running"] is False


def test_realtime_mode_honours_capture_timing_at_the_chosen_speed(client):
    client.post("/api/replay/start", json={"scenario": BENIGN_SCENARIO, "speed": 30, "mode": "realtime"})
    time.sleep(0.4)
    first = client.get("/api/status").json()["clock_ts"]
    time.sleep(1.0)
    second = client.get("/api/status").json()["clock_ts"]
    client.post("/api/replay/stop")
    assert 15.0 < (second - first) < 60.0


def test_alerts_paginate_latest_insertions_first(client):
    # Pagination must not depend on a detector producing extra alerts for one
    # attack episode. Insert known valid records in deliberately unsorted order.
    inserted_ids = []
    for index in (1, 0, 2):
        alert = sample_alert(index)
        inserted_ids.append(alert["id"])
        client.app.state.store.append(alert)
    alerts = client.get("/api/alerts?limit=500").json()
    assert len(alerts) == 3
    # Replay clocks and completed detector windows can arrive out of timestamp
    # order. Recent history follows insertion, including those new arrivals.
    assert [a["id"] for a in alerts] == list(reversed(inserted_ids))
    for size in (1, len(alerts) - 1, len(alerts) + 5):
        page = client.get("/api/alerts", params={"limit": size}).json()
        assert len(page) == min(size, len(alerts))
        assert [a["id"] for a in page] == [a["id"] for a in alerts[:len(page)]]


def test_alerts_since_returns_only_newer_records(attack_run):
    client, _ = attack_run
    alerts = client.get("/api/alerts?limit=500").json()
    cutoff = alerts[-1]["created"]
    newer = client.get("/api/alerts", params={"since": cutoff, "limit": 500}).json()
    assert len(newer) == len(alerts) - 1
    assert all(a["created"] > cutoff for a in newer)


def test_one_alert_carries_its_full_evidence(attack_run):
    client, _ = attack_run
    first = client.get("/api/alerts?limit=1").json()[0]
    alert = client.get(f"/api/alerts/{first['id']}").json()
    assert alert == first
    assert alert["type"] == "indicator" and alert["spec_version"] == "2.1"
    assert 0 <= alert["confidence"] <= 100
    assert alert["x_severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert alert["x_supporting_evidence"]
    for item in alert["x_supporting_evidence"]:
        assert set(item) >= {"feature", "value", "shap"}
    flow = alert["x_flow_identifier"]
    assert set(flow) >= {"proto", "src_ip", "dst_ip", "src_port", "dst_port", "directionality"}
    assert alert["external_references"][0]["source_name"] == "mitre-attack"


def test_unknown_alert_id_is_404(attack_run):
    client, _ = attack_run
    assert client.get("/api/alerts/indicator--does-not-exist").status_code == 404


def test_metrics_reports_non_zero_throughput_after_a_run(attack_run):
    client, _ = attack_run
    metrics = client.get("/api/metrics").json()
    assert metrics["packets"] > 1000
    assert metrics["packets_per_s"] > 0
    assert metrics["mbps"] > 0
    assert metrics["flow_table_entries"] > 0
    assert set(metrics["latency_ms"]) >= {"p50", "p95", "p99", "p999"}
    assert metrics["memory_bytes"]["flow_table"] > 0
    assert metrics["memory_bytes"]["flow_table"] <= metrics["memory_caps_bytes"]["flow_table"]
    assert metrics["stage_timing_us"]["decode"] > 0
    assert set(metrics["queue"]) >= {"depth", "capacity", "dropped", "shedding_tier"}


def test_coverage_sums_to_one(attack_run):
    client, _ = attack_run
    coverage = client.get("/api/coverage").json()
    total = coverage["high_confidence"] + coverage["low_confidence"] + coverage["unclassifiable_opaque"]
    assert total == pytest.approx(1.0, abs=1e-6)
    for reason in coverage["reasons"]:
        assert set(reason) == {"code", "label", "fraction", "detail"}
        assert 0.0 <= reason["fraction"] <= 1.0


def test_ledger_verify_returns_ok(attack_run):
    client, _ = attack_run
    verdict = client.get("/api/ledger/verify").json()
    assert verdict["ok"] is True
    assert verdict["records"] == len(client.get("/api/alerts?limit=500").json())
    assert verdict["broken_at"] is None
    assert verdict["anchors_ok"] is True
    assert verdict["head"].startswith("sha256:")


def sample_alert(index: int) -> dict:
    detection = Detection(
        ts_ns=1_788_775_200_000_000_000 + index * 1_000_000_000,
        threat_class="volumetric-ddos",
        subtype="syn-flood",
        confidence=0.8,
        severity="HIGH",
        source="test",
        flow={"proto": "TCP", "src_ip": "10.20.1.5", "dst_ip": "10.20.4.17", "src_port": 4000 + index,
              "dst_port": 443, "directionality": "FWD_ONLY", "completeness_flag": False},
        evidence=[Evidence("syn_synack_ratio_1s", 41.2, 0.34)],
        summary="synthetic record for the ledger tamper test",
    )
    return resolve_alert_builder()(detection, dict(FALLBACK_LINEAGE))


def test_ledger_verify_names_the_tampered_record(tmp_path):
    store = AlertStore(str(tmp_path / "a.duckdb"), str(tmp_path / "a.jsonl"))
    for i in range(5):
        store.append(sample_alert(i))
    assert store.verify_ledger()["ok"] is True
    lines = (tmp_path / "a.jsonl").read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[2])
    record["record"]["confidence"] = 99
    lines[2] = canonical_json(record)
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    verdict = store.verify_ledger()
    store.close()
    assert verdict["ok"] is False
    assert verdict["broken_at"] == 3, "broken_at counts records from 1, like the ledger line numbers"
    assert verdict["records"] == 2


def test_emitted_alerts_carry_the_engine_lineage_not_a_placeholder(attack_run):
    client, _ = attack_run
    alerts = client.get("/api/alerts?limit=500").json()
    assert alerts
    for alert in alerts:
        lineage = alert["x_model_lineage"]
        assert lineage["model_id"] != FALLBACK_LINEAGE["model_id"]
        assert lineage["model_hash"] != FALLBACK_LINEAGE["model_hash"]
        assert lineage["model_hash"].startswith("sha256:")
        assert lineage["dataset_version"]
    calibrated = [a for a in alerts if a["x_detector"] in ("ensemble", "model")]
    assert calibrated, "the fixture must produce at least one model-backed alert"
    assert all(a["x_confidence_calibrated"] is True for a in calibrated)


def test_replaying_the_same_scenario_twice_does_not_duplicate_alerts(client):
    first = run_to_completion(client, ATTACK_SCENARIO)
    assert first["alerts"] > 0
    ids = [a["id"] for a in client.get("/api/alerts?limit=500").json()]
    run_to_completion(client, ATTACK_SCENARIO)
    again = [a["id"] for a in client.get("/api/alerts?limit=500").json()]
    assert again == ids
    assert len(set(again)) == len(again)
    assert client.get("/api/ledger/verify").json()["records"] == len(ids)
    assert client.get("/api/metrics").json()["store"]["duplicates_ignored"] == len(ids)


def test_alert_windows_land_in_the_capture_year_not_1970(attack_run):
    client, _ = attack_run
    for alert in client.get("/api/alerts?limit=500").json():
        flow = alert["x_flow_identifier"]
        assert flow["window_start"][:4] == alert["created"][:4]
        assert flow["window_start"] <= flow["window_end"]


def test_stage_timings_carry_both_a_per_call_and_a_per_packet_view(attack_run):
    client, _ = attack_run
    metrics = client.get("/api/metrics").json()
    per_call = metrics["stage_timing_us"]
    per_packet = metrics["stage_timing_per_packet_us"]
    assert set(per_packet) >= set(per_call)
    assert metrics["stage_calls"]["detect"] > metrics["stage_calls"]["tier1"]
    assert per_packet["tier1"] < per_call["tier1"]


def test_unknown_scenario_is_404(client):
    response = client.post("/api/replay/start", json={"scenario": "not-a-scenario", "speed": 1, "mode": "virtual"})
    assert response.status_code == 404
    assert "not-a-scenario" in response.json()["detail"]


@pytest.mark.parametrize("speed", [0, -1, 100000])
def test_bad_speed_is_400(client, speed):
    response = client.post("/api/replay/start", json={"scenario": BENIGN_SCENARIO, "speed": speed, "mode": "virtual"})
    assert response.status_code == 400
    assert "speed" in response.json()["detail"]


def test_bad_mode_is_400(client):
    response = client.post("/api/replay/start", json={"scenario": BENIGN_SCENARIO, "speed": 1, "mode": "turbo"})
    assert response.status_code == 400


def test_api_stays_responsive_while_a_replay_runs(client):
    client.post("/api/replay/start", json={"scenario": ATTACK_SCENARIO, "speed": 1, "mode": "virtual"})
    for _ in range(5):
        assert client.get("/api/status").status_code == 200
        assert client.get("/api/metrics").status_code == 200
    client.post("/api/replay/stop")


def test_websocket_pushes_status_and_metrics(client):
    with client.websocket_connect("/ws") as socket:
        first = socket.receive_json()
        second = socket.receive_json()
        assert first["type"] == "status"
        assert second["type"] == "metrics"
        assert set(second["payload"]["queue"]) >= {"depth", "capacity", "dropped", "shedding_tier"}


def test_queue_sheds_oldest_metrics_first_and_never_an_alert():
    queue = FrameQueue(capacity=4)
    for i in range(4):
        queue.offer("metrics", i)
    assert queue.depth == 4
    queue.offer("alert", "a1")
    assert queue.depth == 4
    assert queue.dropped_metrics == 1
    kinds = [f["type"] for f in queue.frames()]
    assert kinds == ["metrics", "metrics", "metrics", "alert"]
    assert [f["payload"] for f in queue.frames()][:3] == [1, 2, 3]


def test_queue_bounds_alert_notifications_and_counts_every_drop():
    queue = FrameQueue(capacity=3)
    for name in ("a1", "a2", "a3"):
        queue.offer("alert", name)
    queue.offer("metrics", "m1")
    assert queue.dropped == 1 and queue.dropped_metrics == 1
    queue.offer("status", "s1")
    assert queue.dropped == 2 and queue.dropped_status == 1
    queue.offer("alert", "a4")
    payloads = [f["payload"] for f in queue.frames()]
    assert payloads == ["a2", "a3", "a4"]
    assert queue.depth == queue.capacity
    assert queue.alert_overflow == 1
    assert queue.shedding_tier == "alerts-only"
    stats = queue.stats()
    assert stats["dropped"] == 3 and stats["capacity"] == 3
    assert stats["dropped_alerts"] == 1


def test_queue_prefers_metrics_over_status_when_shedding():
    queue = FrameQueue(capacity=3)
    queue.offer("status", "s1")
    queue.offer("metrics", "m1")
    queue.offer("status", "s2")
    queue.offer("alert", "a1")
    payloads = [f["payload"] for f in queue.frames()]
    assert payloads == ["s1", "s2", "a1"]
    assert queue.dropped_metrics == 1 and queue.dropped_status == 0


def test_metrics_reports_the_queue_drop_count(client):
    queue = client.app.state.queue
    queue.unbind()
    for _ in range(queue.capacity + 40):
        queue.offer("metrics", {})
    metrics = client.get("/api/metrics").json()
    assert metrics["queue"]["dropped"] >= 40
    assert metrics["queue"]["dropped_metrics"] >= 40
    assert metrics["queue"]["depth"] <= metrics["queue"]["capacity"]
    assert metrics["queue"]["policy"]


def test_a_starved_queue_sheds_frames_but_loses_no_alert(tmp_path):
    queue = FrameQueue(capacity=4)
    store = AlertStore(str(tmp_path / "a.duckdb"), str(tmp_path / "a.jsonl"))
    controller = ReplayController(queue, store)
    controller.start(ATTACK_SCENARIO, 1.0, "virtual")
    deadline = time.time() + 120
    while controller.running() and time.time() < deadline:
        time.sleep(0.05)
    controller.stop()
    alerts_queued = [f for f in queue.frames() if f["type"] == "alert"]
    stats = queue.stats()
    persisted = store.count()
    store.close()
    assert stats["dropped"] > 0
    assert stats["dropped"] == stats["dropped_metrics"] + stats["dropped_status"] + stats["dropped_alerts"]
    assert len(alerts_queued) <= queue.capacity
    assert persisted == controller.run_alerts
    assert controller.run_alerts > 0


def engine_modules() -> list[pathlib.Path]:
    return sorted(p for p in (ROOT / "engine").rglob("*.py") if p.name != "__init__.py")


def test_no_module_under_engine_imports_an_outbound_client():
    offenders = []
    for path in engine_modules():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                if name.split(".")[0] in FORBIDDEN_ROOTS:
                    offenders.append(f"{path.relative_to(ROOT)} imports {name}")
    assert offenders == [], "constraint C-a violated: " + "; ".join(offenders)


GUARD_SCRIPT = """
import socket

opened = []
socket.socket.__init__ = lambda self, *a, **k: opened.append(a) or (_ for _ in ()).throw(
    AssertionError("engine opened a socket"))
socket.create_connection = lambda *a, **k: (_ for _ in ()).throw(AssertionError("engine dialled out"))

from engine.sources.pcap_source import PcapSource
from engine.state.entropy import SlidingEntropy
from engine.state.flow_table import FlowTable
from engine.state.hll import HLLFamily

table, entropy, family = FlowTable(capacity=5000), SlidingEntropy(), HLLFamily()
seen = 0
for meta in PcapSource("data/scenarios/syn_flood.pcap"):
    table.observe(meta)
    entropy.add(meta.ts_ns, meta.src_ip.to_bytes(4, "big"))
    family.add(meta.src_ip.to_bytes(4, "big"), meta.dst_port.to_bytes(2, "big"))
    seen += 1
print(seen, len(opened))
"""


def test_the_detection_path_never_constructs_a_socket():
    result = subprocess.run([sys.executable, "-c", GUARD_SCRIPT], cwd=str(ROOT), capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    packets, opened = result.stdout.split()
    assert int(packets) > 10000
    assert int(opened) == 0


def test_engine_source_text_opens_no_socket():
    for path in engine_modules():
        text = path.read_text(encoding="utf-8")
        assert "socket.socket" not in text
        assert "urlopen" not in text
        assert "create_connection" not in text
