from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from api.replay import FrameQueue
from api.training_jobs import TrainingJobs
from engine.detect.protocol_flood import ProtocolFloodMonitor
from engine.types import TCP, UDP, ICMP, PacketMeta
from training.candidate import PROFILE, check_dataset, promotion_gates
from training.inventory import ROOT, inspect_datasets


def test_bundled_files_and_dashboard_catalogue_match(tmp_path):
    with TestClient(create_app(str(tmp_path / "db"), str(tmp_path / "ledger.jsonl"))) as client:
        report = client.get("/api/datasets").json()
        assert report["ok"], report
        assert {row["id"] for row in report["scenarios"]} == {row["id"] for row in client.get("/api/scenarios").json()}
        assert len(report["scenarios"]) == 11
        assert report["training_dataset"]["rows"] == 31264
        assert all(len(row["files"]) == 3 for row in report["scenarios"])


def test_integrity_rejects_a_one_byte_corruption(tmp_path):
    shutil.copytree(ROOT / "data/scenarios", tmp_path / "data/scenarios")
    path = tmp_path / "data/scenarios/benign.pcap"
    with path.open("r+b") as handle:
        handle.seek(40)
        old = handle.read(1)
        handle.seek(40)
        handle.write(bytes([old[0] ^ 1]))
    report = inspect_datasets(tmp_path)
    assert not report["ok"]
    assert report["scenarios"][0]["files"][0]["hash_status"] == "mismatch"


def test_training_input_and_strict_gates():
    assert check_dataset(ROOT / "data/models")["rows"] == 31264
    policy = json.loads(PROFILE.read_text())["gates"]
    report = {"per_class": {"encrypted-malware": {"precision": 1.0, "recall": 1.0, "rows": 500}},
              "reliability_weighted": {"expected_calibration_error": 0.0}}
    assert not promotion_gates(report, policy)["passed"]
    report["per_class"]["encrypted-malware"]["precision"] = float("nan")
    assert not promotion_gates(report, policy, independent_real_holdout=True)["passed"]


def test_training_is_token_protected_and_cross_origin_writes_fail(tmp_path, monkeypatch):
    monkeypatch.setenv("SIH_OPERATOR_TOKEN", "s" * 32)
    monkeypatch.delenv("SIH_AUTO_TRAIN", raising=False)
    with TestClient(create_app(str(tmp_path / "db"), str(tmp_path / "ledger.jsonl"))) as client:
        assert client.post("/api/training/start").status_code == 401
        assert client.post("/api/training/start", headers={"Authorization": "Bearer wrong"}).status_code == 401
        assert client.post("/api/replay/stop", headers={"Origin": "https://untrusted.example"}).status_code == 403
        monkeypatch.setattr(client.app.state.training_jobs, "start", lambda: {"state": "running"})
        assert client.post("/api/training/start", headers={"Authorization": "Bearer " + "s" * 32}).status_code == 202
        assert client.get("/api/health").json()["production_ready"] is False


def test_training_refuses_after_shutdown(tmp_path):
    manager = TrainingJobs(tmp_path)
    manager.close()
    with pytest.raises(RuntimeError, match="shutting down"):
        manager.start()


def test_development_proxy_fallback_port_preserves_same_origin(tmp_path):
    # Vite can move to 5176 while other projects occupy its default ports.
    with TestClient(create_app(str(tmp_path / "db"), str(tmp_path / "ledger.jsonl")),
                    base_url="http://localhost:5176") as client:
        headers = {"Origin": "http://localhost:5176"}
        assert client.post("/api/replay/stop", headers=headers).status_code == 200
        assert client.post("/api/replay/stop", headers={"Origin": "http://untrusted.example"}).status_code == 403
        assert client.post("/api/replay/stop", headers={"Origin": "null"}).status_code == 403
        with client.websocket_connect("ws://localhost:5176/ws", headers=headers) as socket:
            assert socket.receive_json()["type"] == "status"


def test_queue_bounded_when_event_loop_is_not_servicing_callbacks():
    async def scenario():
        queue = FrameQueue(8)
        queue.bind(asyncio.get_running_loop())
        # No yield during production: the event-loop callback backlog must not grow per packet.
        for number in range(10000):
            queue.offer("alert", number)
        assert queue.depth == 8
        assert queue.alert_overflow == 9992
        assert queue._notification_pending
        frames = await queue.drain()
        assert frames[-1]["type"] == "resync"
        assert [row["payload"] for row in frames[:-1]] == list(range(9992, 10000))
    asyncio.run(scenario())


@pytest.mark.parametrize("protocol", [TCP, UDP, ICMP])
def test_extended_protocol_flood_with_warmup_and_cooldown(protocol):
    monitor = ProtocolFloodMonitor({"enabled": True, "minimum_pps": 100, "warmup_windows": 3})
    output = []
    for second, count in enumerate([10, 10, 10, 10, 300, 300, 10]):
        for packet in range(count):
            meta = PacketMeta((100 + second) * 10**9 + packet * 1000, protocol, 1, 2, 55555, 443, 64)
            output.extend(monitor.observe_packet(meta))
    assert len(output) == 1
    assert output[0].threat_class == "volumetric-ddos"
    assert output[0].context["extended_detection"]
    assert "not proof" in output[0].summary


def test_extended_monitor_is_opt_in_and_bounded():
    off = ProtocolFloodMonitor()
    on = ProtocolFloodMonitor({"enabled": True, "capacity": 4})
    for destination in range(100):
        packet = PacketMeta(100 * 10**9, UDP, 1, destination, 1000, 53, 64)
        assert off.observe_packet(packet) == []
        on.observe_packet(packet)
    assert len(off.buckets) == 0
    assert len(on.buckets) == 4


def test_flow_export_can_be_started_from_dashboard_api(tmp_path):
    with TestClient(create_app(str(tmp_path / "db"), str(tmp_path / "ledger.jsonl"))) as client:
        response = client.post("/api/replay/start", json={"scenario": "benign", "source": "flows", "mode": "virtual"})
        assert response.status_code == 200
        controller = client.app.state.controller
        controller._thread.join(timeout=20)
        assert not controller.running()
        assert controller.error is None
        assert controller.total_packets == 1200
        assert client.post("/api/replay/start", json={"scenario": "benign", "source": "arbitrary"}).status_code == 422
