import json
from types import SimpleNamespace

import dpkt
import httpx
import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from engine.decode.packet import parse_packet
from engine.pipeline import Engine
from tools import attack_lab as lab
from test_live_monitoring import FakeLiveSource


def test_live_cli_rejects_arbitrary_destinations_and_invalid_ports(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "ROOT", tmp_path)
    for arguments in (["live", "--target", "192.0.2.1"], ["live", "--api-port", "0"],
                      ["live", "--api-port", "65536"], ["live", "--scenario", "flood"]):
        with pytest.raises(SystemExit) as error:
            lab.main(arguments)
        assert error.value.code == 2
    assert not (tmp_path / "data").exists()


def test_loopback_plan_owns_its_receivers_is_bounded_and_releases_them():
    with lab.LoopbackTraffic("mixed", "abc123") as traffic:
        assert len(traffic.steps) == 224
        assert len({receiver.getsockname() for receiver, _ in traffic.steps}) == 97
        sockets = {receiver for receiver, _ in traffic.steps} | {traffic.sender}
        assert all(sock.getsockname()[0] == "127.0.0.1" for sock in sockets)
        assert max(len(payload) for _, payload in traffic.steps) < 512
        for _, payload in traffic.steps:
            if payload != b"SIH lab probe":
                query = dpkt.dns.DNS(payload)
                assert query.qd[0].name.endswith(".test") and query.qd[0].type == 16
    assert all(sock.fileno() == -1 for sock in sockets)


def test_dns_wire_pattern_reaches_real_detector_and_preserves_observed_port():
    engine = Engine({"model_enabled": False, "anomaly_enabled": False})
    detections = []
    for index in range(lab.DNS_COUNT):
        payload = lab.dns_query(index, 26145, "lab-unit")
        udp = dpkt.udp.UDP(sport=49150, dport=5353, ulen=8 + len(payload), data=payload)
        ip = dpkt.ip.IP(src=b"\x7f\x00\x00\x01", dst=b"\x7f\x00\x00\x01", p=17, data=udp)
        ip.len = len(ip)
        meta = parse_packet(1_788_825_600_000_000_000 + index * 30_000_000, bytes(ip), 101)
        detections.extend(engine.feed(meta))
    dns = [d for d in detections if d.threat_class == "dga-dns-tunnelling"]
    assert dns and dns[0].subtype == "dns-tunnel-txt-null"
    assert dns[0].flow["dst_port"] == 5353


def test_missing_class_and_benign_false_alert_fail_the_verdict():
    dns = {"x_threat_class": "dga-dns-tunnelling"}
    result = lab.assess(lab.LIVE_EXPECTED["mixed"], [dns])
    assert not result["detection_check_passed"]
    assert result["missing_classes"] == ["recon-scanning"]
    assert not lab.assess(set(), [dns])["detection_check_passed"]
    assert lab.assess(set(), [])["detection_check_passed"]


def test_active_operator_session_is_never_replaced():
    calls = []
    def handler(request):
        calls.append((request.method, request.url.path))
        return httpx.Response(200, json={"running": True})
    with httpx.Client(transport=httpx.MockTransport(handler), base_url="http://127.0.0.1") as client:
        with pytest.raises(RuntimeError, match="already running"):
            lab.run_live(client, "mixed", {"run_id": "test"}, [])
    assert calls == [("GET", "/api/status")]


def test_old_alerts_cannot_pass_a_new_live_test_and_capture_is_stopped(monkeypatch):
    class FakeTraffic:
        steps = [1]
        filter = "udp and src port 50000"
        sent = 1
        def __init__(self, *args):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def send(self):
            return .1
        def stats(self):
            return {"sent_datagrams": 1}
    calls = []
    capture = {"queue_depth": 0, "queue_dropped": 0, "stale_dropped": 0, "undecodable": 0}
    def handler(request):
        calls.append(request)
        path = request.url.path
        bodies = {
            "/api/status": {"running": False},
            "/api/live/interfaces": {"available": True, "interfaces": [{"id": "lo", "name": "Loopback"}]},
            "/api/live/start": {"session_id": "new"},
            "/api/live/status": {"session_id": "new", "running": True, "error": None, "capture": capture},
            "/api/metrics": {"packets": 1},
            "/api/alerts": [{"x_threat_class": name, "x_detection_context": {"capture_session": "old"}}
                            for name in lab.LIVE_EXPECTED["mixed"]],
            "/api/live/stop": {"running": False},
        }
        return httpx.Response(200, json=bodies[path])
    clock = iter(range(0, 1000, 100))
    monkeypatch.setattr(lab, "LoopbackTraffic", FakeTraffic)
    monkeypatch.setattr(lab, "time", SimpleNamespace(monotonic=lambda: next(clock), sleep=lambda _: None))
    report, alerts = {"run_id": "unit"}, []
    with httpx.Client(transport=httpx.MockTransport(handler), base_url="http://127.0.0.1") as client:
        lab.run_live(client, "mixed", report, alerts)
    assert not report["passed"] and len(report["missing_classes"]) == 2
    assert alerts == []
    assert calls[-1].url.params["session_id"] == "new"
    assert report["capture_stopped"]


def test_stale_stop_request_cannot_stop_a_different_capture(tmp_path, monkeypatch):
    monkeypatch.setattr("api.live.interfaces", lambda: {"available": True, "interfaces": [{"id": "eth0"}]})
    monkeypatch.setattr("api.live.LiveSource", FakeLiveSource)
    with TestClient(create_app(str(tmp_path / "a.duckdb"), str(tmp_path / "a.jsonl"))) as client:
        active = client.post("/api/live/start", json={"interface": "eth0"}).json()
        assert client.post("/api/live/stop?session_id=old").status_code == 409
        assert client.get("/api/live/status").json()["running"]
        assert client.post("/api/live/stop", params={"session_id": active["session_id"]}).status_code == 200


def test_api_setup_failure_still_saves_a_failed_report(tmp_path, monkeypatch):
    monkeypatch.setattr(lab, "ROOT", tmp_path)
    def unavailable(*args):
        raise RuntimeError("Capture unavailable")
    monkeypatch.setattr(lab, "run_live", unavailable)
    assert lab.main(["live"]) == 2
    reports = list((tmp_path / "data/attack-lab").glob("*/report.json"))
    assert len(reports) == 1
    report = json.loads(reports[0].read_text())
    assert not report["passed"] and "Capture unavailable" in report["error"]
    assert json.loads(reports[0].with_name("alerts.json").read_text()) == []
