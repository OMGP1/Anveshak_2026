import io
import json
import os
import queue
import struct
import threading
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from engine.pipeline import Engine
from engine.sources.live_source import LiveSource, packet_records, local_interface, SNAPLEN
from engine.types import PacketMeta, TCP, SYN
from engine.detect.beaconing import BeaconDetector
from engine.state.beacon_table import BeaconTable, Candidate
import numpy as np
from test_api import sample_alert


@pytest.mark.skipif(os.name == "nt", reason="POSIX dumpcap paths are rewritten by Windows pathlib")
@pytest.mark.parametrize("candidate", ["/opt/homebrew/bin/dumpcap", "/usr/local/bin/dumpcap"])
def test_macos_finds_homebrew_dumpcap_without_path(monkeypatch, candidate):
    from engine.sources import live_source
    monkeypatch.delenv("SIH_DUMPCAP", raising=False)
    monkeypatch.setattr(live_source.shutil, "which", lambda _: None)
    monkeypatch.setattr(live_source.Path, "is_file", lambda path: str(path) == candidate)
    monkeypatch.setattr(live_source.os, "access", lambda path, mode: str(path) == candidate)
    assert live_source.capture_binary() == str(live_source.Path(candidate).resolve())


def test_invalid_explicit_dumpcap_does_not_silently_use_another_binary(monkeypatch):
    from engine.sources import live_source
    monkeypatch.setenv("SIH_DUMPCAP", "/missing/custom dumpcap")
    monkeypatch.setattr(live_source.shutil, "which", lambda _: "/other/dumpcap")
    monkeypatch.setattr(live_source.Path, "is_file", lambda path: str(path) == "/other/dumpcap")
    monkeypatch.setattr(live_source.os, "access", lambda path, mode: True)
    with pytest.raises(RuntimeError, match="SIH_DUMPCAP.*not an executable file"):
        live_source.capture_binary()


def test_dumpcap_discovery_rejects_nonexecutable_files(monkeypatch):
    from engine.sources import live_source
    monkeypatch.delenv("SIH_DUMPCAP", raising=False)
    monkeypatch.setattr(live_source.shutil, "which", lambda _: "/not-executable/dumpcap")
    monkeypatch.setattr(live_source.Path, "is_file", lambda path: True)
    monkeypatch.setattr(live_source.os, "access", lambda path, mode: False)
    with pytest.raises(RuntimeError):
        live_source.capture_binary()


def test_custom_dumpcap_path_with_spaces_is_preserved(tmp_path, monkeypatch):
    from engine.sources import live_source
    executable = tmp_path / "custom dumpcap"
    executable.write_text("test fixture, not executed")
    executable.chmod(0o700)
    monkeypatch.setenv("SIH_DUMPCAP", str(executable))
    assert live_source.capture_binary() == str(executable.resolve())


def test_capture_start_permission_failure_preserves_error_and_gives_macos_setup(monkeypatch):
    import sys
    from engine.sources import live_source
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(live_source, "capture_binary", lambda: "/installed/dumpcap")
    process = SimpleNamespace(stdout=io.BytesIO(b""), stderr=io.BytesIO(b""), poll=lambda: 1)
    commands = []
    def spawn(command, **kwargs):
        commands.append(command)
        return process
    monkeypatch.setattr(live_source.subprocess, "Popen", spawn)
    source = LiveSource("lo0", "udp and port 50000")
    source._stderr.append("Permission denied opening /dev/bpf0")
    with pytest.raises(RuntimeError) as error:
        source.start()
    assert "Permission denied opening /dev/bpf0" in str(error.value)
    assert "wireshark-chmodbpf" in str(error.value)
    assert commands[0][0] == "/installed/dumpcap"
    assert "ip and (udp and port 50000)" in commands[0]
    assert process.stdout.closed and process.stderr.closed


def test_missing_macos_capture_reports_install_and_permission_steps(monkeypatch):
    import sys
    from engine.sources import live_source
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.delenv("SIH_DUMPCAP", raising=False)
    monkeypatch.setattr(live_source.shutil, "which", lambda _: None)
    monkeypatch.setattr(live_source.Path, "is_file", lambda path: False)
    listing = live_source.interfaces()
    assert not listing["available"] and listing["interfaces"] == []
    assert "brew install wireshark" in listing["error"]
    assert "wireshark-chmodbpf" in listing["error"]
    assert "API" in listing["error"]


@pytest.mark.parametrize("returncode,stderr", [(0, ""), (1, "Permission denied opening /dev/bpf0")])
def test_macos_missing_interfaces_explain_capture_permissions(monkeypatch, returncode, stderr):
    import sys
    from engine.sources import live_source
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(live_source, "capture_binary", lambda: "/installed/dumpcap")
    monkeypatch.setattr(live_source.subprocess, "run", lambda *a, **k:
                        SimpleNamespace(returncode=returncode, stdout="", stderr=stderr))
    listing = live_source.interfaces()
    assert not listing["available"]
    assert "wireshark-chmodbpf" in listing["error"]
    if stderr:
        assert stderr in listing["error"]


def pcap_header(snaplen=SNAPLEN, linktype=1):
    return b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, snaplen, linktype)


def test_live_framing_rejects_oversized_or_truncated_input():
    for payload in (pcap_header() + struct.pack("<IIII", 1, 0, SNAPLEN + 1, SNAPLEN + 1),
                    pcap_header() + struct.pack("<IIII", 1, 0, 8, 8) + b"abc",
                    pcap_header(linktype=999), pcap_header(snaplen=9999999)):
        with pytest.raises(ValueError):
            list(packet_records(io.BytesIO(payload)))


def test_live_reader_accepts_partial_pipe_reads():
    class Fragmented(io.BytesIO):
        def read(self, length):
            return super().read(min(length, 3))
    data = pcap_header() + struct.pack("<IIII", 10, 500, 4, 4) + b"test"
    records = list(packet_records(Fragmented(data)))
    assert records == [None, (10_000_500_000, b"test", 1, False)]


def test_remote_sources_cannot_be_selected():
    for name in ("rpcap://host/eth0", "TCP@host:2002", "-", "--help", "/tmp/fifo", r"\\.\pipe\source"):
        assert not local_interface(name)
        with pytest.raises(ValueError):
            LiveSource(name)
    assert local_interface(r"\Device\NPF_Loopback")
    assert local_interface("eth0")


def test_metadata_queue_discards_stale_packets_and_stays_bounded():
    source = LiveSource("eth0", capacity=2, max_queue_age_s=0.01)
    source.queue.put(("stale", time.perf_counter_ns() - 1_000_000_000))
    source.queue.put(("fresh", time.perf_counter_ns()))
    with pytest.raises(queue.Full):
        source.queue.put_nowait(("overflow", 0))
    assert source.next_packet()[0] == "fresh"
    assert source.stats()["stale_dropped"] == 1
    assert source.stats()["queue_capacity"] == 2


def test_live_reader_excludes_ipv6_even_if_capture_filter_is_bypassed():
    import dpkt
    udp = dpkt.udp.UDP(sport=1234, dport=443, data=b"test", ulen=12)
    ipv6 = dpkt.ip6.IP6(src=bytes.fromhex("20010db8000000000000000000000001"),
                       dst=bytes.fromhex("20010db8000000000000000000000002"),
                       nxt=17, plen=len(udp), hlim=64, data=udp)
    ipv4 = dpkt.ip.IP(src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02",
                     p=17, data=udp)
    ipv4.len = len(ipv4)
    data = pcap_header(linktype=101)
    for packet in (ipv6, ipv4):
        raw = bytes(packet)
        data += struct.pack("<IIII", 10, 0, len(raw), len(raw)) + raw
    source = LiveSource("eth0")
    source._process = SimpleNamespace(stdout=io.BytesIO(data))
    source._read()
    assert source.stats()["packets_received"] == 2
    assert source.stats()["undecodable"] == 1
    assert source.stats()["packets_decoded"] == 1
    assert source.next_packet()[0].src_ip == 0x0A000001
    assert source.queue.empty()


class FakeLiveSource(LiveSource):
    def start(self):
        self.ready.set()
        return self


def test_live_controls_idle_ticks_persistence_and_session_exclusion(tmp_path, monkeypatch):
    monkeypatch.setattr("api.live.interfaces", lambda: {"available": True, "interfaces": [{"id": "eth0"}]})
    monkeypatch.setattr("api.live.LiveSource", FakeLiveSource)
    with TestClient(create_app(str(tmp_path / "a.duckdb"), str(tmp_path / "a.jsonl"))) as client:
        response = client.post("/api/live/start", json={"interface": "eth0"})
        assert response.status_code == 200, response.text
        controller = client.app.state.controller
        assert response.json()["running"]
        assert client.post("/api/live/start", json={"interface": "eth0"}).status_code == 409
        assert client.post("/api/replay/start", json={"scenario": "syn_flood"}).status_code == 409
        assert client.post("/api/replay/pause").status_code == 409
        ticked = threading.Event()
        old_tick = controller.engine.tick
        def tick(now):
            ticked.set()
            return old_tick(now)
        controller.engine.tick = tick
        assert ticked.wait(2), "A quiet live stream must still advance detector windows"
        # Schema-valid alert goes through the shared, durable store even if no
        # browser is connected. Stop/restart does not remove the JSON ledger.
        client.app.state.store.append(sample_alert(700))
        stopped = client.post("/api/live/stop")
        assert stopped.status_code == 200 and not stopped.json()["running"]
        assert json.loads((tmp_path / "a.jsonl").read_text().splitlines()[0])["record"]["id"]
        assert len(client.get("/api/alerts/export").json()) == 1
    with TestClient(create_app(str(tmp_path / "a.duckdb"), str(tmp_path / "a.jsonl"))) as client:
        assert len(client.get("/api/alerts/export").json()) == 1
        assert client.get("/api/ledger/verify").json()["ok"]


def test_unlimited_class_quota_still_protects_the_same_subject():
    engine = Engine({"model_enabled": False, "anomaly_enabled": False, "model_alert_max_per_class": 0})
    score = SimpleNamespace(top_class="recon-scanning")
    now = 1_000_000_000_000
    engine._class_window[score.top_class] = (now, 100)
    packet = PacketMeta(ts_ns=now, proto=TCP, src_ip=1, dst_ip=2, src_port=3000, dst_port=80,
                        length=44, tcp_flags=SYN)
    flow = engine.flows.observe(packet)
    assert engine._quota_ok(now + 1, flow, score)
    engine._cooldown[engine._subject(score.top_class, flow)] = now
    assert not engine._quota_ok(now + 1, flow, score)


def test_json_export_has_a_fixed_boundary_and_handles_more_than_one_page(tmp_path):
    with TestClient(create_app(str(tmp_path / "a.duckdb"), str(tmp_path / "a.jsonl"))) as client:
        store = client.app.state.store
        # Populate many rows through SQL to test pagination without paying for
        # repeated signing; persistence recovery is exercised separately above.
        for index in range(1005):
            store._conn.execute("insert into alerts (seq, doc, threat_class) values (?, ?, ?)",
                                [index + 1, json.dumps({"id": str(index)}), "recon-scanning"])
        snapshot = store.export_records()
        store._conn.execute("insert into alerts (seq, doc, threat_class) values (1006, ?, ?)",
                            ['{"id":"later"}', "recon-scanning"])
        assert len(json.loads("".join(snapshot))) == 1005
        response = client.get("/api/alerts/export?format=json")
        assert len(response.json()) == 1006
        assert 'filename="sih-alerts.json"' in response.headers["content-disposition"]
        lines = client.get("/api/alerts/export?format=jsonl").text.splitlines()
        assert len(lines) == 1006 and json.loads(lines[-1])["id"] == "later"
        assert client.get("/api/alerts/export?threat_class=c2-beaconing").json() == []
        assert client.get("/api/alerts/export?format=exe").status_code == 422


def test_live_alert_is_emitted_and_saved_while_capture_is_still_running(tmp_path, monkeypatch):
    monkeypatch.setattr("api.live.interfaces", lambda: {"available": True, "interfaces": [{"id": "eth0"}]})
    monkeypatch.setattr("api.live.LiveSource", FakeLiveSource)
    with TestClient(create_app(str(tmp_path / "a.duckdb"), str(tmp_path / "a.jsonl"))) as client:
        assert client.post("/api/live/start", json={"interface": "eth0"}).status_code == 200
        source = client.app.state.controller.live_source
        now = time.time_ns()
        source.received = source.decoded = 1200
        # One-way SYN observations only: no responder packets, handshakes,
        # active probes, or actual attack traffic are sent by this test.
        for index in range(1200):
            packet = PacketMeta(ts_ns=now, proto=TCP, src_ip=0x0A000001 + index,
                                dst_ip=0x0A140011, src_port=3000 + index, dst_port=443,
                                length=44, tcp_flags=SYN)
            source.queue.put_nowait((packet, time.perf_counter_ns()))
        deadline = time.monotonic() + 8
        alerts = []
        while time.monotonic() < deadline:
            alerts = client.get("/api/alerts").json()
            if alerts:
                break
            time.sleep(.05)
        assert alerts, client.get("/api/live/status").json()
        assert client.get("/api/live/status").json()["running"]
        alert = alerts[0]
        assert alert["x_threat_class"] == "volumetric-ddos"
        assert alert["x_detection_context"]["ingest"] == "passive-live"
        assert not alert["x_flow_identifier"]["completeness_flag"]
        assert any(row["id"] == alert["id"] for row in client.get("/api/alerts/export").json())
        assert client.get("/api/metrics").json()["live_latency_ms"]["count"] > 0


def test_busy_source_beacon_needs_strong_channel_evidence():
    key = (TCP, 1, 2, 443)
    gaps = np.random.default_rng(9091).uniform(38, 52, 64)
    detector = BeaconDetector({"busy_source_min_samples": 32})
    alert = detector._assess(key, gaps, .05, 10**15)
    assert alert is not None
    assert alert.context["busy_source_channel"] and alert.context["extended_detection"]
    assert "also contacts other destinations" in alert.summary
    assert BeaconDetector()._assess(key, gaps, .05, 10**15) is None
    assert BeaconDetector({"busy_source_min_samples": 32})._assess(key, gaps[:16], .05, 10**15) is None
    noisy = np.random.default_rng(55).uniform(2, 130, 64)
    assert BeaconDetector({"busy_source_min_samples": 32})._assess(key, noisy, .05, 10**15) is None


def test_beacon_tick_budget_defers_work_without_discarding_candidates():
    table = BeaconTable(min_samples=4, ring=4)
    for index in range(8):
        key = (TCP, index, 100, 443)
        table._table[key] = Candidate(1, 100, 0, n_samples=4, ring=np.array([45]*4, dtype=np.float32))
        table._dirty.add(key)
    first = table.ready(100_000_000_000, limit=3)
    second = table.ready(101_000_000_000, limit=3)
    third = table.ready(102_000_000_000, limit=3)
    assert [len(first), len(second), len(third)] == [3, 3, 2]
    assert len({item[0] for item in first + second + third}) == 8
