from __future__ import annotations

import json
import os
from pathlib import Path
import shutil

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from api.main import create_app
from api.store import AlertStore
from engine.models.integrity import verify_bundle
from engine.sources.pcap_source import PcapSource
from engine.sources.rust_source import RustPcapSource, DEFAULT_BINARY
from tools.prepare_deployment import provision
from training.scenarios import SCENARIOS, ROOT
from test_api import sample_alert
from tools.backup_state import snapshot, restore
from training.problem_statement import problem_statement_inventory
from tools.lab_iperf import normalize


@pytest.mark.skipif(not DEFAULT_BINARY.is_file(), reason="Build the Rust binary to run differential checks")
@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s["id"])
def test_rust_metadata_exact_parity(scenario):
    path = str(Path(ROOT) / scenario["file"])
    python = PcapSource(path)
    rust = RustPcapSource(path)
    sentinel = object()
    from itertools import zip_longest
    for expected, actual in zip_longest(python, rust, fillvalue=sentinel):
        assert expected == actual
    assert python.packets_read == rust.packets_read == scenario["packets"]


def test_missing_native_binary_is_explicit():
    with pytest.raises(FileNotFoundError, match="Rust ingest"):
        RustPcapSource(str(Path(ROOT) / SCENARIOS[0]["file"]), "/nonexistent/sih-native")


def test_ledger_recovers_database_gap_idempotently(tmp_path):
    db, ledger = str(tmp_path / "index.duckdb"), str(tmp_path / "ledger.jsonl")
    store = AlertStore(db, ledger)
    first = store.append(sample_alert(0))["record"]
    # Simulate power loss after durable ledger append, before the database insert.
    second = store.ledger.append(sample_alert(1))["record"]
    store.close()
    for _ in range(2):
        store = AlertStore(db, ledger)
        assert store.after()["alerts"] == [first, second]
        assert store.verify_ledger()["ok"]
        store.close()
    # Disaster recovery: rebuild a NEW database solely from the intact ledger.
    store = AlertStore(str(tmp_path / "restored.duckdb"), ledger)
    assert store.after()["alerts"] == [first, second]
    store.close()


def test_corrupt_ledger_refuses_restart_without_editing_evidence(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    store = AlertStore(str(tmp_path / "index"), str(ledger))
    store.append(sample_alert(0)); store.close()
    with ledger.open("ab") as handle:
        handle.write(b'{"partial":')
    raw = ledger.read_bytes()
    with pytest.raises(ValueError, match="integrity"):
        AlertStore(str(tmp_path / "index"), str(ledger))
    assert ledger.read_bytes() == raw


def test_conflicting_database_is_not_overwritten(tmp_path):
    db, ledger = str(tmp_path / "index"), str(tmp_path / "ledger.jsonl")
    store = AlertStore(db, ledger); store.append(sample_alert(0))
    store._conn.execute("update alerts set doc = '{}' "); store.close()
    with pytest.raises(ValueError, match="conflicts"):
        AlertStore(db, ledger)


def test_missing_ledger_newline_refuses_append_on_restart(tmp_path):
    ledger = tmp_path / "ledger.jsonl"
    store = AlertStore(str(tmp_path / "index"), str(ledger))
    store.append(sample_alert(0)); store.close()
    raw = ledger.read_bytes()[:-1]
    ledger.write_bytes(raw)
    with pytest.raises(ValueError, match="integrity"):
        AlertStore(str(tmp_path / "index"), str(ledger))
    assert ledger.read_bytes() == raw


def test_gateway_cannot_be_bypassed_http_or_websocket(tmp_path, monkeypatch):
    monkeypatch.setenv("SIH_GATEWAY_SECRET", "g" * 48)
    with TestClient(create_app(str(tmp_path / "db"), str(tmp_path / "ledger.jsonl"))) as client:
        assert client.get("/api/status").status_code == 401
        assert client.get("/api/status", headers={"X-SIH-Role": "admin"}).status_code == 401
        headers = {"X-SIH-Gateway": "g" * 48, "X-SIH-Role": "viewer", "X-SIH-User": "fixture-viewer"}
        assert client.get("/api/status", headers=headers).status_code == 200
        assert client.post("/api/replay/stop", headers=headers).status_code == 403
        assert not client.get("/api/training", headers=headers).json()["enabled"]
        headers["X-SIH-Role"] = "operator"
        assert client.post("/api/replay/stop", headers=headers).status_code == 200
        assert client.post("/api/training/start", headers=headers).status_code == 403
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws"):
                pass
        with client.websocket_connect("/ws", headers=headers) as ws:
            assert ws.receive_json()["type"] == "status"


def test_provision_manifest_tamper_and_safe_reentry(tmp_path):
    target = tmp_path / "deployment"
    result = provision(target)
    assert result["signed_files"] == 5
    assert verify_bundle(target / "models", target / "secrets/model-trust.pub")["version"] == 1
    with pytest.raises(FileExistsError):
        provision(target)
    path = target / "models/anomaly_iforest.pkl"
    with path.open("ab") as handle:
        handle.write(b"tamper")
    with pytest.raises(ValueError, match="integrity"):
        verify_bundle(target / "models", target / "secrets/model-trust.pub")


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits do not attest Windows ACL permissions")
def test_provision_uses_private_posix_permissions(tmp_path):
    target = tmp_path / "deployment"
    provision(target)
    assert (target / "secrets/backend-token").stat().st_mode & 0o777 == 0o600


def test_production_requires_trusted_gateway_before_creating_state(tmp_path, monkeypatch):
    monkeypatch.setenv("SIH_PRODUCTION", "1")
    monkeypatch.delenv("SIH_GATEWAY_SECRET", raising=False)
    monkeypatch.delenv("SIH_GATEWAY_SECRET_FILE", raising=False)
    with pytest.raises(ValueError, match="gateway secret"):
        create_app(str(tmp_path / "db"), str(tmp_path / "ledger"))
    assert not (tmp_path / "db").exists()


def test_public_demo_requires_the_configured_browser_origin_for_mutations(tmp_path, monkeypatch):
    origin = "https://anveshak-2026.vercel.app"
    monkeypatch.setenv("SIH_PUBLIC_DEMO", "1")
    monkeypatch.setenv("SIH_ALLOWED_ORIGINS", origin)
    with TestClient(create_app(str(tmp_path / "db"), str(tmp_path / "ledger.jsonl"))) as client:
        assert client.get("/api/health").json()["deployment"] == "public-replay-demo"
        assert client.post("/api/replay/stop").status_code == 403
        assert client.post("/api/replay/stop", headers={"Origin": "https://example.invalid"}).status_code == 403
        allowed = client.post("/api/replay/stop", headers={"Origin": origin})
        assert allowed.status_code == 200
        preflight = client.options(
            "/api/replay/start",
            headers={"Origin": origin, "Access-Control-Request-Method": "POST"},
        )
        assert preflight.status_code == 200
        assert preflight.headers["access-control-allow-origin"] == origin


def test_offline_backup_restore_and_corruption(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    store = AlertStore(str(state / "alerts.duckdb"), str(state / "alerts.jsonl"))
    for i in range(3):
        store.append(sample_alert(i))
    store.close()
    backup = tmp_path / "backup"
    manifest = snapshot(state, backup)
    result = restore(backup, tmp_path / "restored")
    assert result["records"] == 3
    assert result["head"] == manifest["head"]
    with pytest.raises(FileExistsError):
        restore(backup, tmp_path / "restored")
    with (backup / "alerts.jsonl").open("ab") as handle:
        handle.write(b"tamper")
    with pytest.raises(ValueError, match="mismatch"):
        restore(backup, tmp_path / "untrusted")
    assert not (tmp_path / "untrusted").exists()


def test_problem_statement_does_not_claim_fake_downloads(tmp_path):
    report = problem_statement_inventory(tmp_path)
    assert not report["downloadable_datasets_provided"]
    assert len(report["generators"]) == 9
    assert all("missing" in row["status"] for row in report["generators"])


def test_iperf_counter_normalization_preserves_observed_values(tmp_path):
    document = {"start": {"timestamp": {"timesecs": 1700000000}, "connected": [
        {"socket": 5, "local_host": "127.0.0.1", "remote_host": "127.0.0.1", "local_port": 40000, "remote_port": 40001}]},
        "intervals": [{"streams": [{"socket": 5, "start": 0, "end": 1, "packets": 100, "bytes": 120000}]}]}
    path = tmp_path / "flows.csv"
    assert normalize(document, path) == 1
    from engine.sources.flowrecord_source import FlowRecordSource
    row = next(iter(FlowRecordSource(str(path))))
    assert row.from_flow_record and row.packets == 100 and row.length == 120000 and row.tcp_flags == 0
    document["start"]["connected"][0]["remote_host"] = "192.0.2.1"
    with pytest.raises(ValueError, match="loopback"):
        normalize(document, tmp_path / "refused.csv")
