from __future__ import annotations

import time

import numpy as np
from fastapi.testclient import TestClient

from api.main import create_app
from engine.alerts.schema import build_alert, validate_alert
from engine.models.novelty import NOVELTY_FEATURES, NoveltyModel
from engine.pipeline import Engine
from engine.types import Detection, Evidence, PacketMeta, UDP


class FakeNovelty:
    nbytes = 128
    meta = {"model_hash": "sha256:" + "1" * 64, "baseline_hash": "sha256:" + "2" * 64}

    @staticmethod
    def score(values):
        return {"raw_score": 1.25, "tail_fraction": 0.0001, "calibration_count": 10_000,
                "deviations": {name: float(index + 1) for index, name in enumerate(NOVELTY_FEATURES)}}


def known_alert(ts_ns: int = 1_700_000_000_000_000_000) -> dict:
    detection = Detection(
        ts_ns=ts_ns,
        threat_class="volumetric-ddos",
        subtype="fixture",
        confidence=0.8,
        severity="HIGH",
        source="test",
        flow={"proto": UDP, "src_ip": 1, "dst_ip": 2, "src_port": 50000, "dst_port": 53,
              "directionality": "FWD_ONLY", "completeness_flag": False,
              "window_start_ns": ts_ns, "window_end_ns": ts_ns},
        evidence=[Evidence("packet_rate", 1000.0, 1.0)],
        summary="Synthetic fixture for API contract tests.",
    )
    return build_alert(detection, {"model_id": "fixture", "model_hash": "none",
                                   "dataset_version": "fixture", "calibrated": False})


def test_unknown_taxonomy_is_alert_only_and_validates():
    detection = Detection(
        ts_ns=1_700_000_000_000_000_000,
        threat_class="unknown-suspicious",
        subtype="novelty-review",
        confidence=0.91,
        severity="MEDIUM",
        source="novelty-companion",
        flow={"proto": UDP, "src_ip": 1, "dst_ip": 2, "src_port": 50000, "dst_port": 443,
              "directionality": "FWD_ONLY", "completeness_flag": False},
        evidence=[Evidence("packet_rate", 12.0, 3.0)],
        summary="Unusual versus the approved baseline; analyst review required.",
        context={"novelty": {"decision": "novelty-review"}},
    )
    alert = build_alert(detection, {"model_id": "novelty-companion-v1",
                                    "model_hash": "sha256:" + "1" * 64,
                                    "dataset_version": "sha256:" + "2" * 64,
                                    "calibrated": False})
    validate_alert(alert)
    assert alert["x_threat_class"] == "unknown-suspicious"
    assert alert["external_references"] == []


def test_novelty_runs_without_a_known_rule_or_classifier_candidate():
    engine = Engine({"model_enabled": False, "anomaly_enabled": False,
                     "novelty": {"enabled": True, "shadow": False, "min_packets": 1,
                                 "persistence_windows": 1, "review_tail_fraction": 0.01,
                                 "suspicious_tail_fraction": 0.001}})
    engine.novelty.model = FakeNovelty()
    packet = PacketMeta(ts_ns=1_000_000_000, proto=UDP, src_ip=1, dst_ip=2,
                        src_port=50000, dst_port=9999, length=120)
    assert engine.feed(packet) == []
    found = engine.tick(7_000_000_000)
    assert [detection.threat_class for detection in found] == ["unknown-suspicious"]
    assert found[0].context["novelty"]["score_meaning"].startswith("rarity")
    assert engine.scored == 0  # the known LightGBM path was never invoked


def test_novelty_finalises_capacity_eviction_and_eof_exactly_once():
    config = {"model_enabled": False, "anomaly_enabled": False, "flow_capacity": 1,
              "novelty": {"enabled": True, "shadow": False, "min_packets": 1,
                          "persistence_windows": 1, "review_tail_fraction": 0.01,
                          "suspicious_tail_fraction": 0.001}}
    engine = Engine(config)
    engine.novelty.model = FakeNovelty()
    first = PacketMeta(ts_ns=1_000_000_000, proto=UDP, src_ip=1, dst_ip=2,
                       src_port=50000, dst_port=9999, length=120)
    second = PacketMeta(ts_ns=2_000_000_000, proto=UDP, src_ip=3, dst_ip=4,
                        src_port=50001, dst_port=9998, length=120)
    assert engine.feed(first) == []
    evicted = engine.feed(second)
    assert len(evicted) == 1
    assert evicted[0].context["novelty"]["reason_codes"][-1] == "flow-table-capacity-eviction"
    assert len(engine.sweep()) == 1
    assert engine.sweep() == []


def test_novelty_model_roundtrip_keeps_finite_sample_tail_floor(tmp_path):
    rng = np.random.default_rng(26145)
    train = rng.normal(size=(32, len(NOVELTY_FEATURES)))
    calibration = rng.normal(size=(16, len(NOVELTY_FEATURES)))
    model = NoveltyModel.fit(train, calibration, trees=8)
    model.save(tmp_path)
    loaded = NoveltyModel.load(tmp_path)
    assert loaded is not None
    result = loaded.score({name: 100.0 for name in NOVELTY_FEATURES})
    assert result["calibration_count"] == 16
    assert result["tail_fraction"] >= 1 / 17


def test_case_conflicts_idempotency_copilot_and_report_draft(tmp_path):
    app = create_app(str(tmp_path / "alerts.duckdb"), str(tmp_path / "alerts.jsonl"))
    alert = known_alert()
    app.state.store.append(alert)
    with TestClient(app) as client:
        first = client.post(
            f"/api/cases/{alert['id']}/commands",
            headers={"x-sih-user": "analyst-a"},
            json={"action": "claim", "expected_version": 0, "idempotency_key": "claim-a"},
        )
        assert first.status_code == 200
        assert first.json()["case"]["version"] == 1
        replay = client.post(
            f"/api/cases/{alert['id']}/commands",
            headers={"x-sih-user": "analyst-a"},
            json={"action": "claim", "expected_version": 0, "idempotency_key": "claim-a"},
        )
        assert replay.json()["idempotent_replay"] is True
        conflict = client.post(
            f"/api/cases/{alert['id']}/commands",
            headers={"x-sih-user": "analyst-b"},
            json={"action": "claim", "expected_version": 0, "idempotency_key": "claim-b"},
        )
        assert conflict.status_code == 409
        review = client.post(
            f"/api/alerts/{alert['id']}/reviews",
            headers={"x-sih-user": "analyst-a"},
            json={"expected_version": 1, "idempotency_key": "review-a",
                  "label": "inconclusive", "reason": "One-sided synthetic fixture."},
        )
        assert review.status_code == 200
        assert review.json()["case"]["review_label"] == "inconclusive"
        events = client.get("/api/cases/events?after=0").json()
        assert [event["case_version"] for event in events["events"]] == [1, 2]

        submitted = client.post("/api/copilot/query", headers={"x-sih-user": "analyst-a"},
                                json={"intent": "explain_alert", "alert_ids": [alert["id"]]})
        assert submitted.status_code == 202
        job = _wait_job(client, submitted.json()["id"], "analyst-a")
        assert job["state"] == "complete"
        assert "not calibrated as an attack probability" in job["result"]["briefing"]
        assert "untrusted_key" in " ".join(job["result"]["limitations"])

        draft = client.post("/api/copilot/query", headers={"x-sih-user": "analyst-a"},
                            json={"intent": "draft_incident_report", "alert_ids": [alert["id"]]})
        completed = _wait_job(client, draft.json()["id"], "analyst-a")
        report = completed["result"]["report"]
        assert report["document"]["submission_status"] == "not_submitted"
        assert "awareness_time" in report["document"]["missing_fields"]
        exported = client.get(f"/api/reports/{report['report_id']}/export?format=markdown")
        assert exported.status_code == 200
        assert "human review required" in exported.text


def _wait_job(client: TestClient, job_id: str, actor: str) -> dict:
    for _ in range(50):
        job = client.get(f"/api/copilot/jobs/{job_id}", headers={"x-sih-user": actor}).json()
        if job["state"] not in {"queued", "running"}:
            return job
        time.sleep(0.01)
    raise AssertionError("copilot job did not complete")
