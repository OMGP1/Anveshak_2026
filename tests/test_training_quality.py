import json

import numpy as np
import pandas as pd
import pytest

from engine.models.tier1 import Tier1Model
from engine.models.support import supports_class
from engine.types import THREAT_CLASSES
from training.candidate import PROFILE, promotion_gates
from training.evaluate import calibrated_probs, persisted_rules
from training.selection import prevalence_weights, temporal_validation, select_parameters
from training.train_tier1 import train


def test_temporal_selection_has_timestamp_embargo_and_no_shared_flows():
    rows = []
    for cls in THREAT_CLASSES:
        for t in range(100):
            rows.append({"scenario": cls, "ts_ns": t, "label": cls,
                         "flow_id": f"{cls}-{t}" if t % 10 else f"{cls}-persistent"})
    fitting, validation = temporal_validation(pd.DataFrame(rows))
    assert not set(fitting.flow_id) & set(validation.flow_id)
    for cls in THREAT_CLASSES:
        assert fitting[fitting.scenario == cls].ts_ns.max() < validation[validation.scenario == cls].ts_ns.min()
    assert set(fitting.label) == set(validation.label) == set(THREAT_CLASSES)


def test_calibration_weights_match_declared_prevalence():
    labels = np.array(["benign"] * 100 + ["c2-beaconing"] * 50)
    weights = prevalence_weights(labels, 0.001)
    assert weights[labels != "benign"].sum() / weights.sum() == pytest.approx(0.001)
    assert weights.mean() == pytest.approx(1)


def test_actual_search_accepts_string_class_labels_and_selects_only_from_training():
    rows = [{"scenario": name, "label": name, "ts_ns": t, "flow_id": f"{name}/{t}",
             "signal": number + (t % 5) / 100}
            for number, name in enumerate(THREAT_CLASSES) for t in range(60)]
    selected, report = select_parameters(pd.DataFrame(rows), ["signal"],
        {"objective": "multiclass", "n_estimators": 12, "min_child_samples": 3,
         "num_leaves": 7, "n_jobs": 1, "verbose": -1, "random_state": 42},
        [{}, {"num_leaves": 5}], 3, calibration_candidates=[
            {"method": "isotonic", "input_space": "raw_margin"},
            {"method": "sigmoid", "input_space": "probability"}])
    assert 1 <= selected["n_estimators"] <= 12
    assert len(report["trials"]) == 2 and report["shared_flow_ids"] == 0
    assert report["inner_calibration_rows"] > 0
    assert report["fit_calibration_shared_flows"] == report["calibration_validation_shared_flows"] == 0


def test_incomplete_evaluation_cannot_pass_promotion_gates():
    report = {"per_class": {"benign": {"precision": 1, "recall": 1, "rows": 1000}},
              "reliability_weighted": {"expected_calibration_error": 0}}
    gates = promotion_gates(report, json.loads(PROFILE.read_text())["gates"], True)
    assert not gates["passed"]
    assert any("omits required classes" in reason for reason in gates["failures"])


def test_dns_rule_does_not_taint_other_clients_using_the_same_resolver():
    rows = pd.DataFrame({"ts": [0, 1, 2], "rule_class": ["dga-dns-tunnelling", "benign", "benign"],
                         "src_ip": ["infected", "healthy", "infected"], "dst_ip": ["resolver"] * 3,
                         "scenario": ["dns"] * 3})
    assert persisted_rules(rows, THREAT_CLASSES).tolist() == ["dga-dns-tunnelling", "benign", "dga-dns-tunnelling"]


@pytest.mark.parametrize("name", THREAT_CLASSES[1:])
def test_structural_features_alone_cannot_support_a_specific_threat_class(name):
    assert not supports_class(name, {"pkts_fwd": 1000, "bytes_fwd": 1000000, "duration": 60})


@pytest.mark.parametrize("name,values", [
    ("encrypted-malware", {"tls_version": 772, "ja4_observation_count": 1, "fingerprint_consistency_score": 0}),
    ("recon-scanning", {"scan_probe_count_60s": 100}),
    ("c2-beaconing", {"beacon_sample_count": 20, "ls_peak_period_s": 60}),
    ("data-exfiltration", {"outbound_bytes_total": 500000, "out_in_ratio_ewma": 10}),
    ("dga-dns-tunnelling", {"source_query_count_300s": 100, "distinct_regdom_300s": 50}),
    ("volumetric-ddos", {"pps_to_dst_ewma_dev": 10, "udp_packet_share": 1, "reflection_service_share": 1}),
])
def test_observed_threat_metadata_remains_eligible_for_model_alerts(name, values):
    assert supports_class(name, values)


@pytest.mark.parametrize("method,space", [("isotonic", "raw_margin"), ("isotonic", "probability"),
                                         ("sigmoid", "raw_margin"), ("sigmoid", "probability")])
def test_training_and_calibration_do_not_depend_on_test_features_or_labels(tmp_path, method, space):
    # Real fitting/export checks, with test rows changed arbitrarily between runs.
    rows = []
    rng = np.random.default_rng(123)
    for split, start in [("train", 0), ("calibration", 100), ("test", 200)]:
        for cls_no, cls in enumerate(THREAT_CLASSES):
            for i in range(60):
                rows.append({"split": split, "scenario": cls, "flow_id": f"{cls}/{start+i}",
                             "ts_ns": start + i, "label": cls,
                             "signal": cls_no + rng.normal(0, .1), "noise": rng.random()})
    frame = pd.DataFrame(rows)
    manifest = {"features": ["signal", "noise"], "dataset_version": "unit-fixture",
                "dataset_sha256": "fixture", "split_bounds": {}}
    models = []
    for name in ("a", "b"):
        path = tmp_path / name
        path.mkdir()
        if name == "b":
            frame.loc[frame.split == "test", ["signal", "noise"]] = 1e9
            frame.loc[frame.split == "test", "label"] = "benign"
        frame.to_parquet(path / "dataset.parquet", index=False)
        (path / "dataset_manifest.json").write_text(json.dumps(manifest))
        train(str(path), {"objective": "multiclass", "n_estimators": 12, "num_leaves": 7,
                          "min_child_samples": 3, "n_jobs": 1, "verbose": -1, "random_state": 42},
              anomaly_trees=5, calibration_prevalence=0.001, purge_calibration_flows=True,
              calibration_candidates=[{"method": method, "input_space": space}])
        models.append(Tier1Model.load(str(path)))
    x = frame.loc[frame.split == "calibration", ["signal", "noise"]].to_numpy()
    assert models[0].meta["model_hash"] == models[1].meta["model_hash"]
    assert models[0].meta["calibration_method"] == method
    assert np.allclose(calibrated_probs(models[0], x), calibrated_probs(models[1], x))
    batched = calibrated_probs(models[0], x[:10])
    for row, expected in zip(x[:10], batched):
        score = models[0].score(dict(zip(["signal", "noise"], row)))
        assert [score.probs[c] for c in models[0].classes] == pytest.approx(expected)


def test_sigmoid_export_handles_extreme_margins_without_overflow():
    from engine.models.calibration import calibrate_matrix
    values = np.array([[-1e6, 1e6], [1e6, -1e6]])
    curves = {name: {"a": -2., "b": 1.} for name in ("benign", "attack")}
    with np.errstate(over="raise", invalid="raise"):
        result = calibrate_matrix(values, values, curves, ["benign", "attack"])
    assert np.isfinite(result).all()
    assert result.tolist() == [[0., 1.], [1., 0.]]


def test_augmented_sessions_preserve_test_rows_and_separate_identical_flow_tuples(tmp_path, monkeypatch):
    from training import augment_dataset as module
    original = pd.DataFrame([{"scenario": "fixture", "split": split, "ts_ns": i,
                              "flow_id": "same-tuple", "label": "benign", "signal": float(i)}
                             for i, split in enumerate(("train", "calibration", "test"))])
    original.to_parquet(tmp_path / "dataset.parquet", index=False)
    (tmp_path / "dataset_manifest.json").write_text(json.dumps(
        {"dataset_sha256": "original-hash", "dataset_version": "fixture"}))
    monkeypatch.setattr(module, "SCENARIOS", [{"id": "fixture", "seed": 10}])

    def build(spec, output):
        from pathlib import Path
        (Path(output) / "fixture.labels.json").write_text("{}")
        return {"seed": spec["seed"]}

    monkeypatch.setattr(module, "build", build)
    monkeypatch.setattr(module, "replay", lambda spec, labels: (original.to_dict("records"), {}))
    result = module.augment(tmp_path, {"train_seed_offsets": [100], "calibration_seed_offsets": [200]})
    frame = pd.read_parquet(tmp_path / "dataset.parquet")
    pd.testing.assert_frame_equal(original[original.split == "test"].reset_index(drop=True),
                                  frame[frame.split == "test"].reset_index(drop=True))
    extra = frame[frame.scenario != "fixture"]
    assert not set(extra[extra.split == "train"].flow_id) & set(extra[extra.split == "calibration"].flow_id)
    assert len(result["augmentation_sessions"]) == 2
    assert result["source_dataset_sha256"] == "original-hash"


def test_augmentation_rejects_seed_reuse_before_creating_captures(tmp_path):
    from training.augment_dataset import augment
    pd.DataFrame({"split": ["test"]}).to_parquet(tmp_path / "dataset.parquet")
    (tmp_path / "dataset_manifest.json").write_text("{}")
    with pytest.raises(ValueError, match="disjoint"):
        augment(tmp_path, {"train_seed_offsets": [1000], "calibration_seed_offsets": [1000]})
    assert not (tmp_path / "augmentation-captures").exists()


def test_holdout_rejects_seeds_seen_in_augmented_training_or_calibration(tmp_path):
    from training.seed_holdout import SCENARIOS, validate_seeds
    (tmp_path / "dataset_manifest.json").write_text(json.dumps({"augmentation_sessions": {
        "training": {"seed": SCENARIOS[0]["seed"] + 610000},
        "calibration": {"seed": SCENARIOS[0]["seed"] + 630000}}}))
    for offset in (610000, 630000):
        with pytest.raises(ValueError, match="overlap"):
            validate_seeds(offset, [tmp_path])
    validate_seeds(910000, [tmp_path])


def test_candidate_rejects_augmented_capture_moved_between_roles(tmp_path):
    from training.candidate import check_dataset
    from engine.models.tier1 import MODEL_FEATURES, sha256_file
    rows = [{"scenario": name, "split": split, "ts_ns": t, "flow_id": f"{name}/{t}", "label": name,
             **{feature: 0. for feature in MODEL_FEATURES}}
            for name in THREAT_CLASSES for t, split in enumerate(("train", "calibration", "test"))]
    rows.append({**rows[0], "scenario": "added/seed-99", "flow_id": "added/seed-99/tuple"})
    frame = pd.DataFrame(rows)
    manifest = {"features": MODEL_FEATURES, "rows": len(frame), "augmentation_sessions": {
        "added/seed-99": {"seed": 99, "rows": 1, "split": "train"}}}

    def save():
        frame.to_parquet(tmp_path / "dataset.parquet", index=False)
        manifest["dataset_sha256"] = sha256_file(str(tmp_path / "dataset.parquet"))
        manifest["counts"] = {split: {"rows": len(part)} for split, part in frame.groupby("split")}
        (tmp_path / "dataset_manifest.json").write_text(json.dumps(manifest))

    save()
    check_dataset(tmp_path)
    frame.loc[frame.scenario == "added/seed-99", "split"] = "calibration"
    save()
    with pytest.raises(ValueError, match="crosses assigned roles"):
        check_dataset(tmp_path)


def test_model_selection_cannot_improve_average_by_dropping_an_attack_class():
    from training.selection import selection_rank
    complete = {"selection_score": .6, "selected_rounds": 100,
                "per_class": {name: {"recall": .5} for name in THREAT_CLASSES if name != "benign"}}
    dropped = {**complete, "selection_score": .99,
               "per_class": {**complete["per_class"], "encrypted-malware": {"recall": 0.}}}
    assert max([dropped, complete], key=selection_rank) is complete
