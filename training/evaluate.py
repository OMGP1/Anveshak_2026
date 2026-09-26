from __future__ import annotations

import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from engine.models.anomaly import AnomalyModel
from engine.models.calibration import calibrate_matrix
from engine.models.rules import subject_endpoint
from engine.models.support import supports_class
from engine.models.tier1 import MODEL_DIR, RAW_SPACE, Tier1Model, softmax
from engine.pipeline import DEFAULT_CONFIG
from training.scenarios import SCENARIOS, load_labels

TARGET_PREVALENCE = 1.0 / 1000.0
RELIABILITY_BINS = 12
RULE_PERSISTENCE_S = 300.0
DRAWS = 400
DRAW_SEED = 26145

PREVALENCE_NOTE = (
    "the corpus is attack heavy by construction, so the natural prevalence of the temporal test "
    "set is nowhere near what a real link carries. every headline number below is therefore "
    "reported at a constructed prevalence of one attack observation per thousand benign ones. the "
    "primary estimator keeps every test row and gives each benign row an importance weight, which "
    "is exact arithmetic and keeps full support for the per-class numbers. the cross-check "
    "physically builds the same ratio by drawing attack rows, and at that ratio only a handful of "
    "attack rows survive, which is why it carries a spread rather than a single figure"
)

ABLATION_NOTE = (
    "rules only is the deterministic detector verdict, held for {0} seconds against the relevant subject "
    "of the flow it named. the hold matters: a rule raises one alert per episode and then goes "
    "quiet on its own cooldown, so scoring the bare fire against every row would report a recall "
    "near zero for a detector that in fact caught the attack. model only is the argmax of the "
    "calibrated tier-1 probability on its own. both is a row-level approximation, which is to "
    "let a held rule name the class and to let the model name a class alone only when it clears "
    "model_alert_confidence, has class-specific observed evidence, and the benign-only isolation "
    "forest calls the row unusual. The relevant subject is the destination for DDoS and source "
    "otherwise. DNS rules do not taint other clients of the resolver. Runtime allowlists, quotas, "
    "cooldowns and the minimum TreeSHAP-evidence count are not simulated here. Actual false "
    "alerts are measured separately by bench.false_positives."
).format(int(RULE_PERSISTENCE_S))

EPISODE_NOTE = (
    "this table asks the operational question rather than the row question: over the whole capture "
    "rather than the temporal test slice alone, did the arm name the right class somewhere inside "
    "the labelled window, and how many positives fell outside every labelled window"
)


def load() -> tuple[pd.DataFrame, Tier1Model, AnomalyModel | None, dict]:
    frame = pd.read_parquet(os.path.join(MODEL_DIR, "dataset.parquet"))
    model = Tier1Model.load(MODEL_DIR)
    if model is None:
        raise SystemExit("no trained tier 1 model in %s, run training/train_tier1.py" % MODEL_DIR)
    with open(os.path.join(MODEL_DIR, "dataset_manifest.json"), "r", encoding="ascii") as fh:
        manifest = json.load(fh)
    return frame, model, AnomalyModel.load(MODEL_DIR), manifest


def calibrated_probs(model: Tier1Model, x: np.ndarray) -> np.ndarray:
    margins = np.asarray(model.booster.predict(x, raw_score=True), dtype=np.float64)
    probs = np.vstack([softmax(row) for row in margins])
    source = margins if model.space == RAW_SPACE else probs
    return calibrate_matrix(source, probs, model.calibration, model.classes)


def weights_for(labels: np.ndarray, target: float) -> tuple[np.ndarray, float, float]:
    attack = labels != "benign"
    n_attack = float(attack.sum())
    n_benign = float((~attack).sum())
    natural = n_attack / max(1.0, n_attack + n_benign)
    if n_attack <= 0 or n_benign <= 0:
        return np.ones(len(labels)), natural, natural
    weight = n_attack * (1.0 - target) / target / n_benign
    return np.where(attack, 1.0, weight), natural, n_attack / (n_attack + n_benign * weight)


def pr_auc(truth: np.ndarray, score: np.ndarray, weight: np.ndarray) -> float:
    from sklearn.metrics import average_precision_score

    if truth.sum() == 0 or truth.sum() == len(truth):
        return float("nan")
    return float(average_precision_score(truth, score, sample_weight=weight))


def per_class(truth: np.ndarray, predicted: np.ndarray, classes: list[str],
              weight: np.ndarray) -> dict:
    from sklearn.metrics import precision_recall_fscore_support

    precision, recall, f1, support = precision_recall_fscore_support(
        truth, predicted, labels=classes, average=None, zero_division=0, sample_weight=weight
    )
    return {
        name: {
            "precision": round(float(precision[i]), 4),
            "recall": round(float(recall[i]), 4),
            "f1": round(float(f1[i]), 4),
            "weighted_support": round(float(support[i]), 2),
            "rows": int((truth == name).sum()),
        }
        for i, name in enumerate(classes)
    }


def macro_f1(report: dict, classes: list[str]) -> float:
    values = [report[name]["f1"] for name in classes if name != "benign"]
    return round(float(np.mean(values)), 4) if values else 0.0


def persisted_rules(frame: pd.DataFrame, classes: list[str]) -> np.ndarray:
    ts = frame["ts"].to_numpy(dtype=np.float64)
    fired = frame["rule_class"].to_numpy()
    src = frame["src_ip"].to_numpy()
    dst = frame["dst_ip"].to_numpy()
    scenario = frame["scenario"].to_numpy()
    attack_classes = [name for name in classes if name != "benign"]
    out = np.array(["benign"] * len(frame), dtype=object)
    last: dict[tuple, float] = {}
    for i in np.argsort(ts, kind="stable"):
        if fired[i] != "benign":
            endpoint = dst[i] if subject_endpoint(fired[i]) == "dst" else src[i]
            last[(scenario[i], fired[i], endpoint)] = ts[i]
            out[i] = fired[i]
            continue
        for name in attack_classes:
            hit = False
            for endpoint in (dst[i] if subject_endpoint(name) == "dst" else src[i],):
                seen = last.get((scenario[i], name, endpoint))
                if seen is not None and 0.0 <= ts[i] - seen <= RULE_PERSISTENCE_S:
                    hit = True
                    break
            if hit:
                out[i] = name
                break
    return out


def arms(frame: pd.DataFrame, probs: np.ndarray, model: Tier1Model, classes: list[str],
         anomaly: np.ndarray | None) -> dict[str, np.ndarray]:
    rules = persisted_rules(frame, classes)
    model_only = np.asarray(model.classes, dtype=object)[np.argmax(probs, axis=1)]
    floor = float(DEFAULT_CONFIG["model_alert_confidence"])
    allowed = (model_only != "benign") & (probs.max(axis=1) >= floor)
    supported = np.zeros(len(frame), dtype=bool)
    for position in np.flatnonzero(allowed):
        supported[position] = supports_class(str(model_only[position]), frame.iloc[position].to_dict())
    allowed &= supported
    if anomaly is not None:
        allowed = allowed & (anomaly >= float(DEFAULT_CONFIG["anomaly_alert_score"]))
    combined = np.where(rules != "benign", rules, np.where(allowed, model_only, "benign"))
    return {"rules_only": rules, "model_only": model_only, "both": combined}


def ablation(frame: pd.DataFrame, probs: np.ndarray, model: Tier1Model, classes: list[str],
             weight: np.ndarray, anomaly: np.ndarray | None) -> dict:
    truth = frame["label"].to_numpy()
    columns = arms(frame, probs, model, classes, anomaly)
    reports = {name: per_class(truth, values, classes, weight) for name, values in columns.items()}
    out = {
        "note": ABLATION_NOTE,
        "model_alert_confidence": float(DEFAULT_CONFIG["model_alert_confidence"]),
        "rule_persistence_s": RULE_PERSISTENCE_S,
        "macro_f1_attack_classes": {name: macro_f1(report, classes)
                                    for name, report in reports.items()},
    }
    out.update(reports)
    return out


def episode_table(frame: pd.DataFrame, probs: np.ndarray, model: Tier1Model, classes: list[str],
                  anomaly: np.ndarray | None) -> dict:
    columns = arms(frame, probs, model, classes, anomaly)
    scenario = frame["scenario"].to_numpy()
    ts = frame["ts"].to_numpy(dtype=np.float64)
    covered = np.zeros(len(frame), dtype=bool)
    rows = []
    for spec in SCENARIOS:
        labels = load_labels(spec["id"])
        here = scenario == spec["id"]
        for attack in labels.get("attacks", []):
            window = here & (ts >= attack["start_ts"]) & (ts <= attack["end_ts"])
            covered |= window
            entry = {
                "scenario": spec["id"],
                "subtype": attack.get("subtype", ""),
                "threat_class": attack["threat_class"],
                "rows_in_window": int(window.sum()),
            }
            for name, values in columns.items():
                entry[name] = int((window & (values == attack["threat_class"])).sum())
            rows.append(entry)
    outside = {}
    for name, values in columns.items():
        loose = (values != "benign") & ~covered
        outside[name] = {
            "total": int(loose.sum()),
            "by_scenario": {key: int(count) for key, count
                            in zip(*np.unique(scenario[loose], return_counts=True))},
        }
    return {
        "note": EPISODE_NOTE,
        "windows": rows,
        "positives_outside_every_labelled_window": outside,
        "rows_outside_every_labelled_window": int((~covered).sum()),
    }


def prior_shift(score: np.ndarray, source: float, target: float) -> np.ndarray:
    a = float(target) / max(1e-12, float(source))
    b = (1.0 - float(target)) / max(1e-12, 1.0 - float(source))
    num = score * a
    return num / np.maximum(1e-12, num + (1.0 - score) * b)


def reliability(truth: np.ndarray, score: np.ndarray, weight: np.ndarray, bins: int) -> dict:
    edges = np.linspace(0.0, 1.0, bins + 1)
    slot = np.clip(np.digitize(score, edges[1:-1], right=False), 0, bins - 1)
    rows = []
    for i in range(bins):
        mask = slot == i
        if not mask.any():
            continue
        w = weight[mask]
        rows.append({
            "bin_low": round(float(edges[i]), 4),
            "bin_high": round(float(edges[i + 1]), 4),
            "mean_predicted": round(float(np.average(score[mask], weights=w)), 5),
            "observed_frequency": round(float(np.average(truth[mask], weights=w)), 5),
            "rows": int(mask.sum()),
            "weighted_rows": round(float(w.sum()), 2),
        })
    gap = sum(r["weighted_rows"] * abs(r["mean_predicted"] - r["observed_frequency"]) for r in rows)
    total = sum(r["weighted_rows"] for r in rows) or 1.0
    return {"bins": rows, "expected_calibration_error": round(gap / total, 5)}


def draw_reliability(natural: dict, weighted: dict, shifted: dict, path: str) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(11.0, 4.8))
    for ax, blob, extra, title in (
        (axes[0], natural, None, "natural test prevalence"),
        (axes[1], weighted, shifted, "constructed prevalence 1 in 1000"),
    ):
        x = [r["mean_predicted"] for r in blob["bins"]]
        y = [r["observed_frequency"] for r in blob["bins"]]
        ax.plot([0, 1], [0, 1], linestyle="--", linewidth=1.0, color="#8a8f98", label="perfect")
        ax.plot(x, y, marker="o", linewidth=1.6, color="#1f6feb", label="tier 1 isotonic")
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.set_xlabel("mean calibrated attack probability")
        ax.set_ylabel("observed attack frequency")
        head = "%s\nECE %.4f" % (title, blob["expected_calibration_error"])
        if extra is not None:
            head += ", %.4f once the prior is shifted" % extra["expected_calibration_error"]
        ax.set_title(head, fontsize=10)
        ax.grid(alpha=0.25, linewidth=0.6)
        ax.legend(fontsize=8, loc="upper left")
    fig.tight_layout()
    fig.savefig(path, dpi=140)
    plt.close(fig)


def constructed_draws(truth: np.ndarray, score: np.ndarray, target: float) -> dict:
    attack = np.flatnonzero(truth)
    benign = np.flatnonzero(~truth)
    keep = int(round(len(benign) * target / (1.0 - target)))
    keep = max(1, min(len(attack), keep))
    rng = np.random.default_rng(DRAW_SEED)
    values = []
    for _ in range(DRAWS):
        index = np.concatenate([benign, rng.choice(attack, size=keep, replace=False)])
        values.append(pr_auc(truth[index], score[index], np.ones(len(index))))
    values = np.asarray(values, dtype=np.float64)
    return {
        "benign_rows": int(len(benign)),
        "attack_rows_kept": keep,
        "measured_prevalence": round(keep / float(keep + len(benign)), 6),
        "draws": DRAWS,
        "pr_auc_mean": round(float(values.mean()), 4),
        "pr_auc_std": round(float(values.std()), 4),
        "pr_auc_min": round(float(values.min()), 4),
        "pr_auc_max": round(float(values.max()), 4),
        "limitation": (
            "only %d attack rows survive at this ratio, so per-class precision and recall are not "
            "estimable here and only the pooled attack against benign pr-auc is reported" % keep
        ),
    }


def evaluate_frame(frame: pd.DataFrame, model: Tier1Model, classes: list[str],
                   forest: AnomalyModel | None) -> dict:
    x = frame[model.feature_names].to_numpy(dtype=np.float64)
    probs = calibrated_probs(model, x)
    anomaly = forest.score_many(x) if forest is not None else None
    truth = frame["label"].to_numpy()
    binary = (truth != "benign").astype(np.int64)
    attack_score = 1.0 - probs[:, model.classes.index("benign")]
    weight, natural, achieved = weights_for(truth, TARGET_PREVALENCE)
    ones = np.ones(len(frame))
    predicted = np.asarray(model.classes, dtype=object)[np.argmax(probs, axis=1)]
    benign_rows = truth == "benign"
    false_positives = int(((predicted != "benign") & benign_rows).sum())
    calibration_prior = (model.meta.get("calibration_target_prevalence")
                         or model.meta.get("calibration_natural_prevalence") or natural)
    per_class_auc = {
        name: round(pr_auc((truth == name).astype(np.int64), probs[:, i], weight), 4)
        for i, name in enumerate(model.classes) if name != "benign"
    }
    return {
        "rows": int(len(frame)),
        "false_positives": {"benign_rows": int(benign_rows.sum()), "attack_predictions": false_positives,
                            "rate": false_positives / max(1, int(benign_rows.sum())),
                            "basis": "Model argmax on benign feature observations, not live alert precision"},
        "natural_prevalence": round(float(natural), 6),
        "constructed_prevalence": round(float(achieved), 6),
        "benign_row_weight": round(float(weight[truth == "benign"][0]), 3)
        if (truth == "benign").any() else 1.0,
        "pr_auc_attack_vs_benign": round(pr_auc(binary, attack_score, weight), 4),
        "pr_auc_at_natural_prevalence": round(pr_auc(binary, attack_score, ones), 4),
        "pr_auc_per_class": per_class_auc,
        "per_class": per_class(truth, predicted, classes, weight),
        "per_class_at_natural_prevalence": per_class(truth, predicted, classes, ones),
        "macro_f1_attack_classes": macro_f1(per_class(truth, predicted, classes, weight), classes),
        "ablation": ablation(frame, probs, model, classes, weight, anomaly),
        "reliability_weighted": reliability(binary, attack_score, weight, RELIABILITY_BINS),
        "reliability_natural": reliability(binary, attack_score, ones, RELIABILITY_BINS),
        "reliability_weighted_after_prior_shift": reliability(
            binary, prior_shift(attack_score, calibration_prior, TARGET_PREVALENCE), weight,
            RELIABILITY_BINS),
        "prior_shift_note": (
            "Prior shift uses the model's calibration target (or measured calibration prevalence), "
            "not the test-label prevalence. When calibration already targets the evaluation prior, "
            "this is the identity. It assumes stable class-conditional distributions."
        ),
        "constructed_test_set": constructed_draws(binary.astype(bool), attack_score,
                                                  TARGET_PREVALENCE),
    }


def print_table(title: str, report: dict, classes: list[str]) -> None:
    print()
    print(title)
    print("  %-22s %9s %8s %8s %10s" % ("class", "precision", "recall", "f1", "test rows"))
    for name in classes:
        row = report[name]
        print("  %-22s %9.4f %8.4f %8.4f %10d"
              % (name, row["precision"], row["recall"], row["f1"], row["rows"]))


def main() -> int:
    frame, model, forest, manifest = load()
    classes = list(model.classes)
    test = frame[frame["split"] == "test"].reset_index(drop=True)
    train_flows = set(frame.loc[frame["split"].isin(["train", "calibration"]), "flow_id"])
    strict = test[~test["flow_id"].isin(train_flows)].reset_index(drop=True)

    headline = evaluate_frame(test, model, classes, forest)
    strict_report = evaluate_frame(strict, model, classes, forest)
    whole = frame.reset_index(drop=True)
    x_all = whole[model.feature_names].to_numpy(dtype=np.float64)
    episodes = episode_table(whole, calibrated_probs(model, x_all), model, classes,
                             forest.score_many(x_all) if forest is not None else None)
    png = os.path.join(MODEL_DIR, "reliability.png")
    draw_reliability(headline["reliability_natural"], headline["reliability_weighted"],
                     headline["reliability_weighted_after_prior_shift"], png)

    metrics = {
        "model_id": model.meta.get("model_id"),
        "model_hash": model.meta.get("model_hash"),
        "dataset_version": manifest["dataset_version"],
        "dataset_sha256": manifest["dataset_sha256"],
        "split_bounds": manifest["split_bounds"],
        "split_note": manifest["split_note"],
        "target_prevalence": TARGET_PREVALENCE,
        "prevalence_note": PREVALENCE_NOTE,
        "classes": classes,
        "feature_count": len(model.feature_names),
        "test": headline,
        "test_strict_no_flow_seen_in_train": strict_report,
        "strict_split_note": "Test excludes every flow seen in training OR calibration; legacy key retained.",
        "episodes": episodes,
        "leakage": manifest["leakage"],
        "reliability_diagram": os.path.relpath(png, os.path.dirname(MODEL_DIR)),
    }
    with open(os.path.join(MODEL_DIR, "metrics.json"), "w", encoding="ascii") as fh:
        json.dump(metrics, fh, indent=2, sort_keys=True)

    print("temporal test rows", headline["rows"], "of", len(frame))
    print("natural test prevalence %.6f, constructed prevalence %.6f (benign weight %.1f)"
          % (headline["natural_prevalence"], headline["constructed_prevalence"],
             headline["benign_row_weight"]))
    print("PR-AUC attack vs benign at 1 in 1000  %.4f" % headline["pr_auc_attack_vs_benign"])
    print("PR-AUC attack vs benign at natural    %.4f" % headline["pr_auc_at_natural_prevalence"])
    print("macro F1 over the six attack classes  %.4f" % headline["macro_f1_attack_classes"])
    print("per class one vs rest PR-AUC at 1 in 1000", headline["pr_auc_per_class"])
    print_table("per class at the constructed prevalence of 1 in 1000",
                headline["per_class"], classes)
    print_table("per class at the natural test prevalence",
                headline["per_class_at_natural_prevalence"], classes)
    print()
    print("ablation macro F1 over attack classes", headline["ablation"]["macro_f1_attack_classes"])
    for arm in ("rules_only", "model_only", "both"):
        print_table("ablation %s at 1 in 1000" % arm, headline["ablation"][arm], classes)
    print()
    print("episode coverage over the whole capture, positive rows inside each labelled window")
    print("  %-14s %-34s %8s %8s %8s %8s" % ("scenario", "subtype", "rows", "rules", "model", "both"))
    for row in episodes["windows"]:
        print("  %-14s %-34s %8d %8d %8d %8d"
              % (row["scenario"], row["subtype"], row["rows_in_window"], row["rules_only"],
                 row["model_only"], row["both"]))
    for name, blob in episodes["positives_outside_every_labelled_window"].items():
        print("  outside every labelled window, %-11s %5d of %d rows %s"
              % (name, blob["total"], episodes["rows_outside_every_labelled_window"],
                 blob["by_scenario"]))
    print()
    print("expected calibration error, constructed prevalence %.5f"
          % headline["reliability_weighted"]["expected_calibration_error"])
    print("expected calibration error, natural prevalence     %.5f"
          % headline["reliability_natural"]["expected_calibration_error"])
    print("expected calibration error after the prior shift   %.5f"
          % headline["reliability_weighted_after_prior_shift"]["expected_calibration_error"])
    print("constructed test set", headline["constructed_test_set"])
    print("strict variant rows", strict_report["rows"],
          "PR-AUC", strict_report["pr_auc_attack_vs_benign"],
          "macro F1", strict_report["macro_f1_attack_classes"])
    print("wrote", png)
    print("wrote", os.path.join(MODEL_DIR, "metrics.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
