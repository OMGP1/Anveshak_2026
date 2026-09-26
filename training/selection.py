"""Bounded model search using only a purged temporal partition of training data."""
from __future__ import annotations

import time
import warnings

import numpy as np
import pandas as pd


def temporal_validation(frame: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    fitting, validation = [], []
    for _, part in frame.groupby("scenario", sort=True):
        stamps = np.sort(part.ts_ns.unique())
        if len(stamps) < 5:
            raise ValueError("Each scenario needs at least five training timestamps")
        # A 2% timestamp embargo precedes the last 20% used for validation.
        fit_end = stamps[max(1, int(len(stamps) * 0.78))]
        val_start = stamps[max(2, int(len(stamps) * 0.80))]
        fitting.append(part[part.ts_ns < fit_end])
        validation.append(part[part.ts_ns >= val_start])
    fit, valid = pd.concat(fitting), pd.concat(validation)
    valid = valid[~valid.flow_id.isin(set(fit.flow_id))]
    expected = set(frame.label)
    if set(fit.label) != expected or set(valid.label) != expected:
        raise ValueError("Purged internal temporal validation must contain every class")
    return fit, valid


def prevalence_weights(labels, target: float) -> np.ndarray:
    if not 0 < target < 1:
        raise ValueError("Target attack prevalence must lie strictly between zero and one")
    attack = np.asarray(labels) != "benign"
    if not attack.any() or attack.all():
        raise ValueError("Prevalence weighting requires both benign and attack observations")
    weight = np.where(attack, target / attack.mean(), (1 - target) / (~attack).mean())
    return weight / weight.mean()


def selection_rank(row):
    """Dropping a class cannot beat a candidate that retains every attack class."""
    covered = all(value["recall"] > 0 for value in row["per_class"].values())
    return covered, row["selection_score"], -row["selected_rounds"]


def select_parameters(frame, features, parameters, candidates, patience, target=0.001,
                      calibration_candidates=None):
    import lightgbm as lgb
    from sklearn.metrics import average_precision_score, precision_recall_fscore_support

    fit, valid = temporal_validation(frame)
    inner_calibration = None
    if calibration_candidates:
        # Three chronological blocks entirely inside training: fitting, calibration,
        # validation. A calibrator must never be scored on the rows that fitted it.
        fit, inner_calibration = temporal_validation(fit)
        valid = valid[~valid.flow_id.isin(set(inner_calibration.flow_id))]
        if set(valid.label) != set(frame.label):
            raise ValueError("Purged calibration-selection validation must contain every class")
    trials = []
    weight = prevalence_weights(valid.label, target)
    for number, changes in enumerate(candidates or [{}]):
        config = {**parameters, **changes}
        model = lgb.LGBMClassifier(**config)
        started = time.perf_counter()
        # LightGBM 4.7's eval_X/eval_y classifier path does not encode string
        # validation labels. The supported legacy pair handles class encoding.
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="The argument 'eval_set' is deprecated")
            model.fit(fit[features], fit.label,
                      eval_set=[(valid[features], valid.label)], eval_metric="multi_logloss",
                      callbacks=[lgb.early_stopping(patience, verbose=False)] if patience else [])
        rounds = int(model.best_iteration_ or model.n_iter_)
        options = []
        for calibration in calibration_candidates or [None]:
            if calibration is None:
                probability = model.predict_proba(valid[features])
            else:
                from training.train_tier1 import fit_calibrator
                calibrated = fit_calibrator(model, inner_calibration[features], inner_calibration.label,
                    prevalence_weights(inner_calibration.label, target), **calibration)
                probability = calibrated.predict_proba(valid[features])
            aps = {str(name): float(average_precision_score(valid.label == name, probability[:, i],
                                                            sample_weight=weight))
                   for i, name in enumerate(model.classes_) if name != "benign"}
            attack_score = 1 - probability[:, list(model.classes_).index("benign")]
            pooled = float(average_precision_score(valid.label != "benign", attack_score, sample_weight=weight))
            prediction = model.classes_[probability.argmax(axis=1)]
            attack_classes = [name for name in model.classes_ if name != "benign"]
            precision, recall, f1, _ = precision_recall_fscore_support(valid.label, prediction,
                labels=attack_classes, sample_weight=weight, zero_division=0)
            # Calibrated F1 exposes threshold errors hidden by a good ranking score.
            score = (0.5 * float(f1.mean()) + 0.5 * float(np.mean(list(aps.values())))) if calibration else (
                0.7 * float(np.mean(list(aps.values()))) + 0.3 * pooled)
            options.append({"trial": number, "parameters": config, "selected_rounds": rounds,
                "calibration": calibration, "selection_score": score,
                "macro_attack_f1": float(f1.mean()), "macro_attack_pr_auc": float(np.mean(list(aps.values()))),
                "attack_pr_auc": pooled, "per_class_pr_auc": aps,
                "per_class": {str(name): {"precision": float(p), "recall": float(r), "f1": float(f)}
                              for name, p, r, f in zip(attack_classes, precision, recall, f1)}})
        choice = max(options, key=selection_rank if calibration_candidates else lambda row: row["selection_score"])
        score = choice["selection_score"]
        trials.append({**choice, "calibration_options": options if calibration_candidates else [],
                       "seconds": round(time.perf_counter() - started, 3)})
        print(f"trial {number + 1}/{len(candidates or [{}])}: rounds={rounds}, validation score={score:.5f}",
              flush=True)
    best = max(trials, key=selection_rank if calibration_candidates else
               lambda row: (row["selection_score"], -row["selected_rounds"]))
    if calibration_candidates and not selection_rank(best)[0]:
        raise ValueError("No calibration candidate retains recall for every attack class")
    selected = {**best["parameters"], "n_estimators": best["selected_rounds"]}
    return selected, {"selected_trial": best["trial"], "trials": trials,
                      "selected_calibration": best["calibration"] or {},
                      "selection_requires_all_attack_classes": bool(calibration_candidates),
                      "fit_rows": len(fit), "validation_rows": len(valid),
                      "inner_calibration_rows": len(inner_calibration) if inner_calibration is not None else 0,
                      "inner_calibration_class_counts": inner_calibration.label.value_counts().to_dict()
                          if inner_calibration is not None else {},
                      "fit_calibration_shared_flows": len(set(fit.flow_id) & set(inner_calibration.flow_id))
                          if inner_calibration is not None else 0,
                      "calibration_validation_shared_flows": len(set(inner_calibration.flow_id) & set(valid.flow_id))
                          if inner_calibration is not None else 0,
                      "shared_flow_ids": len(set(fit.flow_id) & set(valid.flow_id)),
                      "target_prevalence": target,
                      "selection_basis": ("0.5 calibrated macro attack F1 + 0.5 macro attack PR-AUC; "
                                          "three purged temporal blocks inside training; final calibration and test unused"
                                          if calibration_candidates else
                                          "0.7 macro attack PR-AUC + 0.3 pooled attack PR-AUC; "
                                          "purged temporal training partition only; calibration and test unused")}
