# Model Card

See the [8 September candidate comparison](VALIDATION_2026-09-08.md) for stronger training on features
rebuilt from the corrected engine. The candidate remains isolated because it fails acceptance gates.
The historical metrics below use the original dataset; compare models on the same rows using
`python -m training.compare` before interpreting a change as an improvement.

## Current serving decision: retained

The five serving artifacts remain byte-for-byte unchanged (SHA-256 checked before/after the
extended-detection changes). A fresh strict evaluation on the existing 11,731-row synthetic
holdout exactly reproduces the recorded report: PR-AUC **0.2086**, attack-macro F1 **0.3795**, at
0.1% constructed attack prevalence. This does not validate real-world accuracy or the new rule
subtypes. Extended rate/SYN-attempt alarms retain uncalibrated rule-margin confidence, even if
the existing classifier agrees on the broad class. Candidate training never automatically replaces
this bundle. See [validation and remaining gates](VALIDATION_2026-09-07.md).

Requirement R13. This describes what the scoring layer is, what it was trained on, what it is for
and where it should not be trusted. The split protocol, the metrics and the ablation live in
`docs/TRAINING.md`; this file is the model itself.

Model id `tier1-lgbm-v1.0.0`. Dataset version `2026-09-07-scenario-replay-v1`. The artefact hash
and the dataset hash are recorded in `data/models/tier1_meta.json` and are returned by
`Engine.lineage()`, which `Engine.lineage_for(detection)` extends with the calibration flag and
the detector that fired. That object is what an alert's `x_model_lineage` is meant to carry, so an
alert can be traced to the exact booster that produced it.

A rules-only engine has no booster to name, so `Engine.lineage()` reports `model_id` `rules-only`
and `model_hash` `none` in that configuration, and `api/replay.py` falls back to a `rules-v0`
placeholder when the engine it was handed exposes no `lineage_for` at all. Both are the honest
absence of a lineage rather than a fake one, and both are distinguishable from a real hash at a
glance.

---

## 1. What the scoring layer is

Three components, in this order:

1. **A rule layer**, the six detectors in `engine/detect/`. Each is a deterministic online rule
   with published thresholds. It produces a `Detection` with a confidence derived from how far past
   its own thresholds the evidence sits: exactly 0.5 on the threshold, rising linearly to 1.0 when
   every clause is one full stated span past it, averaged over clauses. No model is involved and
   nothing is learned.

2. **Tier 1**, a LightGBM multiclass gradient-boosted tree ensemble over 97 numeric features,
   scoring the same feature vector the rules read. It emits a calibrated probability per class and
   the exact TreeSHAP contribution behind that prediction, from the same `predict` call.

3. **An anomaly layer**, a scikit-learn IsolationForest fitted on benign-labelled training rows
   only, reported as a percentile against the benign score distribution. It is a veto on the
   model-only path and a secondary signal carried in the alert context. It is never a reason to
   alert on its own.

A **promotion gate** sits between them and decides which observations are worth scoring beyond the
rule, so the model does not run on every packet.

## 2. Architecture and hyperparameters

### Tier 1, LightGBM

| Parameter | Value |
|---|---|
| objective | multiclass, 7 classes |
| classes | benign, volumetric-ddos, c2-beaconing, dga-dns-tunnelling, encrypted-malware, recon-scanning, data-exfiltration |
| n_estimators | 140 boosting rounds |
| trees in the artefact | 980, that is 140 rounds x 7 classes |
| num_leaves | 24 |
| max_depth | -1, unlimited, bounded by num_leaves |
| learning_rate | 0.09 |
| min_child_samples | 20 |
| subsample | 0.9, applied every round |
| colsample_bytree | 0.8 |
| reg_lambda | 1.0 |
| class_weight | balanced |
| random_state | 26145 |
| n_jobs | 1 |
| features | 97, every registry feature except the four context features |
| artefact | `data/models/tier1_lgbm.txt`, 2,213,959 bytes |
| model hash | `sha256:49bc0ddd90f93fc13b53c670085fd67bc6d73ec9aa350a1e1f114d197c47e252` |

Class weights are `balanced`, which resolves to the effective weights recorded in the meta file.
They range from 0.37 and 0.38 for the two most common classes to 23.6 for `encrypted-malware`,
which is the rarest. The weighting exists because the cost of a missed attack is not the cost of a
false alarm; it does not make the training set representative, and the test set is not weighted.

`n_jobs=1` is deliberate. The engine is a single-threaded streaming loop and a predictor that
spawns threads under it makes the latency percentiles unreadable.

### Calibration

Per-class isotonic regression, fitted by `sklearn.calibration.CalibratedClassifierCV` with
`cv="prefit"` on a **calibration slice that is temporally between the training slice and the test
slice**. The fitted curves are exported as breakpoints into
`data/models/tier1_calibration.json`, and the engine applies them with `numpy.interp`. That means
inference needs LightGBM and numpy but never scikit-learn, and the calibration in the engine is
provably the calibration that was fitted.

`x_confidence_calibrated` in an alert is true only when the confidence came through this path.
Rule-only alerts set it false, because a rule margin is not a probability and labelling it as one
would be a lie the schema is capable of telling.

### Anomaly layer, IsolationForest

| Parameter | Value |
|---|---|
| n_estimators | 120 |
| contamination | 0.01 |
| random_state | 26145 |
| training rows | 4904, benign-labelled training rows only |
| output | percentile of the observation's score against the stored benign score distribution |
| artefact | `data/models/anomaly_iforest.pkl` plus `anomaly_meta.json` |

Missing features are filled with the training median, and the medians ship with the model so the
fill is identical at inference.

The forest is scored only for observations the gate promoted or that the model wants to alert on
by itself, so it costs nothing on the ordinary path. Its one hard use is the veto described in
section 3: a model-only alert must sit above the median of the benign training distribution. That
is a stated principle, the median, rather than a threshold fitted on test data.

### Promotion gate

| Parameter | Value | Meaning |
|---|---|---|
| uncertain_low | 0.35 | below this the model is confidently benign |
| uncertain_high | 0.85 | above this the model is confident |
| qa_sample_rate | 0.005 | one observation in 200 is promoted regardless, as a quality sample |
| encrypted_prob_min | 0.10 | encrypted-malware probability that makes a candidate worth a second look |
| fingerprint_consistency_max | 0.60 | a JA4 and TCP fingerprint that disagree promote unconditionally |
| seed | 26145 | the QA sample is seeded, so a replay promotes the same rows every run |

The gate is versioned config. `PromotionGate.lineage()` is merged into `Engine.lineage()`, so it
reaches `x_model_lineage` on every alert, and its counters are in `Engine.stats()["gate"]`.
Promoting on low confidence, on encrypted candidates and on a fixed random sample is three
different reasons, and the alert says which one applied.

## 3. How a decision becomes an alert

| Situation | Alert source | Confidence | Evidence |
|---|---|---|---|
| rule fires, model disagrees or scores below 0.50 | `rule` | rule margin, `x_confidence_calibrated` false | the rule's own clauses, each with its weight |
| rule fires and the model agrees at 0.50 or above | `ensemble` | the calibrated model probability, `x_confidence_calibrated` true | exact TreeSHAP contributions, with the rule clauses kept in `context["rule_evidence"]` |
| no rule fires, and every condition below holds | `model` | the calibrated model probability, `x_confidence_calibrated` true | exact TreeSHAP contributions, at least two required |

The model-only path is the one that can produce noise, so it is gated four ways at once. The
calibrated probability must reach **0.99** on a non-benign class; the isolation forest must also
call the observation unusual, above the median of its benign training distribution; the subject
must not have produced a model-only alert in the last **600 seconds**, where the subject is the
destination for a destination-oriented class and the initiator otherwise; and at most **3**
model-only alerts per class are allowed inside one 600 second window. Everything the quota refuses
is counted in `Engine.stats()["model_alerts_rate_limited"]` rather than dropped silently.

Two of those four are worth defending. The 0.99 threshold is high because
`docs/TRAINING.md` section 6 measures the model's precision at realistic prevalence and it is poor
for three classes; a model that alerts alone should have to be nearly certain. The anomaly veto
uses the median rather than a tuned percentile, so no test-set number went into choosing it.

Evidence is never invented. `engine/explain.py` turns the top five contributions into a sentence,
and every number in that sentence is a feature value the engine actually computed.

## 4. Training data

The model is trained on features produced by replaying the eleven committed scenarios through the
engine itself, so the training rows and the production rows come from the same code path. There is
no separate feature implementation for training, which removes the most common source of
train-serve skew.

Every capture is synthetic, written packet by packet by `training/generate_scenarios.py`. No
attack tool was run. `docs/TRAINING.md` gives the row counts, the class prevalence in each split,
the split boundaries and the leakage accounting; `docs/DETECTION_CEILING.md` section 16 states what
synthetic training data does and does not license you to claim.

Labelling rule, quoted from the dataset manifest: a row is an attack row only when both endpoints
of its flow appear in one labelled attack window, one as an attacker and one as a victim.
Everything else is benign, including traffic from an infected host to a destination the label does
not name. That is stricter than labelling every packet from a compromised host as malicious, and it
is the reason the benign class contains traffic from hosts that are, elsewhere in the same capture,
attacking something.

## 5. Intended use

- Replay-driven detection in a passive monitoring enclave that cannot transmit.
- Producing structured, evidenced alerts for a human analyst to triage.
- A prototype demonstration against the SIH26145 problem statement.

## 6. Out of scope

- **Automated blocking or any enforcement action.** The enclave has no return path; a model that
  cannot be acted on automatically should not be wired to something that acts automatically.
- **Attribution.** The model names a threat class, not an actor. A spoofed source address is
  labelled as such in the alert and carries no attribution weight.
- **Deployment on a real link without retraining.** See section 7.
- **Any claim of comparability with published benchmark numbers.** Nothing here was evaluated on
  CIC-IDS2017, UNSW-NB15 or CTU-13, so no number in this repository is comparable to one from them.

## 7. Limitations, stated honestly

- **The model has only ever seen synthetic traffic.** It is trained on features from captures
  generated by a program that was written with the same understanding of these attacks as the
  detectors. That correlation flatters the results and cannot be removed by any split protocol.
  Real deployment means retraining on the target link's own traffic.
- **Precision at realistic prevalence is poor for three classes.** Measured at one attack
  observation per thousand benign ones, per-row precision is below 0.01 for beaconing, encrypted
  malware and exfiltration, while recall stays high. The numbers, and what they do and do not say
  about the shipped alert stream, are in `docs/TRAINING.md` section 6. This is the reason the
  model-only alert path is gated as hard as it is.
- **`encrypted-malware` is trained on very few rows**, the rarest class in the training slice by a
  wide margin, which is why its balanced class weight is the largest. Its metrics should be read as
  indicative of the pipeline working, not as a measurement of detection quality for that class.
- **Long-lived flows straddle the split boundary.** A beacon channel or a drip upload can be
  observed on both sides of the temporal cut. The manifest counts those rows rather than hiding
  them, and `training/evaluate.py` reports a strict variant with every one of them removed. Read
  the strict variant when in doubt.
- **Calibration transfers only to traffic like the calibration slice.** The isotonic curves were
  fitted on a temporal slice of the same synthetic captures. On a real link they would be wrong
  until refitted, and a miscalibrated confidence is worse than no confidence because it is trusted.
- **The model reads no context features.** `sampling_active`, `sampling_ratio`, `shedding_tier`
  and `initiator_is_lo` are excluded from the feature set on purpose, the first three so that the
  score does not learn to depend on the engine's own load and the fourth for the reason below.
  They are carried in the alert instead, for the reader to weigh.
- **An earlier artefact scored higher, and the difference was leakage.** It read
  `initiator_is_lo`, whether the flow initiator's address sorted lower than the responder's in the
  normalised flow key. That is an artifact of key ordering rather than a property of the traffic,
  and because attacker addresses are fixed within each synthetic capture it let the model key on
  address ranges instead of on behaviour. It was found by reading the SHAP evidence on a live
  alert, where that bookkeeping field was the second strongest contributor to the score. The
  field's registry group was changed to `context`, tier 1 was retrained on all eleven captures
  with the remaining 97 features, and every figure quoted here and in `docs/TRAINING.md` comes
  from the retrained artefact. Its headline PR-AUC and macro F1 are lower than the artefact it
  replaced, and those lower figures are the trustworthy ones.
- **Feature values can be missing.** LightGBM handles NaN natively and the IsolationForest fills
  with training medians. A row scored with most of its features missing still produces a
  probability, and nothing in the score says how much of the vector was present.
- **TreeSHAP explains the model, not the world.** A contribution says which feature moved this
  model's output, not which feature caused the attack. When the rule and the model agree, the rule
  clauses are kept alongside, so a reader can see both accounts.
- **The rule layer, not the model, carries most of the detection weight in this build.** Six of the
  detectors are deterministic rules with published thresholds. That is a design choice, defended in
  the ablation table in `docs/TRAINING.md`, not a placeholder for a model that never arrived.
