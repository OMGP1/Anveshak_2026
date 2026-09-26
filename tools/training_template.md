# Training and Validation

Requirement R15. The problem statement asks for documentation of the training and validation
approach, and the audit of the team's earlier work called this the weakest area, so it is written
here in full: how a row is made, how the split avoids leakage, what the class prevalence actually
is in each split, which metrics are reported and why, how the confidence is calibrated, and what
the model adds over the rules.

Generated from `tools/training_template.md` and the artefacts in `data/models/` by
`tools/gen_training_md.py`. Every number below is read out of `dataset_manifest.json` and
`metrics.json` when the file is generated, so retraining and regenerating cannot leave the
documentation quoting a model that no longer exists. Edit the template, not this file.

    python tools/gen_training_md.py

## Serving model preservation

The existing serving bundle is retained. The latest strict evaluation rerun exactly matches its
recorded report: 11,731 synthetic holdout rows, PR-AUC 0.2086 and attack-macro F1 0.3795 at
0.1% constructed attack prevalence. These are frozen-dataset model metrics, not validation of
the new extended rules or real-world attack detection. See [current validation](VALIDATION_2026-09-07.md).

Use `python3 -m api.training_jobs` or the dashboard to create isolated candidates without replacing
the serving artifacts. The extended rate alarms remain uncalibrated rule evidence.

The legacy reproduction commands below **overwrite dataset/model artifacts**. Run them only in a
separate lab copy when intentionally rebuilding a baseline; do not use them to operate the retained serving bundle:

```
python training/build_dataset.py    # replay the corpus, write dataset.parquet and the manifest
python training/train_tier1.py      # fit LightGBM, fit isotonic calibration, fit the anomaly forest
python training/evaluate.py         # write metrics.json, the reliability data and the ablation
```

---

## 1. How a row is made

There is no separate feature implementation for training. `training/build_dataset.py` replays each
committed capture through `engine.pipeline.Engine`, the same class the API runs, with the model and
anomaly layers switched off so the scoring layer cannot see its own output. Whenever a detector's
feature set refreshes, the engine hands the feature vector to a sink, and that vector becomes one
row.

The consequence worth stating: the features in the training set are produced by the code that will
produce them at inference, byte for byte. The most common source of train-serve skew in a NIDS,
a research pipeline computing features one way and the deployed engine computing them another, is
absent by construction rather than by discipline.

Each row carries the 97 model features, the flow identity, the timestamp, the fraction of its own
capture that had elapsed, the rule verdict at that moment, and the label.

## 2. Labelling

A row is an attack row only when both endpoints of its flow appear in one labelled attack window,
one as an attacker and one as a victim. Everything else is benign, including traffic from an
infected host to a destination the label does not name.

That is deliberately strict. Labelling every packet from a compromised host as malicious is the
easy choice and it teaches the model to recognise hosts rather than behaviour, which then reports
excellent numbers that mean nothing. Under this rule the benign class contains ordinary traffic
from hosts that are, elsewhere in the same capture, attacking something, and the model has to tell
the two apart.

## 3. The split is temporal, and why that matters more than anything else here

Rows are placed by the fraction of their own capture's timeline that had elapsed when the engine
produced them. Nothing is shuffled and no row is ever assigned at random.

| Slice | Session fraction |
|---|---|
| train | 0.00 to 0.42 |
| embargo, discarded | 0.42 to 0.45 |
| calibration | 0.45 to 0.53 |
| embargo, discarded | 0.53 to 0.56 |
| test | 0.56 to 1.00 |

Random splitting is the single most common flaw in published NIDS results. An attack burst
produces hundreds of near-identical observations within a few seconds; split them at random and
the same burst lands on both sides of the cut, so the model is tested on what is effectively the
training data and the reported accuracy becomes fiction. A temporal split makes the test question
the honest one: having seen the first part of this session, does the model recognise the rest?

The two embargo bands exist because a purely adjacent split still leaks through the engine's own
windows. Several features are computed over 60 second and 300 second windows, so an observation
taken immediately after the boundary shares state with observations immediately before it. The
bands discard those rows rather than count them.

The split is per capture session, not global. Each of the eleven scenarios contributes its own early
part to training and its own late part to test, so no class is present in only one slice.

## 4. Leakage controls, the leakage that was removed, and the leakage that remains

What is controlled:

- **Temporal placement with embargo bands**, as above.
- **One feature implementation**, the engine's, for both training and inference.
- **No target-derived features.** Nothing in the 97 features is computed from the label, from the
  scenario id, or from the labels file. Two obvious candidates, `scenario` and `subtype`, are
  metadata columns in the parquet and are not in `MODEL_FEATURES`.
- **The four context features are excluded** from the model input, so the score cannot learn to
  depend on the engine's own load state or on the bookkeeping of the flow key.
- **The QA sample in the promotion gate is seeded**, so a replay promotes the same rows every run
  and an evaluation is repeatable.

### One leaking feature was found and removed

An earlier tier-1 artefact scored higher than this one, and the difference was leakage. It carried
a feature called `initiator_is_lo`: whether the flow initiator's address sorted lower than the
responder's in the normalised flow key. That is an artifact of key ordering rather than a property
of the traffic, and because each synthetic capture gives its attacker a fixed address, the field
let the model key on address ranges instead of on behaviour.

It was found by reading the SHAP evidence on a live alert, where that bookkeeping field came out as
the second strongest contributor to the score. A field that carries no threat signal has no
business sitting second. Its registry group was changed to `context`, which excludes it from the
model input, and tier 1 was retrained on all eleven captures with the remaining 97 features.

The PR-AUC and macro F1 in section 6 are lower than the ones the retired artefact produced. They
are the trustworthy ones, because the earlier ones were partly measuring the model's ability to
recognise addresses rather than attacks. `initiator_is_lo` is still computed and still documented
in `docs/FEATURES.md`, carried as context on the alert and never scored. Leakage control is what
requirement R15 asks for, and this is that control catching something in this repository's own
numbers rather than in someone else's.

What is not fully controlled, and is counted instead of hidden. Some flows outlive the split
boundary: a C2 beacon channel and a slow-drip upload are single flows that run for the length of
the capture, so the same flow identity appears in both the training and the test slice. The
manifest reports this explicitly under `leakage`, with the number of flow identities on both
sides and the number of test rows belonging to a flow also seen in training.

These are not duplicated samples of one burst. They are different observations, minutes apart, of
a long-lived channel, which is exactly the case the detector exists for. Removing them entirely
would delete the beaconing and exfiltration classes from the test set. `training/evaluate.py`
therefore reports a **strict variant** with every row from a straddling flow removed, alongside the
full test set, and both are in `metrics.json`. The two do disagree here, in the direction that
needs explaining rather than the direction that flatters; section 6 says why.

## 5. Class prevalence, stated explicitly

This is the number the audit said gets left out, so it is here twice: once as counts, once as a
percentage, for all three slices.

<!-- PREVALENCE_TABLE -->

Two honest observations about these figures.

**The training prevalence is not realistic and is not meant to be.** The corpus is eleven scenarios,
ten of which contain an attack, replayed end to end; attack observations are therefore common in
it. Training uses `class_weight="balanced"` on top of that, so the effective weights range from
0.37 for the commonest class to 23.6 for `encrypted-malware`. That is the standard treatment for
an imbalanced objective and it is applied to the training slice only.

**The test prevalence is also not realistic, and this is the honest limitation of the evaluation.**
On a production link the attack-to-benign ratio is somewhere between 1 in 1000 and 1 in 10000. This
test set is nowhere near that, because it is built from the same ten attack scenarios. Precision
measured at this prevalence is optimistic by roughly the ratio between the two, and the number that
would degrade is precision, not recall: at a fixed false-positive rate, multiplying the benign
population by a thousand multiplies the false alarms by a thousand while the true positives stay
where they are.

So the optimistic number is not the one this document leads with. `training/evaluate.py`
recomputes every headline figure at a constructed prevalence of one attack observation per thousand
benign ones, by keeping every test row and giving each benign row an importance weight, and then
checks that arithmetic against a test set physically built at the same ratio. The natural-prevalence
and the constructed-prevalence figures are both in `metrics.json` and both are in the next section,
side by side, because the difference between them is the point.

## 6. Metrics, and why PR-AUC is the headline

<!-- METRICS_SECTION -->

## 7. Calibration

The confidence attached to a model-sourced alert is a calibrated probability, not a raw softmax
output. Per-class isotonic regression is fitted by `sklearn.calibration.CalibratedClassifierCV`
with a frozen fitted estimator on the calibration slice, which sits temporally after training and before test,
so calibration is never fitted on data the model was trained on and never on data it is evaluated
on.

The fitted curves are exported as breakpoints into `data/models/tier1_calibration.json` and applied
in the engine with `numpy.interp`. Inference therefore needs LightGBM and numpy, never
scikit-learn, and the curve the engine applies is provably the curve that was fitted.

`x_confidence_calibrated` is true in an alert only when the confidence came through this path. A
rule-only alert sets it false, because its confidence is a margin past a threshold and not a
probability, and a schema that can express the difference should express it.

The reliability data is in `metrics.json` under `reliability_natural`, `reliability_weighted` and
`reliability_weighted_after_prior_shift`: for each of twelve confidence bins,
the mean predicted probability and the observed accuracy in that bin, before and after
calibration.

## 8. Ablation: rules, model, and both

<!-- ABLATION_SECTION -->

## 9. What this evaluation does not establish

- **It is all synthetic.** The captures were generated by a program written with the same
  understanding of these attacks as the detectors, so the detectors are partly measured against
  their own assumptions. See `docs/DETECTION_CEILING.md` section 16.
- **No public benchmark.** Nothing here was run against CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15 or
  CTU-13, so no number in this document is comparable to a published one. Adding one is the single
  highest-value extension to this work.
- **`encrypted-malware` is measured on very few rows.** Its metrics are indicative of the pipeline
  working, not a measurement of detection quality for that class.
- **The test prevalence is not production prevalence.** Section 6 reports every headline figure at
  a constructed one in a thousand, which is exact arithmetic over the measured rows and is checked
  against a physically constructed set. But one in a thousand is itself an assumption about a link
  nobody here has measured. Read the figures as "what this model would score if the mix were that",
  not as "what it scores on a real link".


## Expanded training and calibration search

Run the stronger optional presets from the project root:

```powershell
python -m training.high_effort --profile config/training-intensive.json
python -m training.high_effort --profile config/training-expanded.json
```

The intensive preset searches 18 LightGBM configurations, up to 2,000 rounds each,
with isotonic/sigmoid calibration on either raw margins or class probabilities.
Selection scores calibrated macro attack F1 and macro attack PR-AUC equally at the
assumed 0.1% attack prevalence. Three chronological, flow-purged blocks inside the
training partition fit the model, fit each trial calibrator, and compare candidates.
The final calibration partition and test partition never choose parameters or methods. A configuration that drops any attack class is ineligible when an alternative retains all classes; selection fails if no option retains them all.

The expanded preset additionally generates two separate capture-seed sets for training
and a third for final calibration, and compares six model configurations with the same
four calibration choices. The original test observations and labels are checked for exact equality.
Additional captures use session-local flow identifiers and cannot cross assigned roles.
More seeds diversify existing synthetic templates; they do not establish accuracy on new
malware families or real traffic. Existing serving files are preserved and acceptance gates
remain enforced. Each run saves its profile, selection details, logs and gate failures.

After freezing a candidate, evaluate it against an earlier model on another set of seeds:

```powershell
python -m training.seed_holdout --output data/evaluation-runs/new-seeds --candidate data/training-runs/YOUR-RUN --baseline data/training-runs/quality-20260908-validated
```

The holdout command rejects seeds used by either model's fitting or calibration corpus.
It records all model-bundle hashes before generating captures. It never trains a model.
All labels and difficult observations remain in reported metrics; no threshold is tuned
against this evaluation. Reusing a holdout for development must be disclosed.

For a repeat fit on an existing verified corpus, pass `--dataset-from data/training-runs/SOURCE` to `training.high_effort`. This copies only the dataset and manifest into the new run and skips generation/augmentation. The original capture directory remains the source of provenance.
