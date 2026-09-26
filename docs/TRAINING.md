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

| Class | Train | Train % | Calibration | Calibration % | Test | Test % |
|---|---|---|---|---|---|---|
| benign | 4904 | 39.05 | 1113 | 22.18 | 5580 | 40.76 |
| volumetric-ddos | 4732 | 37.68 | 3103 | 61.85 | 4634 | 33.85 |
| c2-beaconing | 737 | 5.87 | 155 | 3.09 | 853 | 6.23 |
| dga-dns-tunnelling | 1604 | 12.77 | 484 | 9.65 | 1878 | 13.72 |
| encrypted-malware | 76 | 0.61 | 18 | 0.36 | 74 | 0.54 |
| recon-scanning | 221 | 1.76 | 93 | 1.85 | 391 | 2.86 |
| data-exfiltration | 283 | 2.25 | 51 | 1.02 | 280 | 2.05 |
| **Total rows** | **12557** | **100** | **5017** | **100** | **13690** | **100** |

Attack rows are 60.9 percent of the training slice, 77.8 percent of the calibration
slice and 59.2 percent of the test slice. The embargo bands discarded the rows
between the slices, so the three counts do not sum to the 31264 rows in the dataset.

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

**PR-AUC is the headline because prevalence is low.** ROC-AUC divides by the benign
population when it computes the false-positive rate. Multiply the benign population
by a thousand and the false-positive rate barely moves, so ROC-AUC barely moves,
while the thing the analyst actually experiences, how many of the alerts in front of
them are real, collapses. Precision-recall works in the space the analyst lives in:
precision is true positives over everything raised, and it degrades exactly as fast
as the false alarms multiply. ROC-AUC is computed internally and deliberately not
published as a headline.

The corpus is attack heavy, so every headline figure is reported at a **constructed**
**prevalence of one attack observation per thousand benign ones**. The primary
estimator keeps every test row and gives each benign row an importance weight of
1452.0, which is exact arithmetic and keeps full support for the per-class numbers.
The natural prevalence of the test slice is 0.5924, that is 59.2 percent attack rows,
which is not a link anyone monitors.

### Headline, tier 1 scored on every test row

| Measure | Value |
|---|---|
| test rows | 13690 |
| natural test prevalence | 0.5924 |
| constructed prevalence | 0.0010 |
| PR-AUC, attack against benign, at 1 in 1000 | **0.1657** |
| PR-AUC, attack against benign, at the natural prevalence | 0.9933 |
| macro F1 over the six attack classes, at 1 in 1000 | 0.3454 |
| expected calibration error, at 1 in 1000 | 0.03793 |

**The gap between 0.9933 and 0.1657 is the whole reason this document states
prevalence.** The same model, the same rows, the same predictions: only the assumed
mix changed. A submission that reported the first number without saying what it was
measured on would be reporting 0.99 for a system that scores 0.17 where it matters.

### Per class, at the constructed prevalence of 1 in 1000

| Class | Precision | Recall | F1 | Test rows |
|---|---|---|---|---|
| benign | 1.0000 | 0.9774 | 0.9886 | 5580 |
| volumetric-ddos | 0.7614 | 1.0000 | 0.8646 | 4634 |
| c2-beaconing | 0.0056 | 0.9426 | 0.0111 | 853 |
| dga-dns-tunnelling | 0.2442 | 0.9995 | 0.3926 | 1878 |
| encrypted-malware | 0.0048 | 0.4730 | 0.0095 | 74 |
| recon-scanning | 1.0000 | 0.6343 | 0.7762 | 391 |
| data-exfiltration | 0.0094 | 0.8321 | 0.0185 | 280 |

One against rest PR-AUC per attack class, same prevalence:

| Class | PR-AUC |
|---|---|
| volumetric-ddos | 0.9852 |
| c2-beaconing | 0.0326 |
| dga-dns-tunnelling | 0.8745 |
| encrypted-malware | 0.4067 |
| recon-scanning | 0.6382 |
| data-exfiltration | 0.0092 |

### The same rows at the natural test prevalence, for contrast

| Class | Precision | Recall | F1 | Test rows |
|---|---|---|---|---|
| benign | 0.9562 | 0.9774 | 0.9667 | 5580 |
| volumetric-ddos | 0.9998 | 1.0000 | 0.9999 | 4634 |
| c2-beaconing | 0.8627 | 0.9426 | 0.9008 | 853 |
| dga-dns-tunnelling | 0.9979 | 0.9995 | 0.9987 | 1878 |
| encrypted-malware | 0.8750 | 0.4730 | 0.6140 | 74 |
| recon-scanning | 1.0000 | 0.6343 | 0.7762 | 391 |
| data-exfiltration | 0.9320 | 0.8321 | 0.8792 | 280 |

### Reading these numbers honestly

Recall holds up and precision does not. At one attack per thousand, three classes
have precision below 0.01: a handful of benign rows misclassified becomes a flood
once the benign population is weighted up by 1452. That is a real weakness of the
tier-1 model and it is stated rather than buried.

Two things it is not. First, it is **not the alert rate of the shipped system**.
This table scores the model's argmax on every observation the engine produced. The
engine does not alert per observation: a rule has to fire, the model has to agree,
cooldowns apply per subject, and the benign baseline capture raises zero alerts end
to end with all six detectors running. Second, it is not a measurement of the
detectors, which are deterministic rules with published thresholds and are measured
in the ablation below.

The classes that do hold precision, volumetric DDoS and reconnaissance, are the ones
whose features are unambiguous per observation. The classes that do not, beaconing
and exfiltration, are the ones whose evidence is a pattern across many observations,
which a per-row classifier cannot see and a stateful detector can. That is an
argument for the architecture, not an excuse for the number.

### The strict variant

Every test row belonging to a flow that was also seen in training is removed, which
leaves 11731 of the 13690 rows in the full test slice.

| Measure | Full test | Strict |
|---|---|---|
| rows | 13690 | 11731 |
| PR-AUC at 1 in 1000 | 0.1657 | 0.2086 |
| macro F1 over attack classes | 0.3454 | 0.3795 |

The strict variant scores higher, not lower, which is worth a sentence. Removing
straddling flows removes the long-lived beacon and drip channels, and those are
exactly the classes the per-row model is worst at. The strict number is cleaner
evidence of leakage control and a weaker sample of the hard classes; read both.

### The physical cross-check

Importance weighting is arithmetic, so it is checked against a test set physically
built at the same ratio: keep all 5580 benign rows, draw 6 attack rows, repeat 400
times with a fixed seed. Measured prevalence 0.001074, PR-AUC 0.1804, standard deviation
0.0368, range 0.0614 to 0.2222.

That agrees with the weighted estimate of 0.1657. Only 6 attack rows survive a draw
at this ratio, so per-class precision and recall are not estimable from it and only
the pooled figure is reported. That is why the weighted estimator is primary and
this one is the cross-check rather than the other way round.

### Reliability

The reliability diagram is at `data/models/reliability.png`, drawn at both
prevalences, and the bins behind it are in `metrics.json` under
`reliability_weighted` and `reliability_natural`. Expected calibration error at the
constructed prevalence is 0.03793 over all twelve bins.

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

Three arms, all at the constructed prevalence of 1 in 1000.

**Rules only** is the deterministic detector verdict, held for 300 seconds against
both endpoints of the flow it named. The hold is not a fudge, it is what makes the
comparison fair: a rule raises one alert per episode and then goes quiet on its own
cooldown, so scoring the bare fire against every row would report a recall near zero
for a detector that in fact caught the attack.

**Model only** is the argmax of the calibrated tier-1 probability, with nothing else
consulted.

**Both** is what the engine actually does: a held rule names the class, and the
model names a class by itself only when it clears the 0.99 `model_alert_confidence`
threshold and the benign-only isolation forest also calls the row unusual.

| Arm | Macro F1 over the six attack classes |
|---|---|
| rules only | 0.2600 |
| model only | 0.3454 |
| both, as shipped | 0.3700 |

Per class F1:

| Class | Rules only | Model only | Both |
|---|---|---|---|
| volumetric-ddos | 0.0000 | 0.8646 | 0.5480 |
| c2-beaconing | 0.0271 | 0.0111 | 0.0549 |
| dga-dns-tunnelling | 0.0090 | 0.3926 | 0.0114 |
| encrypted-malware | 0.6667 | 0.0095 | 0.6903 |
| recon-scanning | 0.8432 | 0.7762 | 0.8986 |
| data-exfiltration | 0.0140 | 0.0185 | 0.0165 |

Per class precision, which is where the arms differ most:

| Class | Rules only | Model only | Both |
|---|---|---|---|
| volumetric-ddos | 0.0000 | 0.7614 | 1.0000 |
| c2-beaconing | 0.0143 | 0.0056 | 0.0290 |
| dga-dns-tunnelling | 0.0045 | 0.2442 | 0.0057 |
| encrypted-malware | 1.0000 | 0.0048 | 1.0000 |
| recon-scanning | 1.0000 | 1.0000 | 1.0000 |
| data-exfiltration | 0.0072 | 0.0094 | 0.0084 |

One artefact of the hold is worth naming before anyone else finds it. Holding a
verdict against both endpoints means a DNS rule that names a host and its resolver
marks the resolver too, so every other host querying that resolver inside the window
counts as a rules positive. The rules-only precision for the DNS class is understated
by that spill. It is left in rather than special-cased, because the fix would be a
scoring rule written to flatter the table.

### The same question asked operationally

Row-level F1 answers "was this observation labelled correctly". An analyst asks
"was the attack found, and how much noise came with it". This table counts, over
the whole capture rather than the test slice alone, how many observations inside
each labelled attack window each arm assigned to the right class, and how many
positives each arm raised outside every labelled window.

| Scenario | Window | Rows in window | Rules only | Model only | Both |
|---|---|---|---|---|---|
| syn_flood | syn-flood-spoofed-source | 7913 | 6795 | 7732 | 6797 |
| udp_reflection | udp-reflection-amplification | 1381 | 1168 | 1223 | 1213 |
| slowloris | slowloris-connection-exhaustion | 4260 | 2610 | 3497 | 3065 |
| beacon_jitter | jittered-https-beacon | 3058 | 442 | 1693 | 870 |
| dga_burst | dga-high-entropy | 2131 | 1539 | 1400 | 1561 |
| dga_burst | dga-dictionary | 2149 | 1605 | 1406 | 1605 |
| dns_tunnel | dns-tunnel-txt-null | 3330 | 2582 | 2482 | 2628 |
| ja4_spoof | ja4-tcp-fingerprint-disagreement | 1383 | 159 | 116 | 160 |
| port_scan | vertical-scan-fast | 53 | 16 | 29 | 23 |
| port_scan | vertical-scan-slow | 1737 | 581 | 540 | 608 |
| port_scan | horizontal-sweep | 858 | 322 | 230 | 322 |
| exfil_drip | slow-drip-https-upload | 1147 | 107 | 216 | 147 |
| exfil_bulk | bulk-https-upload | 587 | 156 | 343 | 320 |

| Arm | Positives outside every labelled window, of 4178 such rows | Of those, in the benign capture |
|---|---|---|
| rules only | 81 | 0 |
| model only | 52 | 17 |
| both, as shipped | 93 | 0 |

The last column is the one to look at. The rule arm raises **nothing at all** in
the benign capture. The model arm raises 17 rows there, in a capture where
nothing is labelled and nothing should fire.

Both units in this table are per-observation verdicts, not emitted alerts. The
engine emits far fewer alerts than it produces observations, because a rule has
to fire and a cooldown has to have elapsed; at the alert level a parametrised
test asserts that no alert in any of the eleven scenarios falls outside a labelled
attack window.

### What the ablation says

Every arm finds every attack window: no cell in the episode table is zero. They
differ in what they cost and in what they can explain.

The model covers more of the windows whose evidence accumulates slowly, the beacon
and the drip, because the rule waits for enough samples before it will commit. The
rules cover more of the DNS windows, and more of the two slower scan windows,
while the model covers more of the one-second sweep that is over almost before
it starts. Macro
F1 is close across the arms, 0.2600 rules only against 0.3454 model only, which is the
honest summary: on this corpus the shipped combination of both scores highest.

So the choice between them is not made on F1. It is made on what an enclave whose
output is evidence can defend. A rule alert states its clauses, its thresholds and
how far past them the evidence sat, and it fires nothing at all on benign traffic. A
model alert states a probability and a set of contributions. The shipped
configuration therefore lets a rule name the class whenever one fires, and lets the
model speak alone only above 0.99 confidence with the anomaly layer agreeing. The
numbers for the alternative are in the tables above, so the choice can be argued
with on the evidence rather than taken on faith.

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
