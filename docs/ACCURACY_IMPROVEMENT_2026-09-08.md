# Accuracy improvement: 8 September 2026

The final candidate improves macro attack F1 from **0.4528 to 0.6771** on the same
13,256 original test observations, and from **0.5256 to 0.7551** on 34,142 observations
from reserved capture seeds. These are model classification metrics at an assumed
0.1% attack prevalence, not live alert precision or proven real-world accuracy.
The baseline here is the previously trained `quality-20260908-validated` candidate.
The serving model was preserved. **The new candidate still fails acceptance gates.**

## What changed

- Added training-only selection of calibration method (isotonic/sigmoid) and input
  (raw margins/class probabilities), with equal weight on calibrated macro attack
  F1 and macro attack PR-AUC. Model fitting, trial calibration and validation use
  three chronological blocks inside the training partition, with flow overlap purged.
- Added a class-coverage requirement: an option that drops any attack class cannot
  beat one retaining all classes. If every option drops a class, selection fails.
  This does not replace or relax the existing 95% precision / 90% recall promotion gates.
- Exported sigmoid coefficients and retained isotonic breakpoints. Batch evaluation
  and live scoring share the same calibration implementation. Exports are checked
  against sklearn; extreme margins, scalar/batch parity and test-data independence
  have regression tests.
- Added isolated capture generation with distinct seeds for training and calibration.
  Augmentation keeps original test values and labels exactly unchanged, namespaces
  flow IDs by capture, and checks that an added capture cannot cross its assigned role.
- Added reserved-seed evaluation that rejects seeds used by any compared model's
  fitting/calibration corpus and records model-bundle hashes before generating captures.
- Corrected the standalone evaluation command to exclude calibration flows as well
  as training flows from its strict test subset.

[Scikit-learn's calibration documentation](https://scikit-learn.org/stable/modules/calibration.html)
discusses the sample-size sensitivity of isotonic calibration and alternatives such
as sigmoid calibration. The method here was chosen by measured training-validation
performance, not by assuming either method always wins.

## Completed training

The intensive run compared 18 model configurations with four calibration choices,
allowing up to 2,000 rounds per configuration. An expanded run compared another six
configurations using additional sessions. Its initial selection reduced false positives
by dropping classes and was rejected. The final fit reused those recorded training-only
validation results after adding the class-coverage requirement. That rejected experiment
and its metrics are retained in the comparison artifact.

The final corpus has **137,801 observations and 97 model features**. Training uses
**83,183** observations; final calibration uses **38,679** after purging original training
flows. There are 22 added training captures and 11 separate calibration captures.
Training contains 569 encrypted-malware observations (previously 104) and 1,754
exfiltration observations (previously 327). Calibration contains 255 encrypted-malware
observations (previously 26).

The selected model has **691 boosting rounds / 4,837 trees**, 15 leaves, depth 6,
minimum 20 child observations, learning rate 0.025, L1 0.2, L2 5, 85% row sampling,
90% feature sampling, and no class balancing. Isotonic calibration on raw margins
reproduced sklearn exactly on the calibration data. The 500-tree Isolation Forest
uses only the 35,654 benign training observations.

Run: [`coverage-20260908-validated`](../data/training-runs/coverage-20260908-validated/).
The directory name means validation was executed; it does not mean its gates passed.
Its [profile](../data/training-runs/coverage-20260908-validated/profile.json) records
the source search and selection basis. The dataset was reused from
[`expanded-20260908-sessions`](../data/training-runs/expanded-20260908-sessions/),
which retains the generated capture files and augmentation log.

## Same original test observations

All 13,256 strict test observations, feature values, labels and ordering were checked
for exact equality against the prior candidate's test subset. This test has been examined
during development; it is not a new untouched holdout. Difficult early observations
remain included. Precision/recall/F1 below use the declared 0.1% attack prevalence.

| Class | Prior F1 | New precision | New recall | New F1 |
| --- | ---: | ---: | ---: | ---: |
| C2 beaconing | 37.22% | 100.00% | 48.46% | 65.28% |
| Data exfiltration | 4.91% | 2.83% | 64.29% | 5.42% |
| DNS tunnelling / DGA | 43.28% | 48.84% | 99.89% | 65.61% |
| Encrypted malware | 9.77% | 100.00% | 53.77% | 69.94% |
| Scanning | 76.52% | 100.00% | 100.00% | 100.00% |
| DDoS | 99.98% | 100.00% | 100.00% | 100.00% |
| Macro over attack classes | 45.28% | | | 67.71% |

Benign observations predicted as attacks fell from **18 to 10 out of 6,878**
(0.262% to 0.145%). Beaconing recall fell from 70.22% to 48.46%, and exfiltration
recall from 72.02% to 64.29%; higher F1 does not mean every metric improved.

## Reserved capture seeds

All compared models were fitted before these 11 captures were generated. The seed
offset 910000 is distinct from the original catalogue and augmentation offsets
610000, 620000 and 630000. No fitting, calibration or threshold adjustment used these
new observations. The captures vary existing generator templates; they are not new
malware families, independent implementations or real network traffic.

| Class | Prior F1 | New precision | New recall | New F1 |
| --- | ---: | ---: | ---: | ---: |
| C2 beaconing | 7.20% | 22.98% | 38.27% | 28.71% |
| Data exfiltration | 76.37% | 99.77% | 63.53% | 77.63% |
| DNS tunnelling / DGA | 44.21% | 73.56% | 99.97% | 84.76% |
| Encrypted malware | 7.59% | 100.00% | 51.71% | 68.17% |
| Scanning | 85.47% | 100.00% | 99.40% | 99.70% |
| DDoS | 94.49% | 89.70% | 98.99% | 94.11% |
| Macro over attack classes | 52.56% | | | 75.51% |

Attack-vs-benign PR-AUC improved **0.3269 to 0.8357**. Benign false predictions fell
**34 to 4 out of 14,270** (0.238% to 0.028%). DDoS F1 regressed slightly. Beaconing
recall fell from 61.27% to 38.27%; exfiltration recall fell from 64.41% to 63.53%.
The large exfiltration-precision difference between this corpus and the original test
is a warning about generalization. The new-seed result does not erase the original
test's exfiltration failure.

Evidence: [complete comparison, including intermediate failures](../bench/model-improvement-20260908.json),
[reserved-seed manifest and results](../data/evaluation-runs/seed-holdout-20260908/result.json).

## Verification and remaining limits

- **416 tests passed, 13 skipped**: [test report](../bench/tests-accuracy-final-20260908.xml).
  Skips remain 11 native-ingestion parity cases without a Windows binary, one POSIX
  permissions assertion, and one opt-in TLS stack integration case.
- Rules, serving and candidate each produced **zero alerts** across 25 benign
  regression cases / 51,350 packet observations per arm. These cases were used to
  develop the existing guards; zero is a regression result, not untouched validation.
  [False-alert report after the scoring optimization](../bench/false-positives-accuracy-final-20260908.json).
- Serving-model artifact hashes remained unchanged. No candidate was promoted.
- A training-only audit found 11 identical-feature groups containing conflicting
  labels. At least 31 errors are unavoidable for a deterministic classifier on those
  original input vectors alone. Additional discriminating information or corrected
  label context is needed; more rounds cannot separate identical inputs.
  [Evidence audit](../bench/training-evidence-audit-20260908.json).
- The final candidate still fails class precision/recall gates, and no independent
  labelled real-traffic holdout is available. No result supports calling it perfect.

Reproduce the expanded search with `python -m training.high_effort --profile
config/training-expanded.json`. The final recorded refit used `config/training-coverage.json`
with `--dataset-from data/training-runs/expanded-20260908-sessions`. Each output directory
must be new. [Training instructions](TRAINING.md).

## Exact anomaly scoring optimization

The broader candidate sends more uncertain observations to the anomaly layer: 9,031
versus 1,522 in the earlier complete replay. Repeating sklearn's per-tree dispatch for
one observation at a time made the first new-candidate benchmark slower (628 packets/s).
The engine now traverses all fitted isolation trees together using NumPy index arrays.
It preserves sklearn's float32 input comparisons, leaf corrections and sequential
floating-point accumulation, and falls back to sklearn for unsupported layouts/inputs.
No trained trees, anomaly percentiles or detection thresholds were changed.

All **34,142 reserved observations produced exactly identical raw anomaly scores and
percentiles**, with maximum raw difference zero. Additional tests cover feature subsampling,
one/two-sample trees, repeated observations, missing values and overflow fallback. The
cache adds 1,782,088 bytes for this forest, included in reported model memory.
[Parity evidence](../bench/anomaly-parity-20260908.json).
The implementation follows the scoring semantics of the installed sklearn 1.7.2
[Isolation Forest](https://scikit-learn.org/1.7/modules/generated/sklearn.ensemble.IsolationForest.html).

## Final performance measurement

The final complete replay processed all **105,142 packets** in **75.35 seconds**:
**1,395.4 packets/s mean**, minimum post-warmup one-second rate **604.9 packets/s**,
**26.855 ms p99** ingest-to-synced-alert latency, and **239.10 MB** peak Python RSS.
It produced the same 40 alerts as the slower pre-optimization candidate. Every detection
payload matched exactly after excluding latency and hash-chain fields.

The optimization improved this candidate from 628 to 1,395 packets/s and reduced
p99 from 55.206 to 26.855 ms. The earlier smaller candidate's historical result was
2,133.5 packets/s; increased accuracy still carries a throughput cost here. These are
single runs on the local Windows/i5-13400F machine, with training/tests stopped during
the final benchmark. Forty alerts are insufficient for a stable extreme-tail estimate.

The replay includes Python PCAP ingestion, model/anomaly decisions, schema validation
and ledger fsync. It excludes initial capture indexing, DuckDB writes, gateway/browser
delivery and the capture-time accumulation needed to recognize a behavior. The existing
qualification policy still fails its sustained-throughput requirement and required native
source; latency and memory pass. No performance threshold was relaxed.

[Final benchmark](../bench/throughput-accuracy-final-20260908.json),
[qualification result](../bench/qualification-accuracy-final-20260908.json),
[alert payload parity](../bench/anomaly-alert-parity-20260908.json).
