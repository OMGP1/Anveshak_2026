# Validation record: 8 September 2026

The requested signal improvements and high-effort training were implemented and exercised on Windows
10, Python 3.11.5, an Intel Core i5-13400F (10 cores / 16 logical processors). This remains a passive,
single-process prototype. No attack traffic was transmitted and no model was labelled perfect.

## Changes and evidence

| Requested area | Implemented and tested |
| --- | --- |
| UDP reflection/amplification | Requires observed UDP and a configured reflection service-port share. TCP download bytes cannot masquerade as UDP reflection. UDP ingress/egress asymmetry is reported with missing-return-path uncertainty. |
| Spoofed floods | Retains SYN/source-diversity detection and adds a suspected randomized-source UDP subtype. Source diversity is evidence of possible spoofing, not source attribution. |
| Window correctness | Core DDoS buckets close on ticks and replay EOF, use their actual one-second rate after quiet gaps, reject late packets, and keep separate evidence for different destinations. |
| DNS length and record types | Full query length, maximum label length and other name features are retained. TXT/NULL ratios and their baseline are now scoped to the source/domain pair, preventing cross-domain contamination. Long benign names, A/AAAA/MX/HTTPS and TXT/NULL tunnels are exercised. |
| Encrypted packet-size/timing sequences | Features refresh at 8 and 20 packets after the initial handshake assessment. The first artificial zero gap is excluded. The total sequence allocation is strictly bounded. UDP/443 sequences expose metadata; the TCP-trained model does not claim validated QUIC malware detection. |
| Model false positives | Model-only alerts require observed metadata for the predicted class and honor DNS/exfiltration suppressions. DNS-only vectors cannot produce encrypted-malware alarms. The Operations view reports withheld predictions and sequence assessments. |
| Windows execution | Native ingestion and inventory look for a Windows `.exe`, rather than attempting to execute the bundled macOS binary. POSIX permissions are tested separately from platform-independent signing/tamper behavior. |

`tests/test_priority_signals.py` covers the new traffic cases. `tests/test_training_quality.py`
checks purged temporal selection, prevalence weights, class-complete gates, string-label training,
calibration export parity, and independence from modified test labels/features. The pagination test
now inserts known records: pagination must not depend on extra detector alarms in an attack fixture.

## Completed high-effort training

Run: [`quality-20260908-validated`](../data/training-runs/quality-20260908-validated/).
It rebuilt **34,199 observations with 97 model features** from the corrected engine. The three new
UDP rule-context fields are retained for evaluation but excluded from the existing model feature
contract. Original serving artifacts and its historical dataset passed before/after SHA-256 checks.

- Six configurations, each allowed **1,200 boosting rounds**, learning rate **0.025**, two CPU threads.
- Validation used only the training partition, a temporal embargo, and removal of shared flow IDs.
- Selection used 70% macro attack PR-AUC and 30% pooled attack PR-AUC at the declared 0.1% prevalence.
- Validation selected **335 rounds**, 31 leaves, depth 8, minimum 20 child observations, L1 0.2,
  L2 2.0, 85% row sampling, 90% column sampling, and no class balancing. Seven classes produce
  **2,345 trees**. Other trials selected 745, 849, 398, 389 and 461 rounds.
- The **500-tree Isolation Forest** was fitted only on 6,118 benign training observations.
- Calibration used 4,417 separate observations, excluded training flows, and weighted the attack
  prevalence to **0.1%**. Exported probabilities matched the fitted calibrator exactly on calibration data.
- Test evaluation excluded flow IDs seen in either fitting **or calibration**. Test results did not
  select configurations or stopping rounds.

[LightGBM](https://lightgbm.readthedocs.io/en/stable/pythonapi/lightgbm.LGBMClassifier.html) uses
boosting rounds rather than neural-network epochs. More rounds are a search budget; validation
determines the retained model. Calibration uses a frozen fitted model as documented by
[scikit-learn](https://scikit-learn.org/1.7/modules/generated/sklearn.calibration.CalibratedClassifierCV.html).

## Same-row model comparison

Both models were evaluated on the **same 13,256 strict synthetic test observations**. Precision,
recall and macro F1 below use the declared 0.1% attack prevalence. These are model-argmax row metrics,
not live alert precision. Earlier model-card metrics used a different dataset.

| Metric | Serving model | New candidate |
| --- | ---: | ---: |
| Attack PR-AUC | 0.2745 | 0.3107 |
| Attack macro F1 | 0.2024 | 0.4528 |
| Benign observations predicted as attacks | 105 / 6,878 | 18 / 6,878 |
| Benign false-positive rate | 1.527% | 0.262% |

Candidate precision/recall: DDoS **99.97% / 100%**; scanning **100% / 61.97%**;
DNS **27.63% / 99.83%**; beaconing **25.32% / 70.22%**; exfiltration **2.54% / 72.02%**;
encrypted malware **5.41% / 50%**. Several classes still miss acceptance gates. There is no
independent labelled real-traffic holdout. **The candidate was rejected for promotion and the
serving model was preserved.**

Evidence: [comparison](../bench/model-comparison-20260908-final.json),
[selected trials](../data/training-runs/quality-20260908-validated/selection.json),
[candidate result and gate failures](../data/training-runs/quality-20260908-validated/result.json),
[training log](../data/training-runs/quality-20260908-validated/worker.log).

## False-positive challenges

Twenty-five offline benign cases cover TCP/UDP downloads, mixed DNS records, TXT-heavy traffic to
another domain, long CDN names, browser connection bursts, regular TLS/UDP sessions, and the bundled
benign PCAP. Each arm processes **51,350 packet observations**. Seeds diversify some cases; other
cases repeat deterministically. They are not independent real-world trials.

The first challenge run found **6 serving-model and 27 candidate false alerts**; deterministic
rules produced zero. This exposed class predictions without relevant observed evidence. After
the evidence/support and suppression fixes, **all three arms produced zero false alerts**.
These cases were used to debug the guards, so the zero is a regression result, not an untouched
generalization claim. No challenge case was used to fit, select or calibrate a model. Both completed
training runs produced the same LightGBM hash.

Evidence: [initial failures](../bench/false-positives-20260908.json),
[guarded regression](../bench/false-positives-guarded-20260908.json).
The evidence gates can also withhold true attacks lacking the required metadata; rule detections
remain active. Missing metadata is not proof of benign traffic.

## Performance and verification

Measured reports are collected in `bench/throughput-*-20260908.json`. Each performance run uses
all bundled PCAP scenarios configured, virtual-time replay, 30 seconds, a two-second warmup, one
numerical-library thread, extended transport monitors, and fsynced alert writes. Training and tests
were stopped during measurements. The deadline ends the model-enabled runs before all scenarios
finish, so these are timed-load measurements rather than matched full-corpus comparisons.

| 30-second configuration | Mean packets/s | Minimum one-second bucket | Empirical p99 ms | Alerts sampled | Peak Python RSS MB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rules only | 5,250.3 | 1,068.0 | 29.174 | 50 | 103.63 |
| Serving model | 2,546.9 | 1,292.4 | 13.945 | 19 | 219.32 |
| Candidate | 1,845.5 | 514.3 | 26.177 | 7 | 226.80 |

These small alert samples do not establish a stable tail-latency distribution. The unchanged
qualification policy **fails sustained rate and native input** for both model-enabled runs;
latency, memory, duration and durable-write checks pass. The required minimum bucket rate remains
3,000 packets/s. The Windows run uses Python PCAP input; a compatible Rust executable is absent.
See [qualification results](../bench/qualification-20260908.json).

Matched complete-corpus runs then processed **all 105,142 packets**, once each, with the same
configuration and durable writes:

| Complete corpus | Elapsed seconds | Mean packets/s | Empirical p99 ms | Alert samples | Peak RSS MB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Serving | 44.01 | 2,389 | 22.690 | 39 | 222.83 |
| Candidate | 49.28 | 2,134 | 51.033 | 44 | 233.29 |

The larger candidate is slower. It also exceeds the policy's **50 ms p99** limit in the complete
run, in addition to missing sustained rate and native input. No acceptance threshold was relaxed.
These are single measurements, not a statistically established performance difference or stable
tail distribution. Raw reports: [serving](../bench/throughput-serving-complete-20260908.json),
[candidate](../bench/throughput-candidate-complete-20260908.json),
[complete-run gates](../bench/qualification-complete-20260908.json).

Virtual-time latency covers engine ingestion through a schema-validated, durably written alert.
It excludes initial capture indexing, DuckDB, gateway, browser delivery and detection-window
accumulation. Looped synthetic captures can create artificial beacon patterns, so benchmark alert
counts are not accuracy evidence. Python source results do not meet a policy requiring Rust input.

## Final verification

- Full Python suite: **400 passed, 13 skipped in 89.49 seconds**.
  [JUnit results](../bench/tests-20260908.xml).
- Skips: 11 Rust differential cases without a Windows native binary; one POSIX permission-mode
  check that cannot attest Windows ACLs; one explicitly opt-in TLS/browser stack test.
- TypeScript and Vite production build passed: 615 modules, 649.69 kB main JavaScript before gzip.
- The final engine regenerated the candidate dataset **byte for byte**, including the last UDP
  evidence correction. [Feature reproducibility check](../bench/feature-recheck-20260908.json).
- Original serving artifacts and original dataset hashes remain unchanged. Final engine/API/training
  source hashes are saved with the candidate in `source-sha256.json`.
- `graphify update .` completed using AST extraction, with no LLM calls. JSON reports and documents
  were reviewed directly; AST extraction does not semantically index them.

## Reproduce

From `SIH2026_prototype/`:

```powershell
python -m training.high_effort
python -m training.compare data/training-runs/quality-20260908-validated --json bench/comparison-repeat.json
python -m bench.false_positives --model-dir data/training-runs/quality-20260908-validated --json bench/benign-repeat.json
python -m pytest -q tests
cd ui
npm run build
```

The dashboard's training button uses the upgraded search profile with its frozen input dataset.
`training.high_effort` additionally rebuilds features in a new directory before training. Neither
path promotes a candidate automatically.
