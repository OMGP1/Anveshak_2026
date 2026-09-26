# Validation record: 7 September 2026

This record distinguishes executable checks from untested deployment claims. Tests ran on the current macOS workspace. No external attack traffic was generated.

## Current: existing model preserved, coverage and resource fixes

This section supersedes earlier totals and performance results below; earlier artifacts are retained.

- Full standard suite: `python3 -m pytest -q tests` — **372 passed, 1 skipped in 55.25 s**. The skipped test is the opt-in localhost TLS/browser stack, exercised separately. New coverage comprises 32 extended-detection tests and four periodogram-budget tests.
- Go gateway: seven **uncached** race-enabled tests passed in 1.758 s; `go vet` passed. Rust: all five tests passed. The full Python suite includes incremental exact Rust/Python metadata parity for all 11 captures.
- TypeScript and Vite build passed: 615 modules, 649.19 kB main JavaScript before gzip. The updated UI distinguishes configured family coverage from exact method validation and exposes resource-abstention counters.
- Final real Chrome/TLS run passed in **59.68 s**: login, 47 coverage rows, `0/47` exact methods validated, both extended monitors enabled, generator inventory, beacon-budget counter rendering, and isolated candidate training. Zero uncaught JavaScript exceptions. TLS 1.3/WSS, role checks, direct-backend denial, two Rust-replay alerts and ledger verification passed. [Final report](../bench/final-stack-report.json), [viewport](../bench/final-dashboard.png). The candidate was rejected; serving artifacts stayed unchanged. The earlier 68.76-second browser run is also retained in `bench/extended-stack-report.json`.
- All 11 scenarios, 33 scenario files, 31,264 training rows and 97 features passed inventory verification. All nine problem-statement generator categories remain mapped; this does not mean nine real datasets exist. The verified iperf counter run remains 313 reported packets, not a packet capture.
- Graphify's AST-only update completed: 1,896 code nodes, 4,103 edges, 114 communities. It does not semantically index the updated documents or JSON reports; those were reviewed directly. No paid semantic extraction was run.

### Correctness and coverage changes

Completed rate windows are now evaluated by ticks and normal replay EOF. Quiet gaps cannot dilute
the rate, late packets cannot reopen finalized buckets, and idle ticks do not scan all retained
baselines. Configurable absolute limits cover cold start. SYN-attempt rate covers an additional
connection-churn signal without claiming completed connections. Seven service-port substitutions
of the same synthetic reflection shape pass; no MHDDoS payloads were executed or independently validated.

Different destinations' tick alerts are scored separately. Extended rule confidence cannot be
relabelled model-calibrated. Epoch-zero alert windows preserve their timestamps. Connection-
exhaustion text now states the uncertainty inherent in missing return traffic and retransmissions.

The resource audit found that `event_train` allocated bins proportional to total span / median gap.
A large silence could therefore exceed the process budget despite the 64-gap ring. It now refuses
more than 4,096 bins before grid allocation. The detector abstains with a counted suppression,
visible in Operations and `/api/metrics`, instead of resampling inputs or emitting a benign verdict.
Regular six-hour beacons retain the same 513-bin grid. Regression proof checks allocation refusal,
unchanged eligible-grid values, no fabricated feature vector, and dashboard-counter propagation.

### Fresh evaluation of the retained model

Loaded the existing bundle and reran `training.evaluate.evaluate_frame` on the strict synthetic
holdout, excluding flows seen in training. The entire returned report exactly matches
`metrics.json.test_strict_no_flow_seen_in_train`. No training or serving-artifact write occurred.

| Metric | Retained model |
|---|---:|
| Strict holdout rows | 11,731 |
| Constructed attack prevalence | 0.1% |
| Attack-versus-benign PR-AUC | 0.2086 |
| Attack macro F1 | 0.3795 |
| DDoS precision / recall | 100% / 100% |
| Scan precision / recall | 100% / 63.43% |
| DGA/DNS precision / recall | 29.19% / 99.95% |
| C2 precision / recall | 0.64% / 93.15% |
| Exfiltration precision / recall | 1.22% / 83.21% |
| Encrypted-malware precision / recall | 0.63% / 47.30% |

These are model-only frozen-dataset row metrics, not live alert accuracy or evaluation of the new
rules/resource abstentions. Poor precision for several classes remains a release blocker. The
encrypted class has only 74 strict test rows. No independent real holdout exists.

All five serving artifacts and the dataset retain their pre-change SHA-256 values:

```text
tier1_lgbm.txt         49bc0ddd90f93fc13b53c670085fd67bc6d73ec9aa350a1e1f114d197c47e252
tier1_meta.json       19600dbc5bc1496d49ba0e1240a5158e2303032faba02351729e1f0d69102d53
tier1_calibration.json 4b33b4494d1be13299999631da0c38868cbc2adb52e171a33f2168eba4c093b9
anomaly_iforest.pkl   552f8f577fd82f43d757a853fe013ea5da35c4dc2fcb6bc274717197635864ef
anomaly_meta.json     05d9970f3b21d1ac6a03d6c9f5e658b39b07bc579c32f26566568eda9538bcbc
dataset.parquet      cea4c5c89bcb7dd9f86cb8b08d1ce8d239367f7b7b363e7ba0af887c26a0a643
```

### Updated performance: memory gate passes; sustained-rate gate still fails

Same declared policy, same numerical-thread allocation, all models enabled and ledger fsync on.
No thresholds were reduced. These are sequential single runs, not a statistical speedup claim.

| Metric | Extended rules, before beacon cap | With beacon cap |
|---|---:|---:|
| Mean packets/s | 4,875 | 5,094 |
| Minimum post-warmup bucket packets/s | 738.6 | 1,397.5 |
| p5 bucket packets/s | 1,214.9 | 2,403.6 |
| p99 ingest-to-synced-alert | 27.646 ms | 28.738 ms |
| Peak Python RSS | 530.43 MB | 292.98 MB |
| Beacon windows skipped for resource budget | 0 | 24 |

The latest run processed 152,877 packets in 30.01 seconds. Its 100 alerts are **not** detection-
accuracy evidence: looping compresses 12,069 capture seconds into 30 seconds and can create
artificial beacon patterns. It excludes source indexing, detection-window accumulation, DuckDB,
Go/browser delivery, Rust-child RSS and container enforcement. Memory/latency gates pass; the
3,000 packets/s minimum-bucket gate still fails. No distributed detection or production certification.

Raw reports: [before cap](../bench/qualification-extended-rust.json),
[after cap](../bench/qualification-bounded-rust.json),
[current failed verdict](../bench/qualification-bounded-result.json).

```sh
# Choose new ledger/report paths for a fresh run; preserve existing evidence.
OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 MKL_NUM_THREADS=2 python3 bench/throughput.py \
  --source rust-pcap --scenario all --duration 30 --loop \
  --engine-config config/engine-production.json \
  --ledger .runtime/qualification-bounded-rust.jsonl --json bench/qualification-bounded-rust.json
python3 bench/check_qualification.py --report bench/qualification-bounded-rust.json \
  --output bench/qualification-bounded-result.json  # measured result: exit 1
```

External acceptance gaps remain: OS capture privilege for real PCAP, authorized representative
labels/independent holdout, target hardware/load and operational requirements, container-runtime
verification, and sustained-rate/soak qualification. The current implementation remains hardened
single-node prototype software, not “perfect,” universally accurate, or field-qualified.

## Rust/Go implementation round: latest evidence

The sections below this update preserve the earlier 314-test baseline. This update supersedes their statements that Go, browser testing, recovery, or real counter analysis were absent.

- Final standard suite: `python3 -m pytest -q tests` — **336 passed, 1 skipped in 79.36 s**. The one skip is the separately executed opt-in real localhost stack test, not an omitted Rust parity test.

- Rust: **5 unit tests passed**, release build passed. All 11 bundled PCAPs produced exactly equal `PacketMeta` records through Rust framing and the original Python reader, compared incrementally, including packet counts and timestamps.
- Go: TLS gateway implemented. **7 race-enabled tests** and `go vet` pass; macOS arm64 and Linux amd64 binaries compile. Tests cover roles, session expiry/logout, body/admission limits, origin/host rejection, credential stripping, audit tampering, unterminated records, and fail-closed audit writes.
- Full native-process stack: **passed** over certificate-validated TLS 1.3 and WSS. Viewer mutations and operator training are rejected; direct backend access returns 401. Rust SYN replay produces two persisted alerts and a valid ledger.
- Real Chrome: **passed** login, Operations navigation, all PS26145 generator names, 31,264 training rows, and clicking the enabled administrator training button. No uncaught JavaScript exceptions. Candidate training finishes `candidate_rejected` and preserves the serving model. Combined browser/stack run: **61.77 s**. Evidence: [stack report](../bench/stack-report.json), [candidate result](../bench/browser-training-result.json), [captured viewport](../bench/dashboard-qualified.png).
- The browser test caught a genuine login defect: `no-referrer` caused native form POSTs to send `Origin: null`. `same-origin` referrer policy fixes the valid form; opaque/foreign origins remain rejected. This behavior follows the [Fetch origin-header algorithm](https://fetch.spec.whatwg.org/#append-a-request-origin-header). The harness also had to select Chrome's page target rather than a background extension.
- Recovery tests cover a durable-ledger/missing-index write, repeated reconciliation, fresh-index reconstruction, conflicting index refusal, partial JSON refusal, backup/restore, and tampered snapshots. A missing final newline is also rejected before further appends, avoiding concatenated records after interrupted writes.
- TypeScript checks and Vite build pass: 615 modules, 648.18 kB main JavaScript output before gzip. No UI mock data was used by the browser check.
- Compose configuration validates. Docker daemon is unavailable; no container image build, runtime isolation, or cgroup behavior is claimed as tested.

### Real benign traffic, without claiming wire capture

Official iperf3 3.21 source was downloaded and checked against its published SHA-256 before building. A one-shot server and client ran only on localhost, UDP at 1 Mbps for three seconds. Run `431b278d4283459fad05b8a5abbd6610` reports **313 packets, 375,600 application bytes, three interval records, zero detections**. Raw JSON and normalized flow CSV fingerprints are verified and visible in Operations. [Raw report](../data/lab-runs/431b278d4283459fad05b8a5abbd6610/report.json).

These are measured application counters, not PCAP/NetFlow exports or independent attack evidence. One earlier run produced counters but its analysis writer failed; it remains as a partial run and is not advertised in the dashboard as verified. The successful rerun corrected the writer. OS BPF denial still blocks actual packet capture. The [official iperf documentation](https://software.es.net/iperf/invoking.html) describes the generator's JSON and interval reporting.

The user-supplied problem statement names nine generator/source categories, not downloadable datasets. All nine are mapped in Operations. Apart from the bounded iperf counters, actual tool-generated datasets are still absent. Eleven synthetic scenarios and 33 associated files remain present with their original reference hashes; the training parquet/serving booster remain unchanged.

### Defined throughput qualification: failed sustained-rate gate

Declared policy: [qualification-policy.json](../bench/qualification-policy.json). Target: 30 seconds of mixed synthetic traffic, all models enabled, at least 3,000 packets/s in **every** post-warmup one-second bucket, p99 ingest-to-synced-alert at most 50 ms, Python peak RSS at most 512 MB. Alert fsync is enabled. Two numerical threads; macOS 26.3.1 arm64, eight reported CPUs, CPython 3.13.2. This is not a wire-to-browser, Docker, long-soak, or hardware-diode test.

| Metric | Rust framing | Python reader |
|---|---:|---:|
| Duration | 30.00 s | 30.01 s |
| Mean packets/s | 5,038 | 5,026 |
| Minimum post-warmup bucket packets/s | 752.3 | 376.0 |
| p5 bucket packets/s | 1,278.1 | 1,401.3 |
| Mean flows/s | 1,085 | 1,084 |
| p99 ingest-to-synced-alert | 27.615 ms | 27.125 ms |
| Python peak RSS | 487.93 MB | 486.83 MB |

**Qualification fails the sustained-rate threshold.** Latency and Python-memory checks pass. No material overall speedup is established; a single pair of runs does not provide a statistical performance claim. Python detection, model inference, and periodic analysis dominate the remaining work. Do not market the mean rate as guaranteed sustained capacity.

The harness replays roughly 1.45 corpus passes at about 380× capture time. Repeated sessions can create artificial beacon patterns and extra tick cost; the 95 emitted alerts are not accuracy evidence. Source indexing, DuckDB insertion, gateway delivery, browser delivery, and detection-window accumulation are excluded. Rust-child memory is not part of the Python RSS metric. Raw measurements and machine-checkable failed verdict: [Rust](../bench/qualification-rust.json), [Python](../bench/qualification-python.json), [verdict](../bench/qualification-result.json).

```sh
OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 MKL_NUM_THREADS=2 python3 bench/throughput.py \
  --source rust-pcap --scenario all --duration 30 --loop \
  --engine-config config/engine-production.json \
  --ledger .runtime/qualification-rust.jsonl --json bench/qualification-rust.json
python3 bench/check_qualification.py  # exits 1 for the measured failed rate gate
```

Use a new ledger path when repeating a qualification run; preserve existing evidence. A pre-hardening 20-second exploratory run was replaced by these matched, sequential 30-second runs. No independent labelled holdout, automatic promotion, distributed detector scaling, or field certification has been manufactured to make a gate pass.

## Earlier baseline: passed

- `python3 -m pytest -q tests`: **314 passed in 53.44 seconds**.
- `node node_modules/typescript/bin/tsc --noEmit`: passed.
- `node node_modules/vite/bin/vite.js build`: passed; 615 modules transformed.
- `cargo test --offline --manifest-path native/pcap-audit/Cargo.toml`: **4 passed**. Tests include every truncated prefix of the fixture except the valid header-only boundary, invalid lengths, and invalid timestamps.
- `cargo build --offline --release --manifest-path native/pcap-audit/Cargo.toml`: passed. The final profile explicitly disables debug stripping because the installed Rust toolchain's optional stripping utility could not locate its LLVM library.
- Dataset audit: **11 scenarios, 33 scenario files, and a 31,264-row/97-feature parquet** present. All recorded PCAP and parquet hashes match. CSV structure/row counts and label identifiers/counts pass. The Rust structural auditor independently passes on all 11 PCAPs with matching packet counts.
- Dataset corruption regression: flipping one byte in a copied PCAP produces an integrity failure.
- Queue regression: 10,000 offered alert notifications leave exactly eight records in an eight-slot queue and request resynchronisation. The existing replay integration confirms stored alerts remain present under notification pressure.
- Flow CSV replay is accepted by the API and completes its benign fixture without a worker error.
- Training control rejects absent/wrong tokens and accepts the configured token; cross-origin mutations are rejected.
- Optional TCP, UDP, and ICMP rate alarms pass offline warmup, threshold, cooldown, and bounded-state tests.

## Executed training, correctly rejected

`python3 -m api.training_jobs` executed the quality profile in a separate process. Run `63688643ab6446bf9fb4f84d84f753f9` completed in approximately 42 seconds. Its result is `candidate_rejected`, not a training crash.

Strict temporal synthetic evaluation, reweighted to 0.1% attack prevalence, produced attack-versus-benign PR-AUC **0.1980**. Gates rejected low per-class precision, several recall failures, inadequate encrypted-class test support, and the missing independent real holdout. This evaluation is not an independently measured live alert precision result.

The serving booster and dataset still match their original fingerprints:

```text
tier1_lgbm.txt
49bc0ddd90f93fc13b53c670085fd67bc6d73ec9aa350a1e1f114d197c47e252

dataset.parquet
cea4c5c89bcb7dd9f86cb8b08d1ce8d239367f7b7b363e7ba0af887c26a0a643
```

Candidate artifacts remain under the ignored `data/training-runs/` directory for operator review. They are not activated. These two fingerprints do not claim that every ancillary file is covered by an independently trusted signed manifest.

## Blocked

`python3 -m tools.capture_loopback` initially failed under sandbox networking restrictions. An approved execution outside the sandbox reached tcpdump but failed at the OS capture device:

```text
tcpdump: lo0: You don't have permission to capture on that device
((cannot open BPF device) /dev/bpf0: Permission denied)
```

No real capture or real-traffic analysis result was produced. The implementation must be exercised by an operator with narrowly scoped OS capture access. Broad BPF permissions or a root-run API are not recommended.

## Not performed

- Browser-level interaction, accessibility, and screenshot tests.
- Production-hardware load, long-duration soak, fuzzing, or crash-recovery tests.
- Independent labelled real-data evaluation or per-MHDDoS-method capture validation.
- Go implementation or measured Rust acceleration of the Python detection path.
- Automatic model promotion, drift detection, trusted-label ingestion, or production deployment.

The test suite passing does not mean every byte or possible execution path has been proven correct. See [production readiness](PRODUCTION_READINESS.md) for release gates and [dashboard usage](../ui/README.md) for the current operational contract.
