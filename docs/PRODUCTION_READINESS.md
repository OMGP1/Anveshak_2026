# Production readiness and acceptance record

The [8 September Windows validation](VALIDATION_2026-09-08.md) adds corrected signal handling,
stronger candidate training, false-positive regressions and new measurements. The Rust results
below remain the earlier macOS record. The newer candidate still fails accuracy acceptance gates.

## Verdict

**Hardened single-node implementation; not field-qualified for production.** Rust now validates and streams PCAP frames into the existing decoder. Go now supplies TLS, authenticated HTTP/WebSocket proxying, roles, bounded admission, and action auditing. Serving-model signature checks, durable ledger appends, index reconciliation, and backup/restore are implemented. Use the [deployment runbook](DEPLOYMENT.md), not the unauthenticated development server, for evaluation of this profile.

The target operating system, CPU/RAM allocation, sustained packet/flow rate, retention period, threat prevalence, recovery objectives, and real labelled evaluation datasets have not been supplied. No line-rate, perfect accuracy, universal attack coverage, or byte-perfect correctness claim is made.

The latest Rust + unchanged models + synced-ledger run measured 5,094 packets/s on average,
28.738 ms p99 ingest-to-synced-alert, and 292.98 MB peak Python RSS. It **failed** the declared
3,000 packets/s minimum-per-bucket gate (minimum 1,397.5). A newly enforced 4,096-bin beacon
analysis limit prevented oversized timing-grid allocation; 24 over-budget windows were explicitly
skipped in that looped synthetic run. This is a coverage/resource tradeoff, not evidence of improved
accuracy or line-rate scaling. See the [latest validation record](VALIDATION_2026-09-07.md).

## Delivered scope

| Requested area | Implemented and verifiable | Remaining acceptance requirement |
|---|---|---|
| Dashboard documentation | [Detailed guide](../ui/README.md), deployment runbook, all panels, provenance, training, recovery | Operator usability and accessibility evaluation |
| Real traffic | Actual bounded iperf3 localhost UDP counters: 313 packets, 375,600 application bytes, 3 intervals, zero detections; visible in Operations | This is not PCAP. macOS BPF permission blocked wire capture; representative authorized captures and labels remain absent |
| Rust/Go | Dependency-free Rust classic-PCAP framing/streaming; exact metadata parity on 11 captures. Go TLS/authenticated gateway and race-tested role/session/audit checks | Sustained target-hardware performance and security qualification; packet decode/inference still Python |
| Scaling | Hard-bounded notification queue, coalesced wakeups, 32-client cap, WebSocket send deadlines, cursor history, pending-window-only rate ticks, pre-allocation beacon grid limit with visible abstention counters | Sustained-rate gate still fails; target-load/concurrency tests, storage sizing, and native capture/flow sharding remain required |
| Verification | Python regressions, TypeScript/UI build, Rust malformed/truncated-input tests, Go race/vet, TLS stack tests, SHA-256 inventory, restore/tamper regressions | Long-running fuzzing, sanitizers, soak tests, broader fault injection, independent audit |
| Dataset completeness | All 11 bundled scenarios, 11 flow exports, 11 labels, parquet; dashboard maps every PS26145 generator and actual lab provenance | Generator names are not downloadable datasets. Actual Ostinato/TRex/hping3/Slowloris/dnscat2/iodine/DGArchive/C2 tool evidence remains missing |
| Click-to-run training | UI action and CLI, frozen inputs/settings, worker timeout, explicit quality gates | Independent real holdout, cost-aware search, per-site calibration, controlled artifact promotion |
| Additional attack families | Optional TCP/UDP/ICMP and SYN-attempt rate alarms, cold-start limits, completed-window/EOF checks, seven synthetic reflection service-port variants, runtime-aware 47-method inventory | Zero exact tool methods validated; representative labelled captures, site thresholds, and passive application telemetry for opaque Layer 7 methods |
| Automatic adaptation | Opt-in verified-digest watcher creates candidates | No pseudo-labels, no unattended model replacement, no implemented drift detector or trusted-label ingestion pipeline |
| Production operations | Go authentication/RBAC/TLS, trusted-header enforcement, signed model bundle, fsynced ledger, idempotent index recovery, offline backup/restore, Compose resource limits | Organization identity lifecycle, trusted signing/backup storage, retention, target-runtime verification, field operations |

## Deployment boundary

Run one API process. Do not run multiple Uvicorn workers: replay state, job state, and DuckDB are process-owned, not distributed. Direct development mode remains unauthenticated and loopback-only. Hardened mode requires a shared gateway secret on every HTTP/WebSocket request, checks roles, and verifies a separately trusted model signature before loading. Never publish the backend port; use the Go HTTPS gateway on the separate operator network.

The Go gateway validates exact hosts/origins, strips spoofed identity headers, and enforces viewer/operator/admin permissions with bounded sessions and connections. Its local token identities do not replace organization SSO/MFA and account lifecycle controls. Run the API without packet-capture privileges. Isolate capture in a separately permissioned process and enforce read-only transfer into detection. The provided traffic generator helper runs outside the enclave and accepts only localhost.

Candidate training uses a separate process, two numerical-library threads, a 1,800-second deadline, retained-run and input limits, and minimum free disk. It now searches six configurations, up to 1,200 boosting rounds, and fits 500 anomaly trees. The Compose profile additionally budgets API plus training to 2 CPUs/4 GiB and Go to 1 CPU/256 MiB. Container execution was not tested because Docker's daemon was unavailable. API and training still compete for that shared allocation; leave automatic training off during latency-critical operation until contention is measured.

## State and recovery limitations

Alert records are stored before WebSocket notification. The notification queue cannot grow past its configured capacity. A full queue can drop notifications; it does not intentionally remove stored alert records. The client refreshes its latest 400 records after a delivery gap. Full history is available using an insertion cursor.

The JSONL ledger and DuckDB remain separate writes. The ledger is now flushed and fsynced first. Startup verifies it and reconstructs missing index rows transactionally; repeated recovery preserves IDs and cursors. Conflicts and corrupted/truncated ledger tails fail closed without rewriting evidence. Tests simulate a missing index write, a fresh-index restore, a conflicting index, and corrupted evidence. Offline snapshot/restore is implemented and tested. These tests do not simulate every filesystem/power-loss failure. A process-owned signing key beside the ledger cannot prove integrity against a fully compromised host; archive checkpoints and protected backups off-host.

Serving-model SHA-256 manifests now have Ed25519 signatures checked against an external trust-key path before model load, including pickle deserialization. Read-only artifact mounts and a protected trust key are required. A signer can authorize malicious bytes: only sign independently reviewed artifacts. Dataset/reference hashes and local lab reports remain integrity fingerprints, not independent provenance signatures. A protected registry, signing-key lifecycle, and label review remain deployment responsibilities.

## Accuracy and model lifecycle

The bundle's feature dataset contains 12,557 training rows, 5,017 calibration rows, and 13,690 test rows. All are derived from local synthetic captures. Temporal embargoes and strict flow exclusion reduce some leakage; they do not make generator-related traffic independent.

The first quality candidate completed in approximately 42 seconds on this machine. Its strict synthetic attack-versus-benign PR-AUC at a constructed 0.1% attack prevalence was **0.1980**. Several per-class precision/recall gates failed. The independent real-holdout gate also failed. The candidate was rejected and the serving model remained unchanged. This is evidence against claiming that higher settings automatically improve operational detection.

The quality profile is a reproducible candidate budget, not a universal “best model” configuration. The [LightGBM tuning guide](https://lightgbm.readthedocs.io/en/stable/Parameters-Tuning.html) discusses complexity/overfitting tradeoffs. [Scikit-learn calibration guidance](https://scikit-learn.org/stable/modules/calibration.html) explains why calibration data must be separate from fitting data. Neither removes the need for representative evaluation.

The automatic watcher only creates candidates from a dataset matching its manifest. Dataset directories must remain administrator-owned. The watcher does not establish label authenticity. It does not train on its own predictions, detect distribution drift, fetch new data, edit reference hashes, lower gates, or promote candidates. It is disabled unless explicitly configured.

## Performance roadmap

1. Define target load, packet-size distribution, active-flow cardinality, attack mix, and latency/availability objectives.
2. Profile decode, shared detector state, scoring, explanation, serialization, persistence, and delivery separately on target hardware.
3. The Rust ingress now has exact differential tests against the bundled Python decoder. Compare measured throughput before changing defaults on another host; it accelerates neither feature extraction nor ML by itself.
4. Go now isolates operator networking and enforces connection/session/request bounds. It does not make stateful Python detectors parallel.
5. Partition by the detector's aggregation key. Five-tuple partitioning alone loses per-destination DDoS, per-source scan, and cross-session beacon evidence. Define merge semantics for sketches and model features before scaling workers.
6. Keep bounded queues at every process boundary. Establish an explicit loss/backpressure policy and expose counters. Stress storage as well as packet processing.
7. Run long-duration load and failure tests with fixed acceptance thresholds. Publish measured hardware-specific results, including errors, drops, p99 latency, memory, and recovery time.

Previously committed benchmarks in `bench/RESULTS.md` describe a different machine and earlier implementation. They were not rerun as production certification for this change.

## Next release gates

- An explicitly authorized real dataset, provenance, labels, and independent holdout.
- Per-class precision and recall at deployment prevalence with confidence intervals and a sufficient sample count.
- False positives on realistic benign TLS, DNS, OT, backup, and flash-crowd traffic.
- A reviewed ingress architecture with privilege separation and actual network-isolation enforcement.
- Organization-reviewed identity lifecycle, certificate issuance, and protected action-log checkpoints around the implemented authenticated gateway.
- Target-filesystem fault testing, protected keys, rotation/retention, and scheduled restore drills around the implemented recovery workflow.
- Load, fuzz, browser, and chaos-test evidence on the stated deployment target.

Failing any gate keeps the system in prototype status. A passing test suite proves only the cases executed.
