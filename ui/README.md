# Dashboard guide

This dashboard is the operator interface for the SIH26145 passive network-threat detection prototype. It shows metadata-derived detections, their supporting evidence, replay progress, runtime measurements, dataset integrity, and model-training candidates.

It is not a firewall. Replaying a file does not transmit its packets onto the network. The engine does not probe observed addresses, decrypt application traffic, block connections, or consult an online reputation service. The browser communicates with the local API; this is separate from the monitored network.

## Current readiness

This is a hardened development prototype, **not a certified production deployment**. The bundled scenarios are synthetic. The supplied feature dataset has 31,264 rows and 97 model inputs. The quality-training workflow can reject a model even when its training accuracy looks high. Read [production readiness](../docs/PRODUCTION_READINESS.md) before any deployment beyond an isolated local machine.

For the Rust + Go deployment, follow [the deployment runbook](../docs/DEPLOYMENT.md). It adds authenticated HTTPS/WSS, viewer/operator/admin roles, signed serving artifacts, and recoverable persistence. The direct local development startup below deliberately retains its original unauthenticated loopback-only mode.

## Install and start

Run these commands from `SIH2026_prototype/`. Use Python 3.11 or later and a Node version compatible with the pinned Vite package; the installed package's `engines` field is authoritative. Python 3.13 and the current local Node installation were used for this change's validation.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cd ui
npm ci
npm run build
cd ..
python -m api.main
```

Open `http://127.0.0.1:8000/?mock=0`. The API serves the compiled dashboard from `ui/dist/`. Keep the process running while using the page. Stop it with Ctrl+C.

For UI development, start `python -m api.main` in one terminal, then run `npm run dev` from `ui/` in another. Open `http://localhost:5173/?mock=0`. Vite proxies API requests to port 8000. Do not expose the development server publicly.

On Windows, activate the environment with `.venv\Scripts\activate`, use `python` instead of `python3`, and run the commands individually. GNU Make is optional; every operation also has a Python module command.

### Real API versus mock display

`?mock=1` enables browser-generated demonstration data. The selection persists in local storage. `?mock=0` clears it. A visible **mock data** badge means alerts and measurements are not engine results. Dataset auditing, method coverage, and training controls do not contact the real backend while mock mode is active.

## Analyst view

### Replay a scenario

1. Select **Input**: `PCAP packets`, `Rust PCAP ingest`, or `Flow CSV (reduced visibility)`.
2. Select one of the 11 bundled scenarios.
3. Choose the clock mode and speed.
4. Press **Start**. Use **Pause**, **Resume**, or **Stop** as needed.
5. Select an alert to keep its evidence visible. Otherwise the panel follows the newest alert.

**Realtime** follows capture timing at the selected multiplier. Long gaps can be shortened by the replay clock's maximum sleep. **Virtual** consumes input as quickly as the pipeline can process it. The speed selector does not throttle virtual replay. Neither mode performs a live network attack.

PCAP input contains packet timing and visible DNS/TLS handshake metadata. Flow CSV input contains aggregated counts and flags. It cannot reconstruct missing ClientHello fields, domain names, or packet-size sequences. Results from the two inputs are therefore not interchangeable. The existing replay counters count ingested records for flow input; packet-oriented captions are primarily intended for PCAP runs.

The scenarios are `benign`, `syn_flood`, `udp_reflection`, `slowloris`, `beacon_jitter`, `dga_burst`, `dns_tunnel`, `ja4_spoof`, `port_scan`, `exfil_drip`, and `exfil_bulk`. Scenario names describe what the local generator emulates, not tools that were actually run.

### Read alerts

The threat strip filters by class. The queue shows recent alerts and their severity. The evidence panel shows the description, confidence, detector source, measured feature values, flow or aggregate subject, capture window, model lineage, and MITRE reference. **Raw STIX** exposes the complete record.

Treat confidence labels carefully:

- `rule` evidence consists of threshold margins. These are not calibrated probabilities or TreeSHAP values, even though the common record field is named `shap`.
- `model` or `ensemble` evidence can contain exact TreeSHAP contributions to raw class margins. These are not percentage changes in probability.
- A calibrated probability reflects the calibration dataset's distribution. A different attack prevalence can make the same score misleading.
- A suspicious JA4/TCP pairing is a lead, not proof of malware. Legitimate software combinations can disagree with a small reference table.

The browser retains up to 400 alerts and 240 metric samples. These limits do not delete stored alerts. Reconnects and notification-overflow signals refresh the latest stored history. This refresh may include earlier runs. Replaying identical detections reuses stable alert IDs; the store deduplicates them.

For complete stored history, page `GET /api/alert-history?after=0&limit=200`. Pass the returned `cursor` as the next `after` value while `has_more` is true. This insertion cursor handles equal capture timestamps correctly. Store resets invalidate old cursors.

`GET /api/alerts` returns the latest insertions first. Capture timestamps may be out of order when replaying another scenario or closing an earlier detection window; a `since` filter still refers to the alert's capture timestamp.

## Operations view

### Dataset inventory

**Verify files** reads every bundled PCAP, CSV export, label file, and the feature parquet. Expand a scenario to inspect file paths, byte sizes, and SHA-256 fingerprints.

- PCAP hashes are compared against `data/scenarios/index.json`.
- The parquet hash is compared against `data/models/dataset_manifest.json`.
- CSV sizes, column order, and row counts are checked.
- Label scenario IDs and packet counts are checked.
- CSV and label fingerprints are marked `measured_only`: the original bundle does not contain reference hashes for them. A new fingerprint cannot retrospectively prove authenticity.
- When built, the Rust auditor independently checks PCAP framing, timestamps, truncation, lengths, and packet counts.

The PS26145 generator table covers iperf3, Ostinato, TRex, hping3, Slowloris, dnscat2, iodine, published DGA/DGArchive, and sandboxed C2 timing. These are generators/examples, not download links. The table maps each to its bundled synthetic scenarios and explicitly marks missing actual tool-generated evidence. Public benchmarks mentioned in planning documents are not silently downloaded or represented as present.

The lab section shows verified raw iperf3 counters, normalized interval records, byte/packet totals, and analysis results when a completed run exists under `data/lab-runs/`. The verified local run reported 313 UDP packets and 375,600 application bytes, with zero alerts. This is real benign localhost traffic—not a PCAP, external attack validation, or independent holdout.

### Train a quality candidate

Enable the operator action before starting the API:

```sh
export SIH_OPERATOR_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
python3 -m api.main
```

Keep the generated token private. Retrieve it from your own terminal when needed; do not commit it or send it in a URL. Enter the token in the **Operator token** field, verify the dataset, and click **Train quality candidate**. The field stays in page memory and is not saved in browser storage.

The same workflow without a browser is:

```sh
python3 -m api.training_jobs
# or: make train-candidate PY=python3
```

The workflow copies the trusted feature dataset, its manifest, and the profile into a private run directory. It verifies hashes, feature order, class presence, and chronological splits. It starts one separate training process. Outputs live under `data/training-runs/<run-id>/`:

- `status.json`: job state and timing;
- `profile.json`: the frozen training settings;
- `worker.log`: diagnostics;
- model and calibration artifacts;
- `result.json`: strict synthetic evaluation and promotion-gate findings.

The quality profile searches six configurations with up to 1,200 boosting rounds and 100-round early stopping. Selection uses a temporal training subset with an embargo and shared flows removed. It refits the selected settings, calibrates on a separate slice with training flows removed, and evaluates test flows absent from both training and calibration. Calibration weights target a stated 0.1% attack prevalence. The anomaly forest uses 500 trees fitted only on benign training rows. Dashboard jobs use two CPU threads, a 1,800-second deadline, a 256 MiB input-file limit, at least 1 GiB free disk, and at most 20 retained run directories.

To rebuild features from the current engine before training, run `python -m training.high_effort`. This creates a separate dataset and candidate directory and verifies that serving artifacts remain unchanged. The dashboard workflow continues to use its frozen input dataset. The [8 September validation record](../docs/VALIDATION_2026-09-08.md) records the latest completed run.

States are `idle`, `running`, `failed`, `candidate_rejected`, and `candidate_ready`. A rejected candidate is a successful safety outcome, not necessarily a crashed job. Inspect its gate failures. No candidate replaces `data/models/`, even if gates pass. The original serving model and dataset remain unchanged.

The current bundle cannot pass the production gate requiring an independent labelled real-traffic holdout. Raising tree counts does not resolve that missing evidence. The legacy `make train` command still rebuilds and overwrites the original artifacts; prefer `train-candidate` for safe experimentation.

### Controlled automatic retraining

Set `SIH_AUTO_TRAIN=1` with an operator token before API startup. The watcher checks once per minute. A newly observed dataset digest must match its administrator-maintained manifest before a candidate can start. An initial verified digest also starts one candidate. Each digest is attempted at most once per process lifetime; restarting the API can attempt it again.

This is automatic **candidate training**, not autonomous labelling, drift-proof adaptation, or automatic deployment. Captured traffic is never labelled benign merely because no alert fired. The watcher does not trust arbitrary captures, repair manifests, lower quality gates, or replace the serving model. Approved real labels, drift evaluation, independent validation, and rollback remain operator responsibilities.

### Extended attack coverage

Development proxy note: Vite may choose a port such as 5176 when 5173 is occupied.
Use the URL Vite prints. Both `/api` and `/ws` are proxied on that same origin, with
the browser-facing Host preserved for the API's origin checks. Do not disable the
origin guard or stop unrelated projects to resolve a port conflict. An HTTP 403 means
the API answered but refused an action; it does not mean the engine is offline.

Expand the method inventory to see all 47 names registered in the reviewed MHDDoS source. Its headline advertises 57; the inventory follows the actual method sets. Status distinguishes synthetic-tested families, partial metadata coverage, experimental rate-only coverage, and methods that cannot be distinguished from the available input. The panel separately shows whether the loaded profile/input enables the family detector and states that **0/47 exact tool methods have been validated**. It refreshes availability every three seconds; flow CSV input disables packet-timing alarms. Catalogue presence does not mean full detection support.

To enable additional TCP/UDP/ICMP rate alarms:

```sh
SIH_ENGINE_CONFIG=config/engine-extended.json python3 -m api.main
```

The baseline branch requires 10 occupied one-second windows, at least 2,500 packets/s, and a six-sigma deviation. The profile also enables a 25,000 packets/s absolute branch that works at cold start. TCP SYN attempts have a separate 100/s baseline floor and 1,000/s absolute limit. SYN retransmissions are not distinct or completed connections. These are starting settings, not validated site thresholds.

State is bounded to 4,096 destination/protocol buckets with a 60-second cooldown. Completed windows are checked by ticks or later packets; normal EOF also closes the final second. Late observations older than the event-time watermark are skipped and counted. Tune against your authorized link's benign traffic. Low-rate attacks can be missed and legitimate flash crowds can trigger alarms. The monitor is disabled without a profile and skips flow exports. Its additional alerts retain rule-based, uncalibrated confidence; the existing serving model is not retrained or replaced.

See [coverage details](../docs/ATTACK_COVERAGE.md). No attack tool is installed or executed by this feature.

### Runtime panels

**Memory** reports engine-estimated structures and process RSS. It is not an enforced process limit. On macOS, the fallback RSS measurement is peak resident memory rather than current memory.

The panel also shows skipped beacon windows, late rate packets, and evicted rate baselines.
Beacon event trains are capped at 4,096 bins before allocation. A long gap can exceed that budget;
the engine abstains and increments the counter rather than silently assigning benign confidence.
These counters are available in `/api/metrics` under `analysis_limits`.

**Latency** and **stage timing** describe pipeline measurements. The current API's alert latency starts after its replay wait and excludes network capture, queueing before that point, browser delivery, and time needed to accumulate a detection window. Do not present it as universal wire-to-dashboard latency.

**Queue** shows a hard-bounded notification queue. Metrics are shed first, then status, then alert notifications. Alert records are appended to storage before notification. An overflow requests browser resynchronisation. At most one pending queue-wakeup callback is scheduled; the callback list does not grow once per packet. Slow WebSocket sends have deadlines and client count is capped at 32.

**Ledger** reports chain integrity and signed-anchor validity separately. Both must pass. A valid chain does not prove the host or signing key was uncompromised. Keep an independently trusted public key and off-host anchors for stronger evidence guarantees.

**Coverage** estimates metadata visibility from flow completeness and protocol conditions. It is not a measured classifier-accuracy percentage. Missing SNI alone does not prove ECH.

## Real traffic capture

Actual benign generator evidence can be produced outside the enclave with an installed iperf3:

```sh
python3 -m tools.lab_iperf --binary /absolute/path/to/iperf3
```

This helper accepts no target address. Both endpoints are bound to localhost, with 1 Mbps for three seconds. It saves iperf JSON, three one-second flow-counter intervals, SHA-256 fingerprints, and a detection analysis. It does not invent missing packet flags or TLS/DNS metadata. Refresh **Verify files** to display completed results. A failed/partial run is not shown as verified evidence.

The safe local smoke command captures only eight benign UDP datagrams exchanged between two sockets created by the test:

```sh
python3 -m tools.capture_loopback
```

It filters by both ephemeral ports on `lo0` (macOS) or `lo` (Linux), limits the capture length, and stops on a short deadline. It writes a private PCAP and analysis report under `data/captures/`. It does not observe a general interface or create an attack.

Capture requires OS packet-capture permission. This workspace's macOS BPF device denied access during validation, so **no real capture result is claimed**. Ask your machine administrator for narrowly scoped capture access. Do not make BPF devices world-readable and do not run the complete API or training stack as root. An authorized existing capture can be analysed with `analyse(Path(...))` from `tools.capture_loopback`; external datasets still need explicit provenance and labels before model evaluation.

## Troubleshooting

- **API down:** start the API, confirm `GET /api/health`, and check port 8000. A successful health response is not production certification.
- **Training disabled:** configure an operator token of at least 32 characters and restart the API.
- **401:** token does not match. It must be the current process's token.
- **409:** a job is already running, retained runs reached their limit, inputs are unavailable, or a safety check failed.
- **Candidate rejected:** inspect `result.json`; do not bypass the failed quality gate.
- **No alerts:** verify input, mode, progress, visibility, and `/api/health`'s `replay_error`. Benign traffic should not necessarily alert.
- **Hash mismatch:** stop using the affected file. Compare with the trusted original; do not update reference hashes merely to make the check green.
- **Permission denied for copied Node executables:** use `node node_modules/typescript/bin/tsc --noEmit` or reinstall dependencies with `npm ci`.
- **Model or dataset edits:** rerun the full test suite and integrity checks. Do not assume earlier validation covers modified artifacts.

## Verification commands

```sh
python3 -m pytest -q tests
python3 -m training.inventory
cargo test --offline --manifest-path native/pcap-audit/Cargo.toml
cargo build --offline --release --manifest-path native/pcap-audit/Cargo.toml
cd ui
node node_modules/typescript/bin/tsc --noEmit
node node_modules/vite/bin/vite.js build
```

The Rust binary has no third-party crates. Audit mode prints counts only. `--stream` sends exact framed packet bytes through a private subprocess pipe to Python's existing metadata decoder; this is an internal ingest protocol, not a dashboard payload endpoint. Native mode validates classic PCAP, not PCAPNG. Python input mode retains its existing formats.

### Gateway login and training

In the hardened deployment, sign in with an assigned role token over HTTPS. A viewer can inspect all read-only panels, an operator can control replay, and an administrator can train candidates. Backend authorization is authoritative even if a read-only user can see a disabled or rejected control. The admin session enables the training button without a second token entry. In direct local development mode, the separate `SIH_OPERATOR_TOKEN` field remains required. A gateway 401 means the session expired or access is invalid; return to `/login`. Sessions expire after 30 minutes or a gateway restart.

State is stored under `SIH_STATE_DIR` when configured; candidate directories are `<state>/training-runs/<id>`. Signed serving models may be mounted separately using `SIH_MODEL_DIR`. On restart the verified alert ledger repairs missing DuckDB rows. Corruption or an index conflict stops startup; use the non-destructive restore procedure in the deployment runbook instead of editing evidence to force a pass.
