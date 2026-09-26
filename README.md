# Unidirectional Threat Detection Enclave

AI-based detection of cyber threats in unidirectional IP traffic. Built for **SIH26145**, set by
the **National Technical Research Organisation (NTRO)** under the Blockchain and Cybersecurity
theme of Smart India Hackathon 2026.

## Dashboard, datasets, and guarded training

**Passive live monitoring is available** in the simplified dashboard's **Live monitor** page.
Read the [SIH26145 live-monitoring guide](docs/LIVE_MONITORING_26145.md) for local capture setup,
concurrent threat detection, automatic JSON alert storage, downloads, tested throughput, and limitations.

A separate [simplified dashboard](ui-simple/README.md) is available at
`http://127.0.0.1:8000/simple/` after building `ui-simple/`. It has a website-style navbar,
replay controls, searchable alerts, and a [plain-language walkthrough](ui-simple/public/dashboard-guide.md).
The original `ui/` dashboard remains at `/`; both views share the detection engine.

The [8 September validation record](docs/VALIDATION_2026-09-08.md) covers the latest flood fixes,
DNS domain isolation, encrypted-session sequences, false-positive challenges, stronger model training
and measured Windows performance. Run `python -m training.high_effort` to rebuild current-engine
features and train a candidate in its own directory.

The [accuracy improvement report](docs/ACCURACY_IMPROVEMENT_2026-09-08.md) records the
expanded training corpus, calibration search, reserved-seed evaluation, exact anomaly-scoring
optimization, and remaining failures. Run `python -m training.high_effort --profile
config/training-expanded.json` for the expanded preset. The improved candidate remains isolated.

Read the [detailed dashboard guide](ui/README.md) for setup, replay, every panel, dataset verification,
one-click training, and troubleshooting. Read [production readiness](docs/PRODUCTION_READINESS.md)
for the measured scope and unresolved deployment gates. This remains a prototype, not a production certification.
The [validation record](docs/VALIDATION_2026-09-07.md) lists exact checks, results, and blocked work.

The Operations view now includes all 11 bundled scenarios and their PCAP, flow CSV, and label files,
SHA-256 verification, an isolated quality-training action, and a [47-method defensive coverage review](docs/ATTACK_COVERAGE.md).
The inventory is not a blanket detection claim: no exact MHDDoS method has tool-generated validation.
Extended profiles add TCP/UDP/ICMP rate and TCP SYN-attempt alarms, including configurable cold-start
limits and final-window flushing. Their confidence remains rule-based; the existing serving model is preserved.
The Analyst view can replay Python PCAP, Rust PCAP ingress, or flow CSV; the latter has reduced metadata visibility.

The [deployment guide](docs/DEPLOYMENT.md) documents the implemented Go TLS/authentication gateway,
Rust streaming ingress, signed serving-model bundles, ledger-to-database recovery, backup/restore,
and a resource-limited Compose profile. This is hardened single-node infrastructure, not field certification.
The supplied problem statement names traffic generators, not downloadable datasets. Operations now
shows every named generator and the difference between synthetic fixtures and actual lab evidence.

```sh
python3 -m training.inventory              # audit existing dataset files
python3 -m api.training_jobs               # train and evaluate a candidate; preserve serving artifacts
python3 -m tools.capture_loopback           # eight benign local packets; OS capture permission required
```

Candidate training searches six configurations with up to 1,200 boosting rounds, temporal early stopping
and 500 anomaly trees. Calibration targets a declared 0.1% attack prevalence.
It uses separate calibration and test slices, reports strict synthetic metrics, and rejects candidates
that fail quality gates. Higher settings do not guarantee accuracy. The first quality candidate was
rejected; no independent labelled real-traffic holdout is supplied. See `config/training-quality.json`.

Set `SIH_OPERATOR_TOKEN` to a private token of at least 32 characters to enable the dashboard's training
button. Set `SIH_AUTO_TRAIN=1` to opt into verified-digest candidate retraining. This watcher does not
pseudo-label live data, detect drift, or automatically replace the serving model. It does not establish
the authenticity of a dataset merely because its hash matches a locally stored manifest.

Additional TCP/UDP/ICMP rate alarms are opt-in through `SIH_ENGINE_CONFIG=config/engine-extended.json`.
The Rust component in `native/pcap-audit/` independently validates classic-PCAP structure with bounded
memory and provides the selectable streaming ingest path. It is not a Rust rewrite of the detector.
The implemented Go gateway supervises bounded operator networking; distributed detection still
requires aggregation design, profiling, and a specified production target.

The approved MVP implementation for **Zero-Day Analysis**, the **Offline SOC Copilot**, and
multi-analyst case collaboration is documented in
[`docs/NOVELTY_COPILOT_COLLABORATION.md`](docs/NOVELTY_COPILOT_COLLABORATION.md). Novelty uses a
separate `novelty-v1` benign companion and alert-only `unknown-suspicious` taxonomy; it never changes
the existing seven-class serving bundle. It stays disabled until an approved, separately signed
baseline is configured. The copilot works immediately in deterministic evidence-linked fallback
mode; no model weights are bundled or downloaded at runtime.

The notification queue is now strictly bounded. It can shed alert notifications after metrics and
status; stored alert records remain queryable. The browser resynchronises recent history after gaps.
`GET /api/alert-history` provides insertion-cursor pagination for complete retained history. Older
architecture prose and benchmarks below may describe the former “never evict a notification” behavior;
the dashboard guide and production-readiness record describe the current implementation.

The local capture check was blocked by macOS BPF permissions. **No real traffic capture or real-world
accuracy result is claimed.** Only explicitly authorized capture should be used.

## The problem, in one paragraph

A critical-infrastructure operator copies traffic off a gateway link into a monitoring enclave,
one way only, through a passive tap or a hardware data diode. The enclave sees everything crossing
the link and has no path back: it cannot probe a host, complete a handshake, resolve a domain, ask
a reputation service anything, or block a flow. That is deliberate. It stops the monitoring system
becoming a pivot into the core network and it keeps a clean chain of custody for forensic use. The
cost is that every detection has to come from passively observed metadata alone.

This repository is a working prototype of the detection pipeline for that enclave: ingest, feature
extraction, six detectors, a scoring layer, and structured alerts with evidence, driven by
replayed traffic and watched from a local dashboard. The full brief is in
`docs/01_Problem_Statement_Verified.md`; the constraints it scores against are in section
"The five constraints" below.

## Quick start

Python 3.11 and Node 20 or newer. Nothing here talks to the internet at run time.

```
pip install -r requirements.txt && cd ui && npm install && cd ..
make demo
```

`make demo` starts the API on `http://127.0.0.1:8000`, waits for it to answer, and opens the
dashboard. On Windows there is no GNU make, so run `mingw32-make demo`. The same thing by hand, in
two terminals:

```
python -m api.main
cd ui && npm run dev
```

Open `http://localhost:5173`, pick a scenario from the replay bar and press start. The alert queue,
the evidence panel and the live throughput meter fill in as the capture replays.

No dashboard needed for a smoke test:

```
make test                                 # the whole test suite
make bench                                # the C-d throughput and latency harness
```

The ledger is written by a replay, so verify it after one has run. Change one byte of one record
first if you want to watch it fail and name the record it failed on:

```
python -m engine.alerts.verify data/alerts.jsonl
```

## The four deliverables the problem statement names

| Deliverable | Where it is |
|---|---|
| A working prototype as a source repository: ingest, feature extraction, model inference, alert output | this repository, `engine/` and `api/` |
| Documentation of the models used, the features engineered and the training and validation approach | `docs/MODEL_CARD.md`, `docs/FEATURES.md`, `docs/TRAINING.md` |
| A simple dashboard showing live or replayed detections with severity and confidence | `ui/`, two views, replay driven |
| Adherence to the five architectural constraints | the section below, and `docs/ARCHITECTURE.md` section 8 |

Two more documents that nobody asked for and that are worth reading first: `docs/ARCHITECTURE.md`,
which redraws the design against what was actually built and lists where the two diverge, and
`docs/DETECTION_CEILING.md`, which states what this system physically cannot see.

## The six threat classes

The problem statement names six classes and, for each, the signal it expects them to be detected
from. Each has one detector under `engine/detect/` and at least one committed scenario.

| Class | Detector | What it keys on |
|---|---|---|
| **(a)** volumetric and protocol DDoS | `ddos.py` | Packets per second per destination against that destination's own EWMA with a Poisson variance floor, source-IP entropy over a 1 s sliding window, and the SYN to SYN-ACK ratio. Three sub-types: a spoofed flood, told apart by `src_cardinality_growth` of 6.05 at alert time; a reflection, told apart by an amplification ratio of 21.5 and a growth of 1.02; and connection exhaustion, which no rate rule can see and which is caught by concurrent half-open connections with almost no teardowns. |
| **(b)** botnet C2 beaconing | `beaconing.py` | Inter-arrival gaps between sessions on a (client, server, port) channel, collected in a 64-sample ring, analysed with a Lomb-Scargle periodogram over 512 log-spaced trial frequencies. Two clauses, either of which alerts: a significant peak, false-alarm probability under 1e-3 with power at least 8, or a regular gap train, at least 20 gaps with a coefficient of variation at or below 0.35 agreeing with the recovered period. Neither is a threshold over the period itself, and every alert names the clause that carried it. |
| **(c)** DGA domains and DNS tunnelling | `dga.py` | Character entropy and mean log-likelihood under an order-2 Markov model for the name itself, plus the campaign shape: distinct registered domains per source per 300 s and the fraction of responses carrying no answer. Tunnelling is distinct subdomains per registered domain against an EWMA baseline, combined with the TXT and NULL query ratio. |
| **(d)** malware in encrypted sessions | `encrypted.py` | JA4 from the ClientHello against a p0f-style TCP fingerprint from the SYN. The TLS library and the OS kernel are two independent claims about the same host, and a disagreement is a spoofing signal that needs no reputation data. No decryption anywhere. |
| **(e)** reconnaissance and port scanning | `scan.py` | Distinct destination ports and distinct destination hosts per source, through rotating HyperLogLog families at 1 s, 60 s and 3600 s, so a fast sweep and a slow scan are both visible. The probe completion ratio and mean bytes per probe keep a busy browser from reading as a sweep. |
| **(f)** data exfiltration | `exfil.py` | An EWMA, alpha 0.2, of the per-60 s outbound-to-inbound byte ratio for each (initiator, responder) pair, combined with destination novelty. Two sub-types off the same rule, told apart by the busiest single 60 s window. On the drip scenario the ratio reads 23.1 to 1 and is still held 840 seconds later while that window carries only 54808 bytes out, which is what a single-window byte threshold walks straight past. On the bulk scenario the same rule reads 55.9 to 1 with 5349618 bytes in one window, and reports `upload-burst` instead. |

## The five constraints

These are the scoring rubric. Each is satisfied by a mechanism, and each mechanism has something
that demonstrates it.

### C-a: read-only ingest, no return path

Nothing in this repository sends a packet off the host. No module under `engine/` imports
`socket`, `requests`, `httpx`, `urllib`, `urllib3`, `http`, `aiohttp`, `ftplib` or `smtplib`.
There is no DNS resolution of observed names, no reputation lookup, no active probe, and no
blocking.

That is narrower than "no socket is ever constructed", and the difference is stated rather than
hidden. Exactly one socket is constructed, at import time and not on the packet path:
`engine/alerts/schema.py` imports `stix2`, `stix2` imports `requests`, and `urllib3` tests for
IPv6 support while it is being imported by opening an `AF_INET6` socket and binding it to `::1`
port 0. Nothing connects, nothing resolves, and nothing leaves the loopback interface, but the
socket is real and the claim has to admit it. The measurement, the call chain and the two ways to
remove it are in `docs/DETECTION_CEILING.md` section 5.

Demonstrated by `tests/test_api.py::test_no_module_under_engine_imports_an_outbound_client`, which
walks the AST of every engine module, and by
`test_the_detection_path_never_constructs_a_socket`, which runs ingest, the flow table and the
sliding state in a subprocess where `socket.socket.__init__` raises, over all 13100 packets of
`syn_flood.pcap`, and asserts zero sockets were constructed. Read that guard for what it covers:
it imports `PcapSource`, `FlowTable`, `SlidingEntropy` and `HLLFamily` only, so it is evidence
about the packet path and not about the detector, model and alert layers above it.

### C-b: no payload decryption

`PacketMeta` in `engine/types.py` has no payload field. Inside `parse_packet` the L4 payload
exists only as a local variable; it is handed to the TLS and DNS parsers, which return metadata
objects holding fingerprints, counters, a query name and a boolean, and the very next statement is
`del payload`. The SNI hostname is read to set a `sni_present` boolean and then discarded, never
stored.

The constraint therefore holds by type rather than by convention: a developer who wanted to
featurise payload would have to change the type first. Demonstrated by
`tests/test_decode.py::test_packet_meta_has_no_payload_field`, which asserts it against
`PacketMeta.__slots__`.

### C-c: streaming, not batch

Every detector is an online algorithm with bounded state, and nothing loads a whole capture.
`PcapSource` iterates and yields; the flow-record adapter uses `csv.DictReader`. Every bounded
structure reports what it holds, `nbytes`, and what it can ever hold, `capacity_bytes`, both as
measured allocations. The total bounded-state ceiling is 270.0 MB; the per-detector mechanism and
bound are tabulated in `docs/ARCHITECTURE.md` section 4.

Demonstrated by `tests/test_state.py` and `tests/test_detectors.py`, which push each structure well
past its capacity and assert the byte count stops growing, and live on the operations view, which
draws current bytes against the cap for every structure while a replay runs.

### C-d: stated and demonstrated throughput

Stated, measured on an i5-13400F desktop, single threaded, over the whole eleven-scenario corpus
in one pass. Full detail, the hardware, the exact command lines and the caveats are in
`bench/RESULTS.md`.

Every figure in this table is copied from `bench/RESULTS.md`, section by section, and no figure
appears here that does not appear there. Re-run the harness and this table has to be re-copied.

| Configuration | Sustained | Latency p50 | Latency p95 | Peak RSS | Source |
|---|---|---|---|---|---|
| rules plus model, virtual mode | 2,818 packets/s mean, 542 flows/s, 7.97 Mbps | 10.322 ms | 12.284 ms | 222.02 MB | section 3 |
| rules only, virtual mode | 7,697 packets/s mean, 1,481 flows/s, 21.76 Mbps | 2.196 ms | 3.128 ms | 88.32 MB | section 4 |
| rules only, best single scenario | 22,894 packets/s p50 on exfil_bulk, 8,552 flows/s p50 on the flood | | | | section 6 |
| rules only, corpus at 30x true wire timing | on schedule, 9,889.9 s of capture in 330.21 s, 10.8 percent of one core | 4.999 ms | 50.254 ms | 91.54 MB | section 5.2 |
| rules plus model, corpus at 30x true wire timing | on schedule, 330.21 s, 19.5 percent of one core | 20.908 ms | 354.363 ms | 224.66 MB | section 5.3 |

Run to run spread is 1.5 percent on a quiet machine, measured by repeating the section 4 run three
times. Measured while other work is running on the same desktop, the same commands come out
roughly half as fast, so read these as quiet-machine figures.

Latency in virtual mode is ingest to alert, because a virtual clock has no wire; in realtime mode
it is true wire to alert, from the packet's own timestamp to the moment the alert is emitted. The
two are never quoted as one number. The shipped default holds 30x wire on this corpus in
aggregate, and an alert raised inside the peak of a volumetric flood can be several seconds late,
which `bench/RESULTS.md` section 5.3 measures rather than hides. That tail traces to tier 1, whose
per-call cost `bench/RESULTS.md` section 9 measures at 702.4 us.

Demonstrated: the same `engine.metrics.Meter` feeds the dashboard, so packets per second, flows per
second, Mbps and the latency percentiles move on screen at about 2 Hz while a replay runs, next to
the memory panel showing every bounded structure against its cap.

### C-e: standardised alert schema

Every alert is a STIX 2.1 indicator carrying the five fields the problem statement requires,
timestamp, flow identifier, threat class, confidence and supporting evidence, plus `x_` extensions
for severity, calibration state, detector, latency, model lineage, detection context and the
previous ledger hash. `validate_alert` raises on anything non-conformant, and the ledger validates
again before it will accept a record, so a malformed alert cannot enter the chain. One caveat,
stated rather than left to be found: a record that fails validation raises out of the replay
thread rather than being dropped, so the run stops instead of losing the one alert.

Demonstrated by the 30 tests in `tests/test_alerts.py` and by `GET /api/alerts/{id}`, which returns
the object exactly as it was written.

## Architecture

```
  data/scenarios/*.pcap        read-only replay        one direction only
  data/scenarios/*.flows.csv   -------------------->   no path back
                                        |
  +-------------------------------------v-----------------------------------+
  |  Detection enclave, one Python process, no outbound connections         |
  |                                                                         |
  |  PcapSource / FlowRecordSource                                          |
  |         |  PacketMeta, no payload field                                 |
  |         v                                                               |
  |  parse_packet -> parse_tls (JA4) / parse_dns / tcp_fingerprint          |
  |         |                                                               |
  |         v                                                               |
  |  FlowTable  LRU 200k flows, idle 120 s, orientation bit                 |
  |         |                                                               |
  |         v                                                               |
  |  six detectors over one shared Context                                  |
  |    ddos  beaconing  dga  encrypted  scan  exfil                         |
  |    shared: BeaconTable, scan and DNS HLL families                       |
  |    per detector: LRU tables, count-min sketches, EWMA deviations        |
  |         |                                                               |
  |         v                                                               |
  |  model layer: LightGBM tier 1, isotonic calibration, promotion gate     |
  |         |                                                               |
  |         v                                                               |
  |  explain -> STIX 2.1 alert -> hash-chained ledger + DuckDB history      |
  |         |                              Meter: pps, flows/s, Mbps,       |
  |         |                              wire-to-alert latency, memory    |
  +---------|---------------------------------------------------------------+
            |  bounded queue, 1024 frames, drops metrics then status,
            |  never an alert
            v
  FastAPI on 127.0.0.1:8000  ---- websocket ---->  React dashboard
     /api/alerts /api/metrics /api/coverage /api/ledger/verify
```

Both input adapters exist and both feed the identical downstream path, but only one of them is
wired to the API: `ReplayController.start` constructs a `PcapSource`, and `POST /api/replay/start`
has no field to ask for the other. `FlowRecordSource` is driven by
`bench/throughput.py --source flows`, measured in `bench/RESULTS.md` section 7, and covered by
`tests/test_decode.py`. From the dashboard it is not reachable today.

The C4 context and container views, the streaming table and the memory ceiling are in
`docs/ARCHITECTURE.md`.

## Repository map

```
engine/
  types.py                 the shared contract: PacketMeta, FlowKey, FlowState, Detection
  sources/base.py          ReplaySource protocol
  sources/pcap_source.py   dpkt PCAP and PCAPNG replay, nanosecond fidelity
  sources/flowrecord_source.py  NetFlow/IPFIX-style CSV replay, same downstream path,
                           reachable from bench/throughput.py and the tests, not from the API
  sources/replay_clock.py  virtual and realtime clocks, speed multiplier
  decode/packet.py         Ethernet or raw IP, v4 and v6, TCP/UDP/ICMP, payload deleted here
  decode/tls.py            ClientHello and ServerHello only, JA4 and JA4S, no dependency
  decode/dns.py            query name, qtype, response and answer count
  decode/tcp_fingerprint.py  p0f-style TTL, window, MSS and option order, OS family
  state/flow_table.py      LRU flow table, orientation resolution, SPLT budget
  state/beacon_table.py    beacon candidates, long TTL, lazy ring allocation
  state/cms.py             count-min sketch, linear update so two sketches merge
  state/hll.py             HyperLogLog and an LRU family of them
  state/entropy.py         sliding-window entropy, EWMA deviation in sigmas
  state/welford.py         streaming mean, std, cv, skew, kurtosis
  analysis/lombscargle.py  classical periodogram, false-alarm probability
  detect/base.py           Context, Detector, reference data, LRU and windowed sketches
  detect/{ddos,beaconing,dga,encrypted,scan,exfil}.py   one per threat class
  features/registry.py     the feature dictionary, 101 entries, source of docs/FEATURES.md
  models/                  tier 1 scoring, calibration, promotion gate, anomaly layer
  explain.py               evidence to a readable sentence
  alerts/schema.py         STIX 2.1 build and validate
  alerts/ledger.py         SHA-256 chain, Ed25519 anchor every 100 records
  alerts/verify.py         chain verification CLI, exit 0 on PASS, 1 on FAIL
  metrics.py               Meter: throughput, fixed-size latency histogram, RSS, memory
  pipeline.py              the streaming loop: state, detectors, model layer, alerts, metrics

api/
  main.py                  FastAPI app, every endpoint, websocket
  replay.py                replay thread, bounded frame queue, coverage accounting
  store.py                 DuckDB alert history and ledger resolution

ui/src/
  App.tsx useEngine.ts api.ts threats.ts    client, state, threat palette
  views/AnalystView.tsx views/OperationsView.tsx
  components/                               panels, queue, evidence, meters

data/
  scenarios/               11 captures, their flow-record CSVs, labels and index.json
  reference/               bigram model, JA4 to TCP family table, DNS and exfil allowlists
  models/                  dataset, manifest, booster, calibration, anomaly forest, metrics.json

training/
  scenarios.py             the scenario catalogue and the emulation table
  generate_scenarios.py    the generator, deterministic, seeded per scenario
  build_dataset.py         replay the corpus into a labelled, temporally split dataset
  train_tier1.py           LightGBM, isotonic calibration, benign-only anomaly forest
  evaluate.py              metrics.json, the ablation, the reliability diagram

bench/
  throughput.py            the C-d harness
  RESULTS.md               hardware, command line and measured numbers

tools/
  gen_features_md.py       regenerates docs/FEATURES.md from the feature registry
  gen_training_md.py       regenerates docs/TRAINING.md from the model artefacts
  training_template.md     the prose half of docs/TRAINING.md, edit this not the output

docs/
  ARCHITECTURE.md  FEATURES.md  MODEL_CARD.md  TRAINING.md  DETECTION_CEILING.md
  00 to 06                 the brief this build was written against

Makefile                   demo, test, bench, train, scenarios, verify
requirements.txt           pinned to the versions every measurement was taken on
```

## Measured results

Eleven scenarios, all synthesised, 105142 packets in total. Replaying each capture on its **own
fresh engine**, through the flow table and all six detectors, gives:

| Scenario | Labelled class | Rule detections raised | With the model layer on |
|---|---|---|---|
| benign | benign | **none** | **none** |
| syn_flood | volumetric-ddos | syn-flood-spoofed-source 1 | 2 |
| udp_reflection | volumetric-ddos | udp-reflection-amplification 1 | 4 |
| slowloris | volumetric-ddos | connection-exhaustion 2 | 3 |
| beacon_jitter | c2-beaconing | periodic-c2-checkin 12 | 30 |
| dga_burst | dga-dns-tunnelling | dga-high-entropy 2, dga-dictionary 2 | 6 |
| dns_tunnel | dga-dns-tunnelling | dns-tunnel-txt-null 2 | 3 |
| ja4_spoof | encrypted-malware | ja4-tcp-fingerprint-disagreement 6 | 9 |
| port_scan | recon-scanning | vertical-scan-fast 1, vertical-scan-slow 7, horizontal-sweep 3 | 13 |
| exfil_drip | data-exfiltration | slow-drip-upload 2 | 7 |
| exfil_bulk | data-exfiltration | upload-burst 1 | 3 |
| **total** | | **42** | **80** |

Alert counts for the same corpus differ between runs and they are not interchangeable. Two things
move them, and both are stated wherever a count appears:

- **one engine per capture, or one engine across all of them.** The table above is eleven
  independent `Engine` instances. `bench/throughput.py --scenario all` builds one engine and
  replays every capture through it in sequence, so a single flow table, a single beacon table and
  a single set of sketches see every scenario; per-subject cooldowns and LRU eviction then
  suppress alerts a fresh engine raises. The continuous-pass total is always the lower of the two.
- **how often the periodic tick fires.** Beacon and scan alerts are produced on a tick, so the
  tick interval changes how many of them there are. The table above uses `run_source`, which ticks
  every 5 capture seconds; the harness ticks every 1.

Reproduce the table above one capture at a time, and the corpus figures from the harness:

```
python -m engine.pipeline data/scenarios/beacon_jitter.pcap   # one fresh engine, one capture
python bench/throughput.py --scenario all --duration 240 --bucket 0.5 --warmup 2 --no-loop
python bench/throughput.py --scenario all --duration 60 --bucket 0.5 --warmup 2 --rules-only --no-loop
```

`bench/RESULTS.md` section 6 note 3 carries the arithmetic between the two. Never quote an alert
count without saying which run produced it. Whichever is quoted, the benign baseline raises zero
in every configuration.

No detection in any of the eleven scenarios falls outside a labelled attack window. That is
asserted by `tests/test_detectors.py::test_no_detection_falls_outside_a_labelled_attack_window`,
parametrised over every scenario with the six rule detectors. With the model layer on, the
equivalent assertion is in `tests/test_pipeline.py` and it covers nine of the eleven:
`beacon_jitter`, where the model contributes 18 of the 30 alerts, and `benign` are not in its
list. The benign baseline raises nothing at all with every detector running, which is the
false-positive demonstration.

Beaconing recall is five of six infected hosts at a 45 second period, with all three benign
update pollers silent. Recovered periods were 43.0 to 51.4 seconds against a true 45. Five of six
is the honest number and the reason the sixth is missed is in `docs/DETECTION_CEILING.md`
section 7, which also explains why some of those twelve alerts are carried by gap regularity
rather than by a significant periodogram peak.

### The model layer, with the prevalence stated

The tier-1 model is evaluated on a temporal test slice of 13690 observations. **That slice is 59.2
percent attack rows**, because it comes from a corpus of eleven scenarios, ten of which contain an
attack. No real link looks like that, so every headline figure is also reported at a **constructed
prevalence of one attack observation per thousand benign ones**, by keeping every test row and
weighting each benign row up.

| Measure | At the natural 59.2 percent | At a constructed 1 in 1000 |
|---|---|---|
| PR-AUC, attack against benign | 0.9933 | **0.1657** |
| macro F1 over the six attack classes | | 0.3454 |
| expected calibration error | | 0.03793 |

The second column is the one to quote. The gap between the two is the entire reason this repository
states prevalence everywhere it states a metric: the same model, the same rows, the same
predictions, and only the assumed mix changed.

Read honestly: recall holds up across classes and precision does not. At one in a thousand,
per-row precision is below 0.01 for beaconing, encrypted malware and exfiltration. That is a real
weakness of the per-row model, it is why the model-only alert path is gated at 0.99 confidence with
an anomaly veto and a rate quota, and it is why the rule layer names the class whenever a rule
fires. The full tables, the strict no-leakage variant, the physical cross-check at the constructed
ratio and the rules-against-model ablation are in `docs/TRAINING.md`.

The PR-AUC and macro F1 above are lower than the ones an earlier tier-1 artefact produced, and
the drop is the point. That artefact read a feature called `initiator_is_lo`: whether the flow
initiator's address sorted lower than the responder's in the normalised flow key. That is an
artifact of key ordering rather than a property of the traffic, and because attacker addresses
are fixed within each synthetic capture it let the model key on address ranges instead of on
behaviour. It was found by reading the SHAP evidence on a live alert, where that bookkeeping
field was the second strongest contributor to the score. It was taken out of the model input,
tier 1 was retrained on all eleven captures with the remaining 97 features, and the table above
is what the retrained model scores. The lower figures are the trustworthy ones.
`docs/TRAINING.md` section 4 gives the full account.

## Regenerating the corpus and retraining

Every capture is synthesised, deterministic and seeded, so anyone can rebuild the corpus from
source:

```
python training/generate_scenarios.py
```

That rewrites the eleven PCAPs, their flow-record CSVs, their labels and `index.json`, which records
the seed and the SHA-256 of each file. Generating three times produces byte-identical output.

**No attack tool was run to produce these captures.** They were written packet by packet with
`dpkt.pcap.Writer`. The problem statement names `hping3`, Slowloris, `dnscat2`, `iodine`,
DGArchive lists and `nmap`; each scenario emulates the traffic those tools produce, and the mapping
is in `EMULATION` in `training/scenarios.py` and in every labels file. Do not describe these
captures as tool output.

Retraining and the reference data:

```
make train                               # build_dataset.py then train_tier1.py
python training/evaluate.py              # metrics.json, the ablation and the reliability diagram
python data/reference/build_bigrams.py   # order-2 Markov model over the committed word list
python data/reference/build_ja4_reference.py  # JA4 to TCP family, parsed from benign.pcap
python tools/gen_features_md.py          # regenerate docs/FEATURES.md from the registry
```

`build_dataset.py` replays the corpus through `engine.pipeline.Engine` itself, so the training
features are produced by the same code that produces them at inference. `train_tier1.py` fits the
booster, the isotonic calibration and the benign-only anomaly forest, and writes the model hash and
the dataset hash into `data/models/tier1_meta.json`. `Engine.lineage()` reads them back and
`Engine.lineage_for(detection)` adds the calibration flag and the detector that fired; that is the
object an alert carries in `x_model_lineage`, so an alert names the exact booster that scored it.

The split protocol, the leakage controls and the prevalence figures are in `docs/TRAINING.md`.

## Limitations

The honest ones, in short. The long version, with the numbers behind each, is
`docs/DETECTION_CEILING.md`.

- **Every number here comes from synthetic traffic.** The detectors were measured against traffic
  generated from a model of each attack, which means they are partly measured against their own
  assumptions. These results are not evidence of field performance.
- **The model's per-row precision at realistic prevalence is poor for three classes**, below 0.01
  for beaconing, encrypted malware and exfiltration at one attack per thousand. Recall holds. That
  is why a rule names the class whenever one fires and the model may only speak alone at 0.99
  confidence with an anomaly veto.
- **Payload is never available**, so anything whose evidence lives in the bytes is out of reach.
  SNI is discarded by choice, and Encrypted Client Hello removes it from the wire anyway.
- **QUIC is not decoded.** Every JA4 is a `t` transport fingerprint. UDP/443 flows are counted as
  unclassifiable in the coverage report rather than quietly ignored.
- **Beacon periods above 21600 seconds cannot be represented**, and any period needs twelve
  observed gaps before a decision, so a 30-minute beacon takes six hours.
- **The bigram model does not separate dictionary DGA** from benign names: -2.74 against -2.71 on
  this corpus. The dictionary family is caught by campaign shape instead, so a slow dictionary DGA
  under 20 domains per five minutes is invisible.
- **The JA4 reference table covers three TLS stacks** learned from one local capture. It is ground
  truth for this enclave and nothing more.
- **The ledger is tamper-evident, not unforgeable.** The signing key sits next to the ledger file.
  Production wants an HSM.
- **Thresholds are published**, so an adversary who reads this repository can sit under them. That
  is a deliberate trade of evasion resistance for auditability.
- **Two detector branches fire on no committed scenario**: `strobe-scan` in `scan.py` and
  `ja4-tcp-pairing-outlier` in `encrypted.py`. They are implemented and reachable, and the corpus
  does not exercise them, so treat either as untested code rather than as a tested detection. Only
  the strobe one says so in its own alert. `docs/DETECTION_CEILING.md` section 11 lists what each
  needs before it can be claimed.
- **The beacon detector fires mostly on gap regularity, not on the periodogram.** Eleven of the
  twelve beacon alerts on `beacon_jitter` are carried by the regularity clause; one clears the
  1e-3 false-alarm bound. Lomb-Scargle recovers and prints the period, but at 30 percent jitter it
  is not what makes the decision. Each alert names its own clause.
- **The second input adapter is not reachable from the dashboard.** `FlowRecordSource` reads the
  committed `.flows.csv` files through the same downstream path and is measured in
  `bench/RESULTS.md` section 7, but `ReplayController.start` constructs a `PcapSource`
  unconditionally and the start payload has no field to ask for the other. R1's second half is a
  code-reading exercise rather than a two-click demo.
