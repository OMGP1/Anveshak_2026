# Architecture

> Update: the API now supports both PCAP and flow-CSV replay. Alert notifications have a strict queue
> bound, with persisted history and resynchronisation after delivery gaps. Candidate training runs in a
> separate bounded-duration process and never replaces serving artifacts automatically. Rust now
> validates and frames streaming PCAP input for the existing Python metadata decoder. Go now terminates
> TLS and authenticates HTTP/WebSocket operator traffic with roles and bounded admission. Production
> mode requires a trusted gateway and signed model bundle. A verified ledger repairs missing database
> rows on restart. See `DEPLOYMENT.md`, `../ui/README.md`, and `PRODUCTION_READINESS.md` for current
> behavior, limitations, and release gates; the detailed design and benchmark discussion below records
> the earlier prototype baseline, including former queue and input-adapter limitations.

The C4 context and container views from `docs/03_Tech_Stack_And_Architecture.md`, redrawn against
what was actually built, plus the streaming table that backs constraint C-c. Where the build
diverges from the plan the divergence is called out with the reason, because a diagram that
flatters the code is worse than no diagram.

---

## 1. Context (C4 level 1)

```
  +----------------------------------------------------------+
  |  Simulated traffic source, read-only                      |
  |                                                           |
  |    data/scenarios/*.pcap        11 synthesised captures    |
  |    data/scenarios/*.flows.csv   the same traffic as        |
  |                                 exporter flow records      |
  +----------------------------------------------------------+
                          |
                          |  one direction only
                          |  files opened read-only, never written
                          v
  +----------------------------------------------------------+
  |  Detection enclave                                        |
  |  one Python process, no outbound connections anywhere      |
  |                                                           |
  |    ingest -> decode -> flow state -> detectors -> alerts   |
  +----------------------------------------------------------+
             |                                  |
             | localhost HTTP + websocket       | append-only file
             v                                  v
  +------------------------+      +-----------------------------+
  |  Analyst dashboard     |      |  Hash-chained alert ledger  |
  |  React, localhost:5173 |      |  data/alerts.jsonl          |
  +------------------------+      |  + Ed25519 anchors          |
                                  +-----------------------------+
```

The read-only invariant is enforced three ways, all of them checkable:

1. The replay adapters call `open()` on a capture or a CSV and nothing else. There is no write
   path back toward the source because there is no code that could take one.
2. No module under `engine/` imports `socket`, `requests`, `httpx`, `urllib`, `urllib3`, `http`,
   `aiohttp`, `ftplib` or `smtplib`. `tests/test_api.py::test_no_module_under_engine_imports_an_outbound_client`
   walks the AST of every engine module and asserts it, and
   `test_the_detection_path_never_constructs_a_socket` runs ingest, the flow table and the sliding
   state in a subprocess where `socket.socket.__init__` raises, over all 13100 packets of
   `syn_flood.pcap`. That guard imports the ingest and state layer only, so it is evidence about
   the packet path rather than about the process. One socket is in fact constructed at import
   time, by `urllib3` underneath `stix2` underneath `engine/alerts/schema.py`, and it binds to
   `::1` without ever connecting; `docs/DETECTION_CEILING.md` section 5 measures it and says what
   it costs the claim. The invariant that survives is "no outbound connection is ever made", not
   "no socket is ever constructed".
3. Payload bytes are discarded at the parse boundary. `PacketMeta` has no payload field, so C-b
   holds by type rather than by convention.

## 2. Containers (C4 level 2)

```
+- Detection engine (Python 3.11, one process) --------------------------------+
|                                                                              |
|  engine/sources/           engine/decode/          engine/state/             |
|   PcapSource       ---->    parse_packet   ---->    FlowTable                 |
|   FlowRecordSource          parse_tls  (JA4)         LRU, cap 200k,           |
|   ReplayClock               parse_dns                idle 120 s               |
|      |                      tcp_fingerprint          orientation bit          |
|      | PacketMeta              |                        |                     |
|      | (no payload field)      | TLSMeta / DNSMeta      | FlowState           |
|      v                         v                        v                     |
|  +----------------------------------------------------------------------+    |
|  |  engine/detect/  six online detectors, one Context of shared state    |    |
|  |    ddos   beaconing   dga   encrypted   scan   exfil                  |    |
|  |    shared: BeaconTable, scan HLL families, DNS HLL families           |    |
|  |    per detector: LRU tables, count-min sketches, EWMA deviations      |    |
|  +----------------------------------------------------------------------+    |
|          |  Detection (rule)                                                  |
|          v                                                                    |
|  +----------------------------------------------------------------------+    |
|  |  engine/models/  scoring layer over the same features                 |    |
|  |    tier1 (LightGBM + isotonic calibration), gate, anomaly, rules      |    |
|  +----------------------------------------------------------------------+    |
|          |  Detection (model), confidence calibrated                          |
|          v                                                                    |
|  engine/explain.py  ->  engine/alerts/schema.py  ->  engine/alerts/ledger.py  |
|   evidence to a                STIX 2.1 indicator      SHA-256 chain,         |
|   readable sentence            with x_ extensions      Ed25519 anchor / 100   |
|          |                             |                       |              |
|          +-------------+---------------+                       v              |
|                        |                              data/alerts.jsonl       |
|                        v                                                      |
|              engine/metrics.py  Meter: packets, flows, wire-to-alert          |
|              latency histogram, RSS, per-structure memory                     |
+------------------------------------|-----------------------------------------+
                                     |
                     bounded FrameQueue, capacity 1024
                     drop order: metrics, then status, never an alert
                                     |
+------------------------------------v-----------------------------------------+
|  api/  FastAPI on 127.0.0.1:8000                                             |
|    /api/scenarios /api/status /api/replay/* /api/alerts /api/alerts/{id}      |
|    /api/metrics /api/coverage /api/ledger/verify        WS /ws                |
|    api/store.py  DuckDB alert history, one table, flat columns plus the doc   |
|    api/replay.py replay thread, ReplayClock, coverage accounting              |
+------------------------------------|-----------------------------------------+
                                     |
+------------------------------------v-----------------------------------------+
|  ui/  React 19 + Vite + TypeScript, two views                                 |
|    Analyst:    alert queue, evidence panel, threat strip, throughput meter    |
|    Operations: memory, latency, stage timing, queue depth, coverage, ledger   |
+------------------------------------------------------------------------------+
```

The replay runs on its own thread. The API never blocks on it: the engine thread hands frames to
the event loop through `FrameQueue.offer`, which takes the drop decision on the loop thread, so no
lock is needed and every drop is counted. The drop counters are on `/api/metrics` under `queue`
and are rendered on the operations view, because a shedding policy nobody can see is a claim
rather than a mechanism.

## 3. Feature and state internals (C4 level 3)

```
FlowTable  (LRU, hard cap 200000 flows, idle timeout 120 s, orientation bit)
   |          SPLT sequences budgeted separately: 50000 flows x 20 samples
   |
   +-- Context, shared by every detector
   |     BeaconTable          cap 50000 candidates, TTL 21600 s, ring 64 gaps
   |     scan port HLLs       1 s / 60 s / 3600 s, 8192 groups per scale
   |     scan host HLLs       1 s / 60 s / 3600 s, 8192 groups per scale
   |     DNS subdomain HLL    300 s window, 8192 groups
   |     DNS regdomain HLL    300 s window, 8192 groups
   |
   +-- per detector, private
         ddos       LRU 4096 destinations, 256 lazily allocated entropy monitors
         beaconing  LRU 20000 channel aggregates
         dga        LRU 4096 sources, LRU 8192 zones, fixed 39x39 bigram matrix
         encrypted  LRU 20000 hosts, LRU 50000 flow fingerprints, 2 count-min
         scan       LRU 8192 sources
         exfil      LRU 20000 peer pairs, 3600 s destination-novelty HLL family

BeaconTable candidates that reach 12 gaps go to engine/analysis/lombscargle.py
   log-spaced grid of 512 trial frequencies over the binned arrival train
   false alarm probability of peak power z over M frequencies: 1 - (1 - e^-z)^M
```

Two structural points carried over from the plan, both load bearing:

- **The beacon table is not inside the flow table.** Different lifetime, different cap, allocated
  lazily only for candidates that pass a cheap pre-filter. Long-period beacon detection is
  possible only because beacon state outlives flow state.
- **HyperLogLog is split into per-group families with their own LRU.** A single global sketch
  cannot answer "how many ports did this source touch", and one sketch per source without a cap
  makes memory grow with cardinality, which is the failure the bounded-memory claim exists to
  avoid.

## 4. What "streaming" means concretely (constraint C-c)

Every detector is an online algorithm: bounded work per packet, bounded state, no pass over a
stored capture. Nothing in the engine loads a whole file; `PcapSource` iterates and yields, and the
flow-record adapter uses `csv.DictReader`, never pandas.

| Detector | Online mechanism | State bound |
|---|---|---|
| DDoS, volumetric | per-destination 1 s and 60 s rolling counters, EWMA of packets per second with a Poisson variance floor and a clipped update at 4 sigma so a sustained attack cannot train the baseline to accept it | LRU of 4096 destinations; sliding entropy over 8 buckets x 512 slots and two 60 s rotating HLLs allocated only for destinations above 8 pps, at most 256 of them |
| DDoS, reflection | 60 s inbound and outbound byte counters per destination, amplification ratio, distinct-reflector HLL | same 4096-destination LRU, no extra structure |
| DDoS, exhaustion | per-destination half-open count and teardown ratio over a 60 s window | same 4096-destination LRU |
| Beaconing | channel aggregate per (client, server, port); one gap appended to a 64-sample ring per session start; Lomb-Scargle over 512 trial frequencies on `tick` only, for candidates with at least 12 gaps | LRU of 20000 channels; beacon table of 50000 candidates, TTL 21600 s, ring 64 |
| DGA, name | per-query stateless scoring: character entropy plus mean log-likelihood under a fixed order-2 Markov model | 39x39 matrix loaded once, no per-query state |
| DGA, campaign | per-source registered-domain cardinality and no-answer ratio over a 300 s window; per-zone subdomain cardinality against an EWMA baseline | LRU 4096 sources, LRU 8192 zones, two HLL families of 8192 groups |
| Encrypted | JA4 from a single-segment ClientHello, p0f-style TCP fingerprint from the SYN, agreement looked up in a local table; a second path counts (JA4, TCP family) co-occurrence in two count-min sketches | LRU 20000 hosts, LRU 50000 flow fingerprints, 2 sketches of 4093 x 4 uint32 |
| Scanning | per-source distinct destination ports and destination hosts at 1 s, 60 s and 3600 s through two-generation rotating HLL families; probe completion ratio and mean bytes per probe as the false-positive guard | LRU 8192 sources; six HLL families of 8192 groups |
| Exfiltration | EWMA, alpha 0.2, of the per-60 s outbound-to-inbound byte ratio per (initiator, responder) pair, plus a 3600 s destination-novelty family | LRU 20000 pairs, HLL family of 20000 groups |

No detector needs the full stream and no detector's memory grows with stream length. That is the
property the constraint asks for and it is the single strongest architectural claim in the build.

## 5. Memory ceiling, computed rather than estimated

Every bounded structure reports both what it currently holds, `nbytes`, and what it can ever hold,
`capacity_bytes`. Both are measured allocations, not a constant times a length. The engine
registers each structure with the meter, so `/api/metrics` carries `memory_bytes` and
`memory_caps_bytes` per structure and the operations view draws the current value against its cap.

| Structure | Configured cap | Ceiling |
|---|---|---|
| Flow table, entries plus SPLT budget | 200000 flows, 50000 SPLT sequences | 151.6 MB |
| Beacon table | 50000 candidates | 31.4 MB |
| Scan HLL families, 6 of them | 8192 groups each | 18.0 MB |
| DNS HLL families, 2 of them | 8192 groups each | 13.5 MB |
| Exfiltration detector | 20000 pairs, 20000 destinations | 22.0 MB |
| Encrypted detector | 20000 hosts, 50000 flows, 2 sketches | 11.8 MB |
| Beaconing detector | 20000 channels | 8.9 MB |
| DDoS detector | 4096 destinations, 256 hot monitors | 7.9 MB |
| DGA detector | 4096 sources, 8192 zones | 3.0 MB |
| Scan detector | 8192 sources | 1.9 MB |
| **Total bounded state** | | **270.0 MB** |

This corrects the 160 MB figure in `docs/03`, which was arrived at with per-entry sizes from a
Rust design. A `FlowState` plus its key plus the dict node measures 428 bytes in CPython, not 96,
and pretending otherwise would have made the headline claim false in the one place it is easiest
to check. The ceiling is larger than planned and it is real: every line is an allocation you can
print.

One number in `bench/RESULTS.md` looks like it disagrees with this table and does not. The engine
reports memory to `/api/metrics` in four groups, flow table, beacon table, sketches and models, and
the cap it publishes for the `sketches` group covers the shared HLL families plus the detectors'
*current* occupancy, not the detectors' LRU ceilings. That gives the 229.50 MB declared cap in the
benchmark. The 270.0 MB above is the same thing summed from every LRU capacity, plus the model
artefacts on top. Use 270.0 MB when the question is "what is the worst case"; the dashboard figure
is what is currently reserved.

Measured steady state is far below the ceiling because the caps are sized for a production link,
not for a 10 MB scenario. Across the committed captures the flow table holds between 0.36 and
5.38 MB, the shared context between 0.15 and 5.05 MB, and the six detectors between 1.47 and
6.30 MB together. The flood scenario is the largest of the three, which is the point: state grows
with concurrent flows and then stops.

## 6. Divergences from the plan, and why

| Plan in docs/03 or docs/04 | What was built | Why |
|---|---|---|
| flow table 500k entries at 96 B, ceiling 160 MB | 200k entries at 428 B, ceiling 270.0 MB with everything counted | 96 B was a Rust number; the CPython object is measured |
| beacon pre-filter applied to one long-lived flow | pre-filter applied to a channel aggregate over repeated sessions | every C2 check-in in the corpus is its own TCP connection, so a per-flow filter rejected all of them; the gaps that matter are between sessions |
| DDoS sub-types separated by source entropy | separated by `src_cardinality_growth`, 60 s distinct sources over 1 s distinct sources | normalised entropy is near its maximum in both sub-types because it normalises by the distinct count; the growth ratio was 6.05 at the SYN flood alert and 1.02 at the reflection alert, because a spoofed flood draws from an unbounded address space and a reflection from a finite reflector list. That is a physical difference rather than a tuned constant |
| SYN to SYN-ACK ratio for every volumetric sub-type | amplification ratio substituted for the UDP reflection sub-type | UDP has no handshake, so there is no ratio to take |
| two DDoS sub-types | three, with connection exhaustion added | Slowloris is filed under class (a) and 19 pps is not a rate anomaly, so the volumetric rule cannot see it by design |
| bigram likelihood catches dictionary DGA | it does not; campaign shape catches it | measured, see `docs/DETECTION_CEILING.md` section 9 |
| ~52 features | 101 in the registry | three DDoS sub-types, three scan scales, campaign-level DNS statistics, and composite scores split into the components that produced them |
| tier 2, an ONNX 1D-CNN over SPLT | not built; the seven SPLT features go to tier 1 with everything else | a second model over 20 packet sizes and gaps would have added a runtime dependency and a second artefact to document for a signal the tree ensemble already reads |
| Merkle tree | hash chain, verification O(n) bounded by anchor spacing | it was never a Merkle tree; calling it one would not survive a question |
| both input adapters selectable at replay time | `PcapSource` only from the API; `FlowRecordSource` reachable from `bench/throughput.py --source flows` and from `tests/test_decode.py` | not a design decision, just unfinished wiring: `ReplayController.start` hardcodes the source and `scenario_list()` does not publish `flow_file` |
| a malformed alert is dropped | it raises out of the replay thread, which ends the run | `_emit` is called from `_run` with no `try`, and `_run` is a daemon thread target, so `/api/status` reports the run as simply not running with no error field |

## 7. Request and data flow, end to end

```
POST /api/replay/start {scenario, speed, mode}
   -> ReplayController starts a thread
        PcapSource yields PacketMeta in timestamp order
        ReplayClock.wait_until(ts) honours original timing in realtime mode,
                                   returns immediately in virtual mode
        FlowTable.observe(meta) -> FlowState, orientation resolved
        Context.begin_packet(meta, flow)
        each detector .observe(...) -> Detections; .tick(...) every few seconds
        model layer scores the same features, gate promotes borderline cases
        build_alert(detection, lineage) -> STIX 2.1 indicator, validated
        Ledger.append(alert) -> {record, prev_hash, hash}, chain extended
        AlertStore.append(alert) -> DuckDB row for paging and filtering
        FrameQueue.offer("alert", alert) -> websocket -> dashboard
   -> the browser shows the alert, its evidence and its latency
```

One thing that diagram flatters and the code does not do. `ReplayController.start` always
constructs a `PcapSource`; the start payload has no field for an input kind, and `scenario_list()`
does not publish the `flow_file` that `training/scenarios.py` carries for every scenario, so
`FlowRecordSource` is unreachable from the API and from the dashboard. It is listed in section 6.

Latency is wire to alert: the packet's own timestamp mapped to a monotonic instant at ingest, and
the alert's emission measured against that. Two alerts emitted at the same instant from packets a
millisecond apart differ by a millisecond, which is the property that makes the number honest. In
virtual mode there is no wire, so the same measurement is pipeline latency and `bench/RESULTS.md`
describes it that way.

## 8. Where each constraint lives in the code

| Constraint | Mechanism | File |
|---|---|---|
| C-a read-only ingest | no outbound client imported anywhere under `engine/`, checked by an AST walk, plus a socket-blocking subprocess over the ingest and state path; one import-time loopback socket under `stix2` is documented rather than denied | `tests/test_api.py`, `docs/DETECTION_CEILING.md` section 5 |
| C-b no payload decryption | `PacketMeta` has no payload field; the parser deletes its local payload after the metadata parsers return | `engine/types.py`, `engine/decode/packet.py` |
| C-c streaming, bounded state | every detector online, every structure reports `nbytes` and `capacity_bytes` | `engine/state/`, `engine/detect/` |
| C-d stated throughput | `Meter` measures packets, flows, Mbps and a fixed-size latency histogram; the dashboard shows them live | `engine/metrics.py`, `bench/throughput.py` |
| C-e standard alert schema | STIX 2.1 indicator with `x_` extensions, validated on build and again before the ledger accepts it | `engine/alerts/schema.py` |
