# Tech Stack & Architecture

## 1. The four tests every choice must pass

Because the Grand Finale is 36 hours on venue hardware, every component must pass all four:

1. **Runs on a laptop.** No cluster, no special NIC, no GPU requirement.
2. **Runs without root.** You will not get sudo on a nodal-centre machine, and you cannot attach XDP programs or open raw sockets without it.
3. **Runs offline.** Assume the venue wifi is unusable. No model downloads, no package installs, no API calls at demo time.
4. **Generates no hostile traffic.** You cannot run `hping3 --flood` at a venue. All attack traffic must be pre-captured and replayed from files in your repo.

Your current stack fails tests 1, 2, and 3.

---

## 2. The stack

| Layer | Choice | Why |
|---|---|---|
| **Language** | Python 3.11+ (single language for the engine) | Team velocity beats theoretical throughput when the deadline is 23 days. One language means one debugging surface at 3 a.m. during a 36-hour build. |
| **PCAP parsing** | `dpkt` | Roughly an order of magnitude faster than Scapy for bulk parsing and has no import-time cost. Use Scapy only for *generating* test traffic offline, never in the hot path. |
| **Numerics / sketches** | `numpy` | CMS is a `uint32` 2-D array; HLL is a `uint8` array. Vectorised batch updates. |
| **Flow table** | Custom LRU over a `dict` + `collections.deque`, hard-capped | Explicit cap is the whole point. Do not use an unbounded dict — the bounded-memory claim is your headline. |
| **Tier-1 model** | **LightGBM** | Fast native C++ predictor, native class weighting, and `predict(pred_contrib=True)` gives you **exact TreeSHAP for free** as a byproduct — which collapses your entire async SHAP worker pool into one function argument. |
| **Tier-2 model** | **ONNX Runtime** (CPU) — 1D-CNN over SPLT | Small, quantisable, no GPU, single dependency. |
| **Anomaly layer** | `sklearn` IsolationForest, *or* a 3-layer autoencoder trained benign-only | The zero-day story, without the SimCLR build cost. |
| **Calibration** | `sklearn.calibration.CalibratedClassifierCV` (isotonic) | Three lines. Turns your confidence score into a real probability. |
| **Alert schema** | STIX 2.1 via the `stix2` library, with `x_` extensions | Exceeds constraint C-e cheaply, and the library validates for you. |
| **Ledger** | Append-only JSONL + SHA-256 `prev_hash` chain + Ed25519 head signature via `cryptography` | ~80 lines. Theme tie-in. Demoable in 20 seconds. |
| **Storage** | **DuckDB** | Embedded, columnar, zero-config, fast analytical queries, single file. Gives you the ClickHouse story at zero operational cost. |
| **API** | **FastAPI** + WebSocket | Async, one process, WebSocket push for the live alert stream. |
| **Queueing** | `asyncio.Queue` with `maxsize` set and an explicit drop policy | Your backpressure and load-shedding narrative, minus Redpanda. When the queue is full you shed L7 features first, then sample — exactly the hierarchy you already designed. |
| **Dashboard** | **React + Vite + TypeScript**, `recharts` or `d3` for charts | Plays to your existing strength. Vite dev server is instant. |
| **Packaging** | `docker compose up` → engine + API + UI | One command. This matters more than you'd think. |
| **Traffic generation** | `scapy` / `hping3` / `dnscat2` in a Docker lab, **run once offline**, output committed as small PCAPs | Satisfies the PS's named tooling without needing any of it at the venue. |

---

## 3. The swaps, and the reasoning for each

### Rust + AF_XDP → Python + PCAP/flow-record replay

The PS input is "**simulated IP data**." You are not capturing from a wire. AF_XDP needs root, an XDP-capable driver, and a machine you control — none of which you have in December. It is also 3–4 weeks of work that produces nothing a judge can see.

**Keep the Rust story as a stated production path.** One PPT line: *"The prototype's ingest is a replay adapter; for production line-rate capture we specify Rust + AF_XDP, benchmarked separately."* You get the credibility with none of the risk.

**Optional stretch, if you have a Rust developer:** write *only* the flow table and sketches as a Rust extension via **PyO3 / maturin**, keeping everything else Python. That's a 1–2 day job, gets you past 500k flows/sec, and gives you a real, honest Rust story. This is the highest-value optional item in the whole package. Do it in November if you're shortlisted, never before 30 September.

### Redpanda → bounded `asyncio.Queue`

Redpanda solves multi-node partitioning and durability. You have one node and a replay file. A bounded queue with an explicit drop policy gives you the identical *architectural narrative* — "we never buffer unboundedly; here is the shedding order" — for zero deployment cost. It also means one process instead of a cluster you have to babysit during a demo.

Also, in passing: Redpanda's core is under the Business Source License, not an OSI-approved open-source licence. Your checklist item 82 claims every component was licence-audited; that one has a footnote.

### ClickHouse → DuckDB

Both are columnar. DuckDB is a Python import with a single file on disk, no server, no config, no container. For alert history, replay analytics, and the evidence-bundle query it is more than fast enough, and it removes an entire operational dependency from your demo. If a judge asks about scale, "DuckDB embedded for the prototype, ClickHouse for the production tier" is a perfectly good answer.

### Treelite → LightGBM native (+ optional TL2cgen)

Two reasons. First, **Treelite 4.0 removed model compilation** — that moved to TL2cgen, so your documents' phrasing is out of date (finding E8). Second and more practically, LightGBM's built-in predictor at your tree depths is fast enough for the demonstrated throughput, and `pred_contrib=True` gives you exact TreeSHAP as a free byproduct of the same call.

That last point deletes a whole subsystem. Your TRD specifies an async SHAP worker pool, a queue high-water mark, and a split-gain fallback path. With LightGBM you get exact per-alert attributions from the prediction call. Keep the async-queue design *as a slide* explaining what you'd do at production alert volumes; don't build it.

If you want the compiled-inference story for the finale, add TL2cgen as an optional backend behind a flag and benchmark both. That's a nice "we measured it" table.

### HSM → local Ed25519

`cryptography`'s Ed25519 API is four lines to generate, sign, and verify. The demo — tamper a ledger record, run `verify`, watch it fail — is identical. Say "HSM-backed in production" on the slide.

### Five personas → two views

**Analyst view** (the alert queue, evidence, and the live throughput meter) and **Operations view** (memory, latency, shedding state, coverage report). That's it. The PS says "simple dashboard."

---

## 4. Corrected architecture — C4 levels

Keep the C4 approach from your TRD; it's the right presentation. Here it is redrawn against the corrected stack.

### L1 — Context

```
[ Simulated traffic source ]
   • PCAP files (pre-captured attack + benign scenarios)
   • Synthetic flow-record generator (NetFlow/IPFIX-style)
            |
            |  one direction only — replay adapter, read-only
            v
[ Detection Enclave  (single process, no outbound sockets) ]
            |
            |  alerts + metrics, local only
            v
[ Analyst Dashboard  (localhost) ]
```

The **read-only invariant** is now enforced by three things you can actually demonstrate on a laptop:
1. The replay adapter has no write path back to the source — it opens files read-only.
2. No component in the detection path constructs an outbound socket. Prove it with a CI check that greps for `socket`, `requests`, `httpx`, `urllib` outside the API layer, and by running the engine with network egress blocked in the container.
3. Payload bytes are discarded at the parse boundary, before the feature-extraction module is called — a structural boundary, not a coding convention (this is your dossier's own Part 1 gap #5, and it's a good idea; implement it as an actual module boundary where the parser returns a `FlowMetadata` object that has no payload field at all).

That third one is worth emphasising: it means constraint **C-b (no decryption)** is satisfied by *type*, not by promise. If a judge asks "what stops a developer piping payload into a feature six months from now," the answer is "the object they'd have to pipe it from doesn't have the field."

### L2 — Containers

```
┌─ Detection Engine (Python, one process) ────────────────┐
│                                                          │
│  ReplaySource ──> Decoder ──> FlowTable ──> Features     │
│    (pcap|flow)    (drops       (LRU,        (sketches,   │
│                    payload)     capped)      entropy,    │
│                                              JA4, SPLT)  │
│                                                 │        │
│                                                 v        │
│                                          Tier1 (LightGBM)│
│                                                 │        │
│                                        gate ────┤        │
│                                                 v        │
│                                    Tier2 (ONNX) + Anomaly│
│                                                 │        │
│                                                 v        │
│                                    AlertBuilder (STIX)   │
│                                          │               │
│                              ┌───────────┴──────┐        │
│                              v                  v        │
│                     HashChainLedger        DuckDB        │
│                       (JSONL)             (history)      │
└──────────────────────────────┬───────────────────────────┘
                               │ bounded asyncio.Queue
                               v
                    ┌─ FastAPI + WebSocket ─┐
                    └──────────┬────────────┘
                               v
                    ┌─ React Dashboard ─────┐
                    └───────────────────────┘
```

### L3 — Feature extraction internals

```
Decoder ──> FlowTable (LRU, hard cap N_flows)
              │
              ├──> CountMinSketch      (global, standard/linear update, mergeable)
              ├──> HyperLogLog_global  (m = 2^12)
              ├──> HyperLogLog_perkey  (m = 2^8, per source)   ← E4 fix
              ├──> SlidingEntropy      (1s / 5s / 60s, roll-forward)
              ├──> WelfordMoments      (streaming skew/kurtosis)
              ├──> TLSFingerprint      (JA4 + p0f-style TCP fp)  ← E9 fix
              ├──> SPLTBuilder         (N = 20, signed by direction)
              └──> DNSFeatures         (entropy, bigram LL, qtype, length)

BeaconTable  (SEPARATE, TTL 2–6h, cap 50k, lazy alloc)          ← E2 + E5 fix
              └──> IATRing(64) ──> LombScargle
```

Two structural fixes are visible here and both matter:
- **BeaconTable is not inside FlowTable.** Different lifetime, different cap, allocated lazily only for flows passing a cheap pre-filter. This is what makes long-period beacon detection actually possible (E2) and cuts flow-table memory by ~83% (E5).
- **HLL is split into global and per-key instances at different sizes.** This is what makes the bounded-memory claim survive multiplication by cardinality (E4).

---

## 5. Corrected memory budget

State this in your PPT. It's defensible because every line is a real allocation you can point at.

| Structure | Sizing | Bytes |
|---|---|---|
| Flow table | 500,000 entries × ~96 B | ~48 MB |
| Flow table index + LRU overhead | ~500,000 × ~64 B | ~32 MB |
| Beacon table | 50,000 × (96 + 512) B | ~30 MB |
| CMS (global, w=2719 d=5, u32) | fixed | 54 KB |
| HLL global (m=2^12) | fixed | 3 KB |
| HLL per-source (m=2^8) × 100,000 sources | 100,000 × 192 B | ~19 MB |
| Entropy windows (3 scales × 60 buckets) | fixed | < 1 MB |
| Models (LightGBM + ONNX CNN + IsolationForest) | loaded once | ~30 MB |
| **Total steady-state ceiling** | | **≈ 160 MB** |

Under 200 MB, fully pre-allocated, invariant to attack volume. That is a claim you can prove live by running a flood scenario with a memory graph on screen and showing the line flat — see `06_Differentiators_And_Demo.md`, item 6.

Compare to your current documents' 1.2 GB for the flow table alone, with three unbounded HLL families uncounted. The corrected number is both smaller *and* actually true.

---

## 6. What "streaming" means concretely (constraint C-c)

Every detector must be an online algorithm with O(1) per-event cost and bounded state. Concretely:

| Detector | Online mechanism | State bound |
|---|---|---|
| DDoS rate | EWMA per destination (α=0.1), kσ trigger | O(1) per dest, capped dest table |
| DDoS entropy | Sliding window, roll-forward add/subtract | 3 windows × 60 one-second buckets |
| Beaconing | Ring buffer + Lomb-Scargle on promotion only | 64 samples per candidate |
| DGA | Per-query stateless scoring (entropy + bigram LL) | Markov model loaded once, fixed |
| DNS tunnelling | Per-source subdomain HLL | 192 B per source |
| Encrypted malware | Per-flow JA4 + TCP fp + SPLT(20) | Fixed per flow |
| Port scan | Per-source dst-port and dst-host HLL | 2 × 192 B per source |
| Exfiltration | EWMA of outbound:inbound ratio per (src, dst) | O(1) per pair, capped |

No detector requires the full stream. No detector's memory grows with stream length. That's the property, and it's worth stating exactly this way in your documentation — it's the single strongest architectural claim you have.

---

## 7. Things to keep from the original stack

Not everything should change:

- **The two-tier cascade.** Correct, keep it, just implement it with LightGBM + ONNX rather than Treelite + a Rust inference loop.
- **The promotion gate** (confidence in [0.3, 0.7] OR encrypted-malware candidate OR a 0.1% QA sample). Well-designed. Keep exactly as specified, and *log the gate as a versioned config value* as you proposed — that's a good instinct.
- **The load-shedding priority order** (sketches preserved last, L7/SPLT shed first). Correct. Implement it against the `asyncio.Queue` depth instead of an AF_XDP fill ring.
- **Split-gain fallback** as a *concept*. You won't need it (LightGBM gives you SHAP free), but keep it as a slide showing you thought about attribution cost at production alert volumes.
- **The coverage report** (`high_confidence` / `low_confidence` / `unclassifiable_opaque` fractions). Cheap, honest, and nobody else will do it. Build it.
- **The detection-ceiling appendix.** Keep it verbatim. It's good.
