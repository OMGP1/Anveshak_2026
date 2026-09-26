# Audit of Your Five Documents

Every claim below was checked either against the official problem statement, against the arithmetic in your own documents, or against a primary source I looked up. Where I looked something up, I say so.

Findings are grouped:
- **§1 What's right** — keep these, they're your strengths
- **§2 Technical errors and internal contradictions** — E1–E12, with fixes
- **§3 Scope findings** — S1–S13, what to cut and why
- **§4 Gaps** — G1–G6, things the PS asks for that your documents don't cover
- **§5 Per-document verdict**

---

## §1 What's right — and it's a lot

These are correct, well-reasoned, and several are better than what most teams will bring. Keep every one.

| # | Decision | Why it's right |
|---|---|---|
| 1 | **Refusing full TCP stream reassembly.** Track flow-key + observed-flags bitmap + counters + timestamps instead. | Correct and directly responsive to the PS's "cannot complete any handshake itself." A Zeek-style reassembler on a one-legged tap corrupts state. This is the single best call in the pack. |
| 2 | **`completeness_flag` as a conditioning feature, not a data-quality caveat.** | Genuinely sophisticated. Asymmetric routing makes "SYN with no ACK" mean different things on different links, and training the model with the flag as an input is the right resolution. Lead your PPT with this. |
| 3 | **Bounded memory everywhere** — CMS/HLL/LRU/ring buffers, no unbounded dict keyed by 5-tuple. | This is the correct headline. "The monitoring system falls over exactly when the attack starts" is a real failure mode and you named it before an evaluator could. |
| 4 | **Lomb-Scargle periodogram over FFT for jittered beacons.** | Mathematically the right tool. FFT assumes uniform sampling; jitter smears the spectral peak. Lomb-Scargle is built for unevenly-sampled series. Great demo material. |
| 5 | **JA4 ↔ JA4T cross-layer disagreement as a first-class output.** | The best *original* idea in the pack. JA4 is set by the TLS library, JA4T by the OS kernel. A Chrome-on-Windows JA4 sitting on a Linux TCP stack is a strong spoofing signal that needs no destination reputation data. Cheap to build, hard to argue with. |
| 6 | **Two-tier inference cascade.** Cheap model on all flows, expensive model on a gated subset. | The correct answer to "does your ML become the bottleneck." Keep the structure, simplify the implementation. |
| 7 | **Asynchronous XAI — SHAP on alerts only, off the hot path.** | Correct. Alerts are orders of magnitude rarer than flows. |
| 8 | **Sliding rather than tumbling entropy windows.** | Correct — a tumbling boundary splits an attacker's signal across two windows. |
| 9 | **Normalized entropy H/log₂(k).** | Correct. Raw entropy isn't comparable across windows with different cardinality. |
| 10 | **Entropy collapse vs. entropy explosion as two separate features.** | Precise and useful — it lets the alert say *which* DDoS sub-type was seen. |
| 11 | **DGA: entropy AND n-gram fusion.** | Correct. Dictionary DGAs (Suppobox-style) have low character entropy and are invisible to entropy alone. |
| 12 | **Vertical / horizontal / strobe scan as three separate features.** | Good. A collapsed fan-out score loses the explainability the PS asks for. |
| 13 | **Load-shedding priority order: sketches preserved last.** | Correct and it's a great answer to a hostile question. |
| 14 | **Calibrated confidence (Platt/isotonic), not raw softmax.** | The PS asks for a confidence score. Calibrating it makes yours mean something. Genuine differentiator. |
| 15 | **Publishing a "detection ceiling" — what is physically unobservable.** | Judges reward this. ECH hides SNI, payload is always opaque; saying so first is strength, not weakness. |
| 16 | **Reproducible throughput harness with exact command lines.** | Directly satisfies constraint C-d, which most teams will fumble. |

---

## §2 Technical errors and internal contradictions

### E1 — Conservative Count-Min Sketch cannot be merged. Three of your checklist items are mutually incompatible. **(Severity: high)**

Your documents mandate all three of these:

- **Item 29:** conservative update is implemented ("we do not take the simpler standard-update shortcut")
- **Item 31:** CMS sketches merge across shards, "verified with a unit test asserting `merge(A,B) == merge(B,A)`"
- **Item 62:** push-based gossip merge every 1 second, giving a ≤1s staleness bound for cross-node attacks like distributed scans

These cannot all be true. Conservative update (Estan & Varghese's "minimal increment") improves accuracy on arrival-only streams but **removes the linearity property of the sketch, and with it the ability to merge**. This is stated directly in the Count-Min Sketch authors' own FAQ. Standard CMS is mergeable precisely because it is linear; conservative CMS is not.

There is a second, independent error stacked on top. Item 31 says CMS merges by **element-wise max**. For shards observing *disjoint* portions of the stream — which is exactly your symmetric-hash partitioning design — the correct merge for standard CMS is **element-wise sum**. Element-wise max is correct for HyperLogLog, and for CMS only when the sketches summarise the *same* stream. Merging disjoint-shard CMS by max systematically undercounts, which for a distributed scan detector means you miss the attack you built the merge for.

Your dossier's Phase 3.2 actually states this correctly — "element-wise max (if built with the same hash functions) **or sum** (if independently built and you want combined frequency)". The checklist collapsed the nuance to the wrong branch.

Third problem: the unit test you specified cannot catch either bug. `merge(A,B) == merge(B,A)` tests commutativity. Both max and sum are commutative. Both a correct and an incorrect implementation pass.

**Fix.** Pick one:
- **(Recommended for the hackathon)** Use **standard linear CMS**, merge by **sum**, keep mergeability. Accept slightly looser estimates. Make conservative update a config flag documented as *"single-node only — disables cross-shard merge."*
- Or drop cross-shard merging entirely (you don't need it for a single-node demo anyway) and keep conservative update.

**Replace the unit test** with one that actually tests correctness: build a sketch over stream S, build two sketches over a partition S₁ ∪ S₂ = S, merge them, and assert the merged estimates match the single-sketch estimates within the (ε,δ) bound. That test fails loudly on a max-vs-sum mistake.

---

### E2 — Your C2 beacon detector cannot work, because your own eviction policy deletes its state. **(Severity: high)**

PRD Situation B walks through detecting a **45-minute** jittered beacon using the 64-sample IAT ring buffer and Lomb-Scargle.

But your flow-state policy says:
- Item 20: idle-timeout-only termination, **default 120 seconds**
- Dossier Phase 2.2: flows idle **>5 minutes** are evicted regardless of LRU position (decayed TTL)

A flow that beacons every 45 minutes is idle for ~45 minutes between packets. Under a 120-second idle timeout it is evicted roughly 43 minutes before its second packet ever arrives. The IAT ring buffer never accumulates two samples, let alone 64. **The flagship scenario in your PRD is impossible under the architecture in your TRD.**

There's a second, compounding issue: 64 samples at a 45-minute period requires **48 hours** of continuous observation for a single flow. Nowhere in your documents is a 48-hour state-retention commitment budgeted, sized, or even acknowledged.

**Fix.** Beacon state must be a *separate structure* from the flow table, with a different lifetime:

```
BeaconCandidate table   — keyed by (src_ip, dst_ip, dst_port)
                        — TTL: 2–6 hours (configurable)
                        — hard cap: e.g. 50,000 entries, LRU
                        — holds: 64-sample IAT ring, packet/byte totals,
                                 first_seen, last_seen, dst_stability
```

Your own checklist item 40 hints at this — it says the ring buffer is "per (source, destination) pair" — but the TRD implements `IatRingBuffer` inside `FlowRecord`, inside the short-TTL flow table. Fix the TRD to match item 40, and state the maximum detectable beacon period explicitly as a function of the beacon-table TTL. Then say so in your documentation: *"at default settings we detect beacon periods up to N minutes; longer periods require raising the beacon-table TTL, at a stated memory cost."* Honest bounds beat implied omniscience.

---

### E3 — Your flow record cannot tell forward from reverse. **(Severity: high, and it's a real bug)**

Your `FlowKey` canonicalises addresses:

```rust
pub ip_lo: u32,   // min(src_ip, dst_ip) after canonical ordering
pub ip_hi: u32,   // max(src_ip, dst_ip)
```

That's correct for symmetric partitioning — both directions of a conversation hash to one key. But `FlowRecord` then stores `pkts_fwd`, `pkts_rev`, `bytes_fwd`, `bytes_rev` and a `Directionality` enum — and **there is no field recording which of `ip_lo` / `ip_hi` was the initiator.** The canonical ordering has thrown that information away. "Forward" is undefined.

This matters a great deal, because threat class (f) — data exfiltration — is defined by the PS as "unusual **outbound-to-inbound** byte ratios." If you can't orient the flow, you can't compute the ratio, and detector (f) doesn't work. It also breaks the SPLT directional signing (`client=+, server=−`) that Tier 2 depends on.

**Fix.** Add one bit:

```rust
pub struct FlowRecord {
    // ...
    pub initiator_is_lo: bool,  // true if ip_lo sent the first packet / SYN
}
```

Then `fwd` is defined as "from the initiator." Checklist item 27 gestures at the SYN-originator heuristic but the struct never stores the result. Also note: on a one-legged tap you may never see the SYN, so you need a documented fallback (first-packet-seen, with a `orientation_confidence` flag) — and that fallback should itself be a feature, in the same spirit as `completeness_flag`.

---

### E4 — HyperLogLog: the code and the memory proof disagree, and the sizing is wrong for per-key use. **(Severity: medium-high)**

Two separate problems.

**(a) Code contradicts proof.** TRD §1.4 declares:
```rust
pub struct HyperLogLogPP {
    registers: [u8; 16384],   // m = 2^14, 6-bit values packed conceptually
}
```
That is 16,384 bytes — one full byte per register. TRD §2.2 then "proves" the footprint is `16384 × 6/8 = 12,288 bytes (packed)`. The comment says "packed conceptually," which is doing a lot of work: the declared type is not packed, so the real cost is 16 KB, 33% above the proof. Either implement 6-bit packing or fix the proof. A reviewer who reads both will notice.

**(b) The real problem: m = 2^14 is far too large for per-key sketches.** Your documents use HLL for:
- per-source distinct destination ports (port scan)
- per-source distinct subdomains (DNS tunnelling)
- per-destination distinct sources (DDoS fan-in)

These are **per-key** sketches — you need one per tracked source or destination. At 12–16 KB each, tracking even 100,000 sources costs **1.2–1.6 GB for one HLL family alone**, and you have three. Your bounded-memory proof only ever computes the cost of a *single* sketch and never multiplies by cardinality. This is the biggest hole in the memory argument, and it's the exact thing an evaluator probing your headline claim will find.

**Fix.** Separate global sketches from per-key sketches and size them differently:

| Sketch | Scope | m | Bytes | Std. error | Enough to... |
|---|---|---|---|---|---|
| Global source-IP cardinality | one | 2^12 = 4096 | ~3 KB | 1.6% | track link-wide fan-in |
| Per-source distinct dst-ports | per source | **2^8 = 256** | ~192 B | ~6.5% | separate "3 ports" from "3000 ports" |
| Per-source distinct subdomains | per source | **2^8 = 256** | ~192 B | ~6.5% | separate normal from tunnelling |

A 6.5% error is completely adequate for port-scan detection — you are distinguishing orders of magnitude, not measuring precisely. Dropping from 2^14 to 2^8 cuts per-key HLL memory by **64×** and turns an unbounded-in-practice claim into a genuine one. Keep HLL++ bias correction; it matters most in exactly the low-cardinality regime where a scan begins.

---

### E5 — Allocating a 512-byte IAT ring buffer to every flow wastes ~85% of your flow-table memory. **(Severity: medium, but the fix is a big win)**

Your per-flow arithmetic:

```
sizeof(FlowRecord) + 64 × 8 bytes (IAT samples) ≈ 96 + 512 = 608 bytes
608 × 2,000,000 entries ≈ 1.2 GB
```

The arithmetic checks out. But look at the split: **512 of those 608 bytes are the IAT ring buffer**, and its only consumer is C2 beacon detection. You are paying 1 GB to run periodicity analysis on two million flows, of which essentially none are beacons.

**Fix.** Allocate the IAT buffer **lazily**, only to flows that pass a cheap beacon pre-filter — for example ≥4 packets observed, low total byte volume, small stable destination set, non-trivial inter-arrival gap. Everything else keeps a bare ~96-byte record.

At a realistic 2% candidate rate:
```
2,000,000 × 96 B  +  40,000 × 512 B  ≈  192 MB + 20 MB  ≈  212 MB
```
That is an **83% reduction**, and combined with the E2 fix (beacon state in its own long-TTL table) it makes both the memory story and the beacon story correct at once. This is the highest-value single change in this document.

---

### E6 — "Merkle" is the wrong word, and the O(log n) claim is wrong. **(Severity: medium — it's a credibility issue, not a functional one)**

Your design is a **linear hash chain**: each record stores `prev_hash = SHA-256(previous record)`. That is a blockchain-style append-only log. It is *not* a Merkle tree, and calling it a "Merkle hash chain" throughout will be noticed by anyone on an NTRO panel.

The consequence shows up in PRD Situation D, which claims the chain-walk is an "**O(log n)-ish** chain-walk operation." It isn't. Verifying a linear hash chain from an anchor to a target record is **O(n)** in the number of records between them. Your own dossier Part 3.3 says this correctly: "chain-verification is a cheap, periodic **O(n)** integrity check." The PRD contradicts the dossier.

**Fix — pick one and be consistent:**
- **Simple (recommended):** keep the linear chain, call it a "hash-chained append-only ledger," and state O(n) verification with hourly signed anchors bounding the walk length. This is honest, cheap, and completely adequate.
- **Ambitious:** build an actual Merkle tree / RFC 6962-style transparency log, which genuinely gives you O(log n) inclusion proofs. More work, but then the word "Merkle" is earned and the O(log n) claim is true.

Do not keep the current mixture, where the name promises one thing and the implementation delivers another.

---

### E7 — 15 µs was an amortized average in one document and became a p99 SLO in another. **(Severity: medium)**

- Dossier Phase 2.4: "target **≤15μs/flow amortized with batching**"
- TRD §3.1 and checklist item 50: "**p99 ≤ 15µs/flow** — average-case latency is explicitly not the reported SLO"

These are different quantities and the second is much harder than the first. For a batched tree ensemble on a shared CPU with GC, cache misses, and scheduler jitter, p99 is routinely 3–10× the amortized mean. You have committed, in writing, to a number you derived as an average, promoted to a tail metric, and then declared you will fail the build on.

Insisting on p99 over average is exactly the right instinct — that part is good. The mistake is applying it to a number that was never measured as a tail. **Fix:** measure first, then set the SLO. State p50 *and* p99 as separate measured numbers and let them be whatever they are. A truthful "p50 8 µs, p99 47 µs" is far stronger than a missed 15 µs p99.

---

### E8 — Treelite no longer compiles models. Your stack reference is two major versions out of date. **(Severity: low, but easily caught)**

Your documents specify "Treelite-compiled shared library" for Tier 1 in at least six places. **From Treelite 4.0, Treelite no longer supports compiling tree models into C code** — that functionality was split out into a separate project, **TL2cgen**. Modern Treelite is a model-exchange and serialisation library; TL2cgen is the compiler and provides the `Predictor` runtime.

**Fix.** The current-correct phrasing is: *"Treelite for model loading/serialisation, TL2cgen (`tl2cgen.export_lib`) for compiling to a native shared library, `tl2cgen.Predictor` for inference."* One sentence, and it signals you actually know the tooling rather than having read a 2022 blog post. (Practical note: for a hackathon, LightGBM's own C++ predictor is fast enough, and ONNX Runtime is a simpler story. See `03_Tech_Stack_And_Architecture.md`.)

---

### E9 — JA4+ licensing. Your "we audited every component" claim has a hole in it. **(Severity: low for SIH, high if you ever productise)**

Checklist item 82 claims every chosen component was audited for licensing and phone-home behaviour. The JA4 suite was not.

The split is: **JA4 (TLS client fingerprinting) is BSD 3-Clause** — freely usable. But **JA4S, JA4T, JA4L, JA4H, JA4X, JA4SSH, JA4TS and the rest of JA4+ are under the FoxIO License 1.1**, which is permissive for academic and internal-business use but **not permissive for monetisation**; selling JA4+ as part of a product requires an OEM licence from FoxIO.

Your entire cross-layer innovation (§4.3, item 85) rests on **JA4T**, which is on the restricted side of that line.

**For SIH this is fine** — a student hackathon project is academic use. But two things follow:
1. You must include the FoxIO License 1.1 text and attribution in your repo. It's a condition, not a courtesy.
2. Your "this is deployable at NTRO / this is a product" framing needs a footnote, because a government procurement is not obviously "internal business use by the licensee."

**Fix, and it's a good one:** implement the TCP fingerprint yourself in **p0f style** — initial TTL, window size, MSS, TCP options ordering, window scale. It captures the same kernel-level signal, it's the classic prior art, it is completely licence-clean, and it lets you say *"we implemented our own OS fingerprint rather than taking a restrictively-licensed one."* Optionally emit the JA4T-format string too, behind a feature flag, for tool parity. This turns a licensing gap into a differentiator.

---

### E10 — You cite CERT-In but mandate the wrong clock control. **(Severity: low)**

Your documents make hardware **PTP** timestamping a non-negotiable requirement and cite CERT-In compliance as part of the surrounding justification. CERT-In's 2022 Directions — issued 28 April 2022 under IT Act §70B(6) — do contain a clock mandate, but it is **NTP synchronisation to the NIC (National Informatics Centre) or NPL (National Physical Laboratory) time servers, or servers traceable to them.** Not PTP.

The 6-hour reporting window and the 180-day rolling ICT log retention that you cite are both **correct** — I verified them. But if you are going to claim regulatory alignment, cite the actual control. Naming NIC/NPL NTP traceability is a small detail that reads as genuine familiarity; mandating PTP while citing CERT-In reads as having skimmed a summary.

(PTP is stricter than NTP so it would satisfy the requirement — but nobody at a hackathon has a PTP grandmaster, and with replayed data your timestamps come from the capture file anyway. See scope finding S4.)

---

### E11 — Your throughput numbers disagree across documents. **(Severity: low, but it's the number judges will fixate on)**

| Document | Claim |
|---|---|
| Dossier Phase 2.4 | 66,600 flows/s per core × 8 cores = **~500,000 flows/sec** |
| Dossier Phase 4.4 | **≥100,000 flows/sec** sustained on demo hardware, single inference-node pool |
| PRD §3.2 NFR | **≥100,000 flows/sec single-node** |

500,000 is described as an 8-core single-node figure in one place while "single-node" means 100,000 in another. The arithmetic in each is fine on its own (1/15 µs ≈ 66,667 ✓). But constraint **C-d requires you to state and demonstrate a rate**, and three different numbers in one submission is exactly the inconsistency a screener flags.

**Fix.** State exactly two numbers, define both precisely, measure both: a **demonstrated** rate (what you actually ran, on named hardware) and a **projected** rate (with the scaling assumption stated as an assumption). Never let a third number appear.

---

### E12 — Situations A and item 21 frame the same feature in opposite directions. **(Severity: low)**

- **Item 21:** half-open SYN with `completeness_flag = 0` "is **exactly the volumetric-DDoS signal**, fed directly into the SYN:SYN-ACK ratio feature."
- **PRD Situation A, step 3:** the model "does **not** treat 'no ACK visible' alone as the anomaly signal on this link."

Both are defensible — the reconciliation is that completeness is a *conditioning* input rather than a *trigger*, and the actual trigger is rate-of-change plus entropy explosion. But a judge who reads both sentences will ask you to reconcile them on the spot. Write the reconciliation into the documents now, in one sentence, rather than improvising it under questioning.

---

## §3 Scope findings — what to cut, and why

Each of these is well-executed work that answers a question SIH26145 did not ask.

| # | What | Where | Verdict |
|---|---|---|---|
| **S1** | Optical diode physics: beam-splitter ratios, insertion-loss budgets, receive-only SFP BOM, IEEE 802.3ah link modes, optical power meter acceptance tests, receiver saturation | Checklist Domain 1 (items 1–9), Dossier Phase 1.1 | **Cut to one PPT slide.** The PS *gives* you the diode as environment. You cannot buy, build, or demo any of this. Nine checklist items of pure paper. |
| **S2** | AF_XDP + Rust + UMEM sizing + RSS symmetry + NUMA pinning + ring-depth matching | Checklist Domain 2, TRD §2.1, Track 1 | **Cut from the build; keep as a one-line "production scale-out path."** The PS input is *simulated IP data*. You will also never get root + an XDP-capable NIC at a nodal centre. |
| **S3** | Redpanda broker, symmetric partitioning, cooperative rebalancing, multi-node scaling curve | Checklist Domain 7, TRD §1.2 | **Cut.** A bounded in-process `asyncio.Queue` gives you the same backpressure story for zero operational cost. Multi-node scaling is not requested. |
| **S4** | Hardware PTP timestamping as a mandatory requirement | Item 9, item 72, item 103 | **Cut.** With replayed data, timestamps come from the capture. See E10. |
| **S5** | ClickHouse cold storage, 180-day retention, storage-budget maths, compression-ratio validation | Item 79, item 99, Dossier Phase 1.3 | **Cut ClickHouse; use DuckDB.** Retention is not requested. Keep the 389 TB calculation as *one slide* — it's a genuinely good argument for metadata-only retention, which is a design principle worth stating. |
| **S6** | Crypto-shredding, per-day data-encryption keys, HSM-logged key destruction | Item 108, TRD §4.2 | **Cut entirely.** Not requested, not demoable, high build cost. |
| **S7** | HSM/TPM-backed signing, key rotation, revocation | Item 86, TRD §4.2 | **Downgrade.** A local Ed25519 key via the `cryptography` library gives you the identical demo for ~20 lines. Say "HSM in production" on a slide. |
| **S8** | Ed25519 air-gapped update channel, write-once media, canary validation, one-click rollback | Dossier Phase 3.3, Situation F, Track 4 week 12 | **Cut to a slide.** Genuinely interesting problem, zero marks available. |
| **S9** | Five personas with RBAC, CISO compliance workspace, retention-integrity dashboard, key-destruction log view | PRD §1, Track 4 | **Cut to two roles at most.** The PS says "simple dashboard." Every hour here is an hour not spent on R15/R19. |
| **S10** | CERT-In reporting workflow, IT Act §70 Protected System mapping | Dossier Phase 1.3, Domain 12 | **Downgrade to one button + one slide.** A "generate incident report" button is a cheap, nice touch. The compliance *architecture* is not. |
| **S11** | Chaos engineering suite, Chandy-Lamport coordinated checkpointing, 20-second warm-up windows, post-reboot threshold raising | Checklist Domain 11, Track 3 | **Cut.** Distributed-systems resilience for a system that will run as one process on one laptop. |
| **S12** | Modbus/TCP + MQTT OT demonstration on Raspberry Pi | Dossier Phase 4.3, Track 3 week 9 | **Cut or make it strictly optional.** It's a second project. The PS never mentions OT/ICS. |
| **S13** | SimCLR-style contrastive pretraining for the Tier-2 sequence encoder | Item 84, Dossier Phase 4.2, Track 2 week 6 | **Replace with something cheaper.** The zero-day story is worth having, but a benign-only autoencoder or IsolationForest gets you 80% of the narrative for 20% of the work — and is far easier to explain to a judge in 90 seconds. |

**Rough total: 60–70% of the content across the five documents falls into this table.** That is not a criticism of the thinking; it is a statement that the thinking was aimed at a production CII deployment rather than at SIH26145.

---

## §4 Gaps — what the PS asks for that your documents don't cover

### G1 — No input format contract. **(This is the biggest single omission.)**

The PS names its inputs explicitly: "packet captures, exported flow records (**NetFlow/IPFIX/sFlow**), and derived metadata." Nowhere in 170 KB of documentation is there a specification of what your pipeline actually reads. Your architecture jumps straight from AF_XDP raw frames to feature extraction. There is no PCAP reader, no flow-record parser, no schema for the "simulated IP data" the PS hands you.

**This is the first thing to build.** Two adapters behind one interface: PCAP replay and flow-record replay.

### G2 — No replay controller.

The PS says "live **or replayed** detections." Replay is your entire demo — it's the only thing that works at a venue. But nothing in your documents specifies a replay controller: scenario selection, speed multiplier, seek, pause, virtual-clock handling. This is a core deliverable that currently doesn't exist on paper.

### G3 — Training and validation methodology is essentially absent. **(This is deliverable #2 in the PS.)**

The PS explicitly requires "accompanying documentation of the model(s) used, features engineered, and the **training/validation approach**." Your documents describe *which* models and list metrics, but never specify:
- the train/validation/test split protocol
- **temporal** splitting (you must not train on flows from the same capture window you test on — that's leakage, and it's the single most common flaw in published NIDS results)
- how the synthetic attack traffic and benign traffic are combined
- hyperparameter search protocol
- what the **class prevalence in the test set** is

### G4 — The class-imbalance argument contradicts your own training plan.

Your documents argue at length that malicious flows are <0.01% of real backbone traffic, and correctly mandate PR-AUC over ROC-AUC on that basis. But your training data is **synthetic and self-generated** — its class balance is whatever you choose. If you generate a roughly balanced set and report PR-AUC on it, that PR-AUC says nothing about the <0.01% regime you used to justify the metric.

An NTRO evaluator will absolutely ask this. **Fix:** construct the test set at a stated, realistic prevalence (e.g. 1 attack flow per 1,000–10,000 benign) even if you train on a rebalanced set, and report the prevalence alongside every metric. Then your PR-AUC means what you claim it means. Doing this is roughly half a day and it converts your biggest exposed flank into a strength.

### G5 — No repository structure, README, or run instructions.

The PS asks for "a working prototype (**source repository**)." Your five documents contain no repo layout, no dependency list, no build steps, no `make demo`. A screener who cannot run your thing in one command will assume it doesn't run. See `04_Prototype_Build_Spec.md`.

### G6 — No use of any public benchmark dataset.

Everything is synthetic. Adding one public labelled dataset — CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, or CTU-13 for the botnet class — gives you a number that is comparable to published work, which is a large credibility gain for roughly one day of work. (If you use CIC-IDS2017, note that its labelling has been criticised in the literature and corrected versions exist; mentioning that you know this is itself a good look.)

---

## §5 Per-document verdict

| Document | Verdict |
|---|---|
| **Technical Feasibility Dossier** (61 KB) | **The strongest of the five.** Parts 1.1, 1.2, 2.1–2.5 are genuinely good and should survive largely intact — the threat/evasion/defence matrix in §1.2 is excellent and maps cleanly onto the PS's six classes. Parts 3.1, 3.3, and 4.4's regulatory content are out of scope. Errors: E1, E4, E5, E7, E9. **Action: keep ~50%, becomes your technical appendix.** |
| **108-Item Checklist Resolution** (50 KB) | **Impressive discipline, wrong target.** Domains 4, 5, 6 are your best material and directly serve the PS. Domains 1, 2, 7, 11, 12 are almost entirely out of scope — that's about 55 of the 108 items. Errors: E1 (items 29/31/62), E4 (item 30), E7 (item 50), E9 (item 82), E10 (items 9/72/103). **Action: keep Domains 3–6 and 8–10, drop the rest.** |
| **PRD** (22 KB) | **Over-scoped in personas, valuable in scenarios.** The five personas are 2.5× what the PS asks for. But Situations A–C are excellent — they are essentially your demo script already written. Situations D–F are compliance and resilience theatre. Errors: E2 (Situation B), E6 (Situation D), E11, E12. **Action: keep Situations A–C as the demo storyboard, cut personas to two, rewrite §3.2 with real measured numbers.** |
| **TRD** (19 KB) | **Best structure, most concrete errors.** The C4 decomposition is the right way to present this and the L4 structs are the right level of detail — that's a genuine strength. But the structs contain the E3 orientation bug and the E4 HLL contradiction, and the whole ingest layer (§2.1) is built on a stack you shouldn't use. Errors: E3, E4, E5, E6, E7, E8. **Action: keep the C4 approach and redraw all four levels against the corrected stack.** |
| **Implementation Plan** (17 KB) | **Least salvageable — it's a plan for a different calendar.** 12 weeks across 4 tracks, against a 23-day submission deadline and a 36-hour finale. The test criteria and "Done" definitions are well-written and worth reusing as a QA checklist. **Action: discard the schedule, keep the test criteria, replace with `05_Timeline_And_Plan.md`.** |

---

## §6 One thing worth saying plainly

The volume and rigour of these documents is well above typical SIH work, and the instinct behind them — anticipate the hostile question before the evaluator asks it — is exactly right. Domain 4 and Domain 5 in particular are the work of someone who understands streaming systems.

The failure mode here is a specific and common one: the documents were written to survive a **production defence-procurement review**, and they would do reasonably well at one. But SIH26145 is judged on a working prototype, a simple dashboard, a demonstrated throughput number, and documented training methodology — and on those four axes, 170 KB of architecture is currently worth less than 2,000 lines of running Python.

The good news is that the hard thinking is already done. What's left is subtraction and building.
