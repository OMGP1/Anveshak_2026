# Timeline & Plan

Replaces the 12-week / 4-track Implementation Plan, which was written against a calendar that doesn't exist.

---

## 1. The real calendar

| Window | What's due | What actually gets judged |
|---|---|---|
| **Now → mid-Sept** | College internal hackathon | A PPT + ideally something running. This is where most teams are eliminated. |
| **→ 30 Sept 2026** | **National idea submission via SPOC** | Idea PPT + video. Hard deadline. |
| **October** | National screening | Nothing from you — reviewers score the submission. |
| **November** | Finalist announcement, mentoring | Refinement if shortlisted. |
| **December** | **Grand Finale — 36 continuous hours** | A live working demo in front of judges. |

Two facts reshape everything:

**Between now and 30 September you are selling an idea.** ~23 days. The submission is a PPT and a video. Nobody clones your repo at this stage. But a video of something *actually running* is worth more than any number of architecture diagrams, because it proves feasibility in a way slides cannot.

**The Grand Finale is 36 hours.** You do not build a system in 36 hours — you *arrive* with a system and spend 36 hours integrating, hardening, and rehearsing. Anything not working before you travel will not work at the venue.

---

## 2. Phase 1 — now to internal hackathon (~1 week)

**Goal: something runs, and the story is clear.**

| Day | Deliverable |
|---|---|
| 1 | Reconcile scope with the team. Read `01_Problem_Statement_Verified.md` §3 together. Agree the cut list from `02_Audit_Of_Your_Documents.md` §3. Assign owners. |
| 1–2 | `FlowMetadata` + PCAP source + LRU flow table. Prints flows from a PCAP. |
| 2–3 | Rule-based DDoS and port-scan detectors. Prints alerts. |
| 3–4 | FastAPI + WebSocket + a minimal React alert list. |
| 4 | Metrics + the **on-screen throughput/latency meter**. |
| 5 | Generate scenarios 1, 2, 9 as PCAPs. Commit them. |
| 5–6 | The internal-hackathon PPT (use the official SIH template — colleges reject non-template decks). |
| 6–7 | Rehearse the demo. Twice. Time it. |

**Internal hackathon deck outline (10–12 slides on the SIH template):**
1. The problem in one sentence — a monitoring enclave that can only watch, never touch
2. The six threat classes, mapped to the passive signal each leaves behind
3. Why this is hard: no handshakes, no decryption, no return path, asymmetric routing
4. Architecture — the C4 L2 diagram from `03_Tech_Stack_And_Architecture.md`
5. **Bounded memory** — the ~160 MB table. This is your headline.
6. Two-tier cascade and why explainability isn't the bottleneck
7. **The JA4 ↔ TCP-fingerprint idea.** Your best original contribution.
8. Live demo — 90 seconds
9. Throughput and latency, measured, with hardware stated
10. What we deliver: repo, dashboard, model docs, benchmark
11. Roadmap to the Grand Finale
12. Team

Slide 5 and slide 7 are what people will remember. Build the whole deck around them.

---

## 3. Phase 2 — internal hackathon to 30 September (~2 weeks)

**Goal: a demo video that makes the screener believe you can finish this.**

| Days | Deliverable |
|---|---|
| 1–3 | Sketches: CMS (linear/mergeable), HLL (split global 2^12 / per-key 2^8), sliding entropy. Remaining rule detectors. |
| 3–5 | Generate all nine scenario PCAPs. `training/generate_traffic.sh` runs **once**, offline, in Docker. Commit trimmed outputs. |
| 4–6 | Dataset build with **temporal split** and **stated test prevalence**. Train LightGBM Tier 1. Isotonic calibration. |
| 6–7 | SHAP evidence via `pred_contrib=True` + the NL template renderer. |
| 7–8 | STIX 2.1 schema + validation in CI. Hash-chained ledger + `verify` CLI. |
| 8–10 | **Beacon table + Lomb-Scargle.** Scenario 5. Build the FFT-vs-Lomb-Scargle side-by-side comparison — this is your strongest visual. |
| 10–12 | **JA4 + p0f-style TCP fingerprint + consistency score.** Scenario 8. |
| 12–13 | Dashboard polish. Analyst + Operations views. |
| 13–14 | Run the full benchmark. Write `bench/RESULTS.md`. Write `docs/TRAINING.md`, `MODEL_CARD.md`, `FEATURES.md`. |
| 14–15 | **Record the video.** Then the final PPT. Submit to SPOC with margin. |

### The video — this is the highest-leverage artefact you produce

Assume 2–3 minutes and assume the reviewer is on their fortieth submission of the day.

| Time | Content |
|---|---|
| 0:00–0:15 | The constraint. "The enclave can watch but never touch — no probes, no handshakes, no decryption, no way back." |
| 0:15–0:45 | Live: replay starts, alerts stream in, **throughput counter visible on screen the whole time.** |
| 0:45–1:15 | Click one alert. Show the evidence panel with SHAP attributions in plain language. |
| 1:15–1:45 | The jittered beacon. FFT finds nothing; Lomb-Scargle resolves the period. Side by side. |
| 1:45–2:10 | The JA4 spoof caught by TCP-fingerprint disagreement. Both claims shown side by side. |
| 2:10–2:30 | Tamper a ledger record. Run `verify`. It fails, naming the record. |
| 2:30–2:45 | Memory graph flat while the flood runs. "The monitor doesn't fall over when the attack starts." |
| 2:45–3:00 | Numbers on screen: flows/sec, p99 latency, PR-AUC per class, hardware spec. |

Do not narrate architecture. Show the thing working. Every second of diagram is a second not spent proving it runs.

### Submit early

Portals fail on deadline day, every year. Have the SPOC upload by **27 September**.

---

## 4. Phase 3 — October / November (if shortlisted)

Screening runs through October; finalists are announced around November. Use the time.

**Priority order:**
1. **Tier 2 + anomaly layer.** The zero-day story. IsolationForest or a benign-only autoencoder — not SimCLR.
2. **Public benchmark.** Run against CIC-IDS2017 / UNSW-NB15 / CTU-13. One number comparable to published work is worth a lot.
3. **Optional Rust core via PyO3.** Only the flow table and sketches. 1–2 days, gets you past 500k flows/sec, gives a real Rust story. **Only if you have a Rust developer** — do not learn Rust in November.
4. **Coverage report + detection-ceiling panel.** Cheap, honest, distinctive.
5. **Robustness.** Malformed packets, truncated PCAPs, IPv6, VLAN tags, tunnelled traffic. A demo that crashes on a judge's file is a catastrophe.
6. **The CERT-In export button.** One click → structured incident report. Half a day, good story.

**Deliberately not doing:** multi-node scaling, ClickHouse, Redpanda, crypto-shredding, the OT/Modbus demo, the air-gapped update channel, RBAC across five personas.

---

## 5. Phase 4 — the 36-hour Grand Finale

### Before you travel

- [ ] Everything runs offline. `docker compose up` with wifi disabled. Test this.
- [ ] All models committed as artefacts. Nothing trains at the venue.
- [ ] All scenario PCAPs committed. No traffic generation at the venue — **you cannot run `hping3 --flood` on a nodal-centre network.**
- [ ] Runs on at least two different laptops. Test on both.
- [ ] Offline dependency mirror (`pip download` into a local wheelhouse) in case you must rebuild.
- [ ] A known-good git tag you can `checkout` when a change breaks something at hour 30.
- [ ] Benchmark numbers already measured and written down. Do not plan to measure at the venue.
- [ ] Demo rehearsed to time, by at least two team members.

### The 36 hours

| Hours | Focus |
|---|---|
| 0–2 | Set up. Verify the demo runs on venue hardware **immediately**. Fix environment issues now, not at hour 30. |
| 2–10 | Highest-value improvement identified from mentor feedback. One thing, not three. |
| 10–16 | Second improvement. Freeze features at hour 16. |
| 16–24 | Hardening only. Error paths, edge cases, the crash you've been ignoring. |
| 24–30 | Documentation, README, results table. Re-run the benchmark on venue hardware and update the numbers. |
| 30–34 | Rehearse the pitch. Out loud. To a stranger if you can find one. |
| 34–36 | Sleep, or at least stop typing. Do not commit anything after hour 34. |

**The rule:** freeze at hour 16. Every team that keeps adding features into hour 30 demos something broken. The teams that win demo something small that works perfectly.

---

## 6. Work split for a 6-person team

| Role | Owns | Person-days to 30 Sept |
|---|---|---|
| **Ingest + state** | Sources, decoder, flow table, beacon table, sketches | 8 |
| **Detection + ML** | Features, rules, Tier 1/2, calibration, SHAP | 10 |
| **Backend + alerts** | FastAPI, WebSocket, STIX, ledger, DuckDB, metrics | 7 |
| **Frontend** | React dashboard, both views, charts, replay controls | 7 |
| **Data + evaluation** | Traffic generation, dataset build, training docs, benchmark | 7 |
| **PPT + video + integration** | Deck, video, README, keeping the demo runnable end-to-end | 6 |

The last role matters more than it looks. Someone must own "does the whole thing still run today," or on 29 September you will discover it hasn't for a week.

---

## 7. Risk register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Scope creep back toward the original architecture | **High** | The cut list in `02_Audit_Of_Your_Documents.md` §3 is a decision, not a suggestion. Re-read it weekly. |
| Traffic generation eats a week | Medium | Timebox to 3 days. Fall back to a public dataset + synthetic flow records. Generation is a means, not a deliverable. |
| Throughput number is embarrassing | Medium | Measure early — day 4, not day 14. If it's low, you have time for the PyO3 core. Discovering it on day 13 is fatal. |
| Demo crashes at the venue | Medium | Rehearse on two machines offline. Keep a recorded video as fallback. |
| Model underperforms | Medium | The rule layer is your floor. Rules alone detect (a), (c), (e), (f) adequately. ML is uplift, not foundation. |
| Team splits attention across 26145 and 26153 | Medium | Pick one. They need different architectures. |
| Someone learns Rust in November | Low | Don't. |

---

## 8. What to reuse from the original Implementation Plan

The schedule doesn't survive, but the **test criteria and "Done" definitions do** and they're well-written. Keep these as your QA checklist:

- Memory-bound static check in CI — no unbounded `dict`/`list` growth on the processing path
- CMS/HLL accuracy tests against known-cardinality synthetic streams
- Sketch merge correctness test — **rewritten per finding E1** to test partition-merge equivalence, not just commutativity
- Load-shedding order test — sketches never shed before flow-table entries
- Attack-onset stability test — inject the flood mid-run, report latency/drop/memory **during** the attack window
- STIX schema validation as a CI gate
- Ledger tamper-detection test
- Flat-memory test — 1 hour of sustained load, memory must not grow

That last one, run live with a graph on screen, is one of your best demo moments.
