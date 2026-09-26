# SIH26145 — Verified Review & Corrected Build Package

**Reviewed:** 7 September 2026
**Subject:** the five documents you uploaded (Technical Feasibility Dossier, 108-Item Checklist Resolution, PRD, TRD, Implementation Plan)
**Against:** the official SIH 2026 problem statement SIH26145, retrieved and read in full.

---

## The three-line verdict

1. **Your documents are technically impressive and largely internally coherent, but they are solving a much larger problem than the one SIH26145 actually poses.** Roughly 60–70% of the content — optical diode engineering, AF_XDP/Rust line-rate capture, Redpanda, ClickHouse, 180-day retention, crypto-shredding, HSM signing, air-gapped update channels, 5-persona RBAC — is not requested anywhere in the problem statement and cannot be demonstrated at a hackathon.

2. **There are seven concrete technical errors or internal contradictions**, three of which are load-bearing: the Count-Min Sketch design contradicts itself, the C2 beaconing detector is architecturally impossible under your own eviction policy, and the flow record cannot distinguish forward from reverse direction. Details in `02_Audit_Of_Your_Documents.md`.

3. **The 12-week implementation plan does not fit the actual SIH calendar.** The national idea submission closes 30 September 2026 — 23 days from today — and the Grand Finale is a *36-hour* build in December. Nothing in your plan is sized for either window.

None of this means the work was wasted. The core architectural instincts (bounded memory everywhere, no TCP reassembly, completeness flag as a conditioning feature, two-tier cascade, Lomb-Scargle over FFT, JA4↔JA4T cross-layer disagreement) are genuinely good and several are better than what most competing teams will bring. The problem is scope and calibration, not judgement.

---

## The actual calendar you are working against

| Date | What happens |
|---|---|
| **Now (7 Sep 2026)** | College internal hackathons are running this month. Many are the week of 8–15 Sep. |
| **30 September 2026** | **National idea submission closes.** Your SPOC uploads an idea PPT + video. This is a hard deadline. |
| October 2026 | National screening. |
| November 2026 | Finalist list announced. |
| December 2026 | **Grand Finale — 36 continuous hours** at a nodal centre, in front of judges. |

Two consequences that should reshape everything:

- **Between now and 30 Sep you are selling an idea, not shipping a system.** What wins the screen is a clear PPT, a short video of something actually running, and evidence you understand the problem better than the other teams. The PS caps submissions at 500 ideas — assume real competition.
- **The Grand Finale is 36 hours on venue hardware.** Whatever you demo there must run on a laptop, without root, without special NICs, without an internet connection you can rely on, and without you running a SYN flood on the venue's network. Any architecture that fails those four tests is not a Grand Finale architecture, however good it looks on paper.

---

## What's in this package

| File | What it's for |
|---|---|
| `01_Problem_Statement_Verified.md` | The official PS, decomposed into a numbered requirement/compliance matrix. Read this first — it is the scoring rubric. |
| `02_Audit_Of_Your_Documents.md` | Item-by-item verification of your five documents. What's correct, what's wrong, what's out of scope, with the evidence. |
| `03_Tech_Stack_And_Architecture.md` | The stack I'd actually build, with the reasoning for each swap away from yours. |
| `04_Prototype_Build_Spec.md` | Repo layout, module specs, the full feature list, detector algorithms, alert schema. Buildable as written. |
| `05_Timeline_And_Plan.md` | A plan sized to the real calendar: internal hackathon → 30 Sep → Oct/Nov → 36-hour finale. |
| `06_Differentiators_And_Demo.md` | What extra to provide, ranked by judge-impact ÷ build-cost. Plus the demo script and the judge Q&A you should rehearse. |

---

## The one-paragraph summary of what to build

A Python streaming detection engine that reads **simulated/replayed IP traffic** (PCAP *and* NetFlow/IPFIX-style flow records), maintains **strictly bounded** per-flow and sketch state, extracts ~50 passive metadata features, runs a **two-tier cascade** (a fast gradient-boosted tabular model on every flow, an expensive sequence/anomaly model on a gated ~2% subset), and emits **STIX 2.1 alerts** carrying a calibrated confidence score and SHAP-derived supporting evidence into an **append-only hash-chained ledger**. A FastAPI/WebSocket layer streams those alerts to a React dashboard that shows the alert queue, the per-alert evidence, and — critically — a **live throughput and latency meter**, because the PS explicitly requires you to state and demonstrate the rate you were tested at. Everything runs on one laptop with `docker compose up`.

That is the whole system. It is achievable. It satisfies every stated requirement. It leaves room for four or five genuine differentiators that your competition will not have.
