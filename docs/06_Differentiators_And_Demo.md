# What Extra to Provide, and How to Demo It

The PS caps submissions at 500 ideas. Assume every serious team hits the six threat classes and produces a dashboard. Differentiation is the entire game — but only *after* R1–R20 are green.

---

## 1. Ranked by judge-impact ÷ build-cost

### Tier A — build all of these

**A1. Live throughput + latency meter on the dashboard.** *Cost: 0.5 day*
Constraint C-d requires you to "state and demonstrate" your traffic rate. Almost every team will state it on a slide. A counter moving on screen while the judge watches is a categorically different kind of evidence. Show flows/sec, packets/sec, Mbps, and a rolling p99 latency figure. This is the cheapest high-impact thing in this document.

**A2. JA4 ↔ TCP-fingerprint disagreement detector.** *Cost: 1.5 days*
Your best original idea and it comes straight from your own dossier. JA4 is set by the TLS library; the TCP fingerprint is set by the OS kernel. Malware that spoofs a Chrome JA4 from a Linux box still exposes a Linux TCP stack. Emit both claims side by side.

Two things make this stronger than it currently is: build the TCP fingerprint **p0f-style yourself** (initial TTL, window size, MSS, options ordering) rather than using JA4T, because that sidesteps the FoxIO licence entirely (finding E9) and lets you say "we implemented our own OS fingerprint." And make the disagreement a **first-class alert type**, not a feature buried in a score.

**A3. Calibrated confidence + a reliability diagram.** *Cost: 0.5 day*
The PS asks for a confidence score. Yours will be the only one that means anything. `CalibratedClassifierCV` with isotonic regression is three lines; the reliability diagram is a matplotlib plot. Put the plot in the deck. Almost nobody produces one, and it reads as unusually rigorous for the effort involved.

**A4. Hash-chained, signed alert ledger with a `verify` CLI.** *Cost: 1 day*
Ties directly to the Blockchain & Cybersecurity theme without pretending to be a blockchain. The PS's own background paragraph says the diode "preserves a clean chain of custody for forensic use" — you're answering a need the PS itself raised. Demo: tamper a record, run `verify`, it names the exact record where the chain breaks. Twenty seconds, and people remember it.

**A5. Live bounded-memory proof.** *Cost: 0.5 day*
Run a flood scenario with an RSS graph on screen and show the line flat. This is "the monitor falls over exactly when the attack starts" — the failure mode your own documents correctly identified as the most operationally important — turned into something visible. Pair it with the ~160 MB budget table.

**A6. Explicit detection-ceiling panel.** *Cost: 0.5 day*
A UI panel showing what fraction of observed traffic is `high_confidence` / `low_confidence` / `unclassifiable_opaque`, with a note on why (ECH hides SNI, QUIC obscures handshake metadata, payload is always opaque). Judges reward candour and no other team will volunteer their own limits. It also pre-empts the question "what *can't* you see," which somebody will ask.

### Tier B — build if time allows

**B1. Adversarial evasion demo: FFT vs. Lomb-Scargle.** *Cost: 1 day (mostly already built)*
Two panels: a naive FFT periodogram showing nothing on a ±30% jittered beacon, and Lomb-Scargle resolving a clean peak at the true period. This is the single most persuasive 60 seconds you can give a technical judge, because it shows you knew the evasion existed and picked the tool that beats it.

**B2. Benign-only anomaly layer.** *Cost: 1.5 days*
IsolationForest or a small autoencoder trained on benign traffic only, flagging reconstruction-error outliers. Answers "what about attacks not in your training set" with a mechanism rather than a promise. Explains in one sentence, unlike contrastive learning.

**B3. Rules vs. ML ablation table.** *Cost: 0.5 day*
Per threat class: rules only / ML only / both. Shows you didn't ML-ify problems a threshold solves better. Evaluators notice engineering judgement.

**B4. Public benchmark number.** *Cost: 1 day*
One run against CIC-IDS2017 / CSE-CIC-IDS2018 / UNSW-NB15 / CTU-13. Makes your numbers comparable to published work instead of self-referential.

**B5. CERT-In 6-hour incident export.** *Cost: 0.5 day*
One button → a structured incident report. The 6-hour reporting window and 180-day retention obligations are real (I verified both — CERT-In Directions of 28 April 2022, under IT Act §70B(6)). Frame it as regulatory awareness, one slide, one button. Do not build the retention architecture.

### Tier C — only if genuinely ahead

**C1. Rust core via PyO3** for the flow table and sketches only. Real throughput, real Rust story, no AF_XDP fantasy. Only with an existing Rust developer.
**C2. Offline LLM triage brief.** Judges like it, but many teams will bolt an LLM on and it carries hallucination risk. If you do it: keep the template-generated evidence as the default and ground truth, put the LLM behind a flag, label it "AI-generated — verify before acting," and measure its error rate against a held-out set. Your original documents got all three of those right.

### Do not build

Multi-node scaling curves · ClickHouse · Redpanda · crypto-shredding · HSM integration · the air-gapped update channel · RBAC across five personas · Modbus/MQTT OT demo · SimCLR contrastive pretraining · anything touching optical hardware.

---

## 2. The demo script

Five minutes. Rehearse it out loud. Time it.

**0:00 — The constraint (20s).**
"A monitoring enclave sees everything crossing a critical link and can touch none of it. No probes, no handshakes, no decryption, no path back. Every detection has to come from metadata alone."

**0:20 — Start the replay (30s).**
Benign scenario. Alerts stay at zero. Point at the throughput counter. *"We're sustaining N flows per second — this number is live, not a slide."*

**0:50 — SYN flood (45s).**
Inject scenario 2. Alerts fire within a second. Open one. Evidence panel: SYN:SYN-ACK ratio, source-IP entropy, completeness flag — with SHAP contributions in plain language. *"Not a black box. The alert says why."*

**1:35 — Memory (20s).**
Switch to Operations view mid-flood. *"Flat. The sketches are fixed-size — the flood can't exhaust the thing detecting it."*

**1:55 — Jittered beacon (60s).**
Scenario 5. Two panels. FFT: noise. Lomb-Scargle: a clean peak at 45 minutes with a false-alarm probability below 10⁻³. *"Jitter is a deliberate evasion against FFT-based detection. Lomb-Scargle is built for unevenly-sampled data, so the evasion doesn't work."*

**2:55 — JA4 spoof (60s).**
Scenario 8. *"This client's TLS fingerprint says Chrome on Windows. Its TCP stack fingerprint says Linux. The TLS library is application-controlled — the TCP stack isn't. That disagreement is the detection, and it needs no reputation lookup, which matters because a reputation lookup would violate the read-only constraint."*

**3:55 — Ledger (25s).**
Edit a byte in an old alert record. Run `verify`. It fails, naming the record. *"Chain of custody, which is exactly what the problem statement says the diode exists to preserve."*

**4:20 — Honesty (20s).**
Detection-ceiling panel. *"Here's what we can't see. Under Encrypted Client Hello the SNI is opaque. Payload always is. We report the fraction of traffic we can't classify rather than hiding it."*

**4:40 — Numbers (20s).**
One slide: flows/sec sustained, p50/p99 wire-to-alert latency, PR-AUC and F1 per class, test-set prevalence, peak RSS, exact hardware. *"Reproducible — the harness and command line are in the repo."*

---

## 3. Judge Q&A — rehearse these

**"What's your throughput?"**
Give the measured number, the hardware, and the definition. Then: *"That's demonstrated on replay; the harness is in the repo and you can re-run it."* Never give two different numbers (finding E11).

**"Isn't this just anomaly detection with extra steps?"**
No — three specific things. Detectors are matched to the physics of each threat class rather than generic outlier scoring. Every alert carries feature attribution, so it's triageable. And every structure is bounded, so it survives the attack it's detecting.

**"What happens when the attacker knows your design?"**
Name the evasions and the counters: jittered beacons → Lomb-Scargle; dictionary DGAs → n-gram likelihood, not entropy; JA4 spoofing → cross-layer TCP disagreement; slow scans → multi-scale windows; slow-drip exfiltration → EWMA rather than single-window. Then the honest part: *"Sketch hash seeds are randomised per deployment so an attacker can't craft deliberate bucket collisions."* Then the limits: *"Against a patient attacker below every threshold, we degrade — which is why there's a benign-only anomaly layer as backstop."*

**"Why not deep learning end-to-end?"**
Latency budget and explainability. A gradient-boosted model on engineered features runs in microseconds with exact SHAP attributions. The sequence model runs only on the promoted subset where its cost is affordable. *"We use deep learning where it earns its cost, not everywhere."*

**"How do you know it works on real traffic?"**
The honest answer: *"We don't fully — it's trained on synthetic and public datasets. Here's our public-benchmark number for comparability, here's the test-set prevalence we measured at, and here's the drift-monitoring design for deployment."* Do not overclaim. An evaluator from NTRO will know instantly.

**"What's your false-positive rate?"**
The measured number at the stated prevalence, plus the allowlist mechanism for known-asymmetric and high-cardinality legitimate traffic, plus the note that suppressions are logged rather than silently dropped.

**"Why is this NTRO-relevant rather than generic IDS?"**
The unidirectional constraint is the whole design. No probing, no handshake completion, no reputation lookups, no blocking. Standard IDS tooling assumes at least one of those. *"Every architectural decision here follows from not having a return path."*

**"Where does the blockchain theme come in?"**
*"We didn't force a chain in. We built the property the theme is actually about — tamper-evident, append-only, cryptographically verifiable evidence — because the problem statement's own background says the diode exists partly to preserve chain of custody."* That answer is much stronger than bolting on a ledger for the sake of the theme.

**"What can't you detect?"**
Have the answer ready and give it without hedging: payload contents, SNI under ECH, anything requiring active probing, attacks entirely below your thresholds, and beacon periods longer than your beacon-table TTL. Then state the TTL number. Volunteering your limits precisely is more convincing than any claim of completeness.

---

## 4. The three sentences to open with

If you get thirty seconds before a judge's attention drifts:

> "A monitoring enclave on a critical link can see everything and touch nothing — no probes, no handshakes, no decryption, no path back. We built a streaming detector for that constraint: bounded memory that can't be exhausted by the flood it's detecting, six threat classes each matched to the passive signal it actually leaves, and an explanation attached to every alert. It sustains N flows per second on a laptop, and that number is on the screen, live, right now."
