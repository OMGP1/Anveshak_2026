# SIH26145 — The Problem Statement, Verified

Source: official SIH 2026 portal listing (sih.gov.in), retrieved 7 September 2026.

---

## 1. Identification — confirmed correct in your documents

| Field | Value |
|---|---|
| PS code | **SIH26145** |
| Title | AI-Based Detection of Cyber Threats in Unidirectional IP Traffic |
| Organisation | National Technical Research Organisation (NTRO) |
| Department | NTRO |
| Category | **Software** |
| Theme | **Blockchain & Cybersecurity** |
| Serial number | 145 |
| Submission deadline | **30 September 2026** |
| Idea submission cap | 500 |

Your documents label this correctly. One note on context: a memory of an earlier conversation has your team on **SIH26153** ("AI based Network Attack Forecasting from Network Traffic Data", also NTRO, also Blockchain & Cybersecurity). Both exist and they are different problem statements. If you have switched, fine — but make sure the whole team knows which one you are submitting against, because 26153 is a *forecasting* problem and 26145 is a *detection* problem, and the architectures diverge sharply.

---

## 2. What the problem statement actually says

### Background (paraphrased)

Critical-infrastructure operators watch their gateway and peering links using **passive mirroring or hardware data diodes** that copy traffic into a monitoring enclave in one direction only. The enclave sees everything crossing the link but has no physical or protocol-level path back into production. This is deliberate: it removes the class of attack where a compromised monitoring system becomes a pivot into the core network, and it preserves a clean chain of custody for forensic use. The trade-off is that any intelligence layer in that enclave must work purely from what it can passively observe — packet captures, exported flow records (NetFlow/IPFIX/sFlow), and derived metadata — with no ability to send probes, complete handshakes, or push a mitigation command back.

**Read that paragraph carefully.** It says the diode *is the environment you are given*. It does not ask you to design, build, verify, or specify one. This is the single most important scoping fact in the whole PS, and your Technical Feasibility Dossier's entire Domain 1 (optical power budgets, beam-splitter ratios, receive-only SFP BOM, IEEE 802.3ah link modes) is answering a question that was never asked.

Also note the phrase **"preserves a clean chain of custody for forensic use."** That is the PS itself handing you the justification for a tamper-evident alert ledger — which is also the tie-in to the Blockchain & Cybersecurity theme. That one is worth keeping.

### Description (paraphrased)

Design and build an AI/ML pipeline that ingests a one-directional stream of IP traffic **from simulated IP data**, and detects, classifies and scores cyber-security threats in near real time using only passively collected data. The pipeline must assume it can never re-contact the source or destination, cannot complete a handshake, and cannot issue any action back across the ingest path. Its output is intelligence: **labelled alerts, confidence scores, and supporting evidence, displayed on a visualisation dashboard.**

"**From simulated IP data**" is the second most important scoping fact. You are not being asked to capture live 10 Gbps traffic off a NIC. That single phrase deletes the justification for AF_XDP, DPDK, UMEM sizing, RSS symmetry, NUMA pinning, PTP hardware timestamping, and receive-ring depth matching.

### The six mandated threat classes

| # | Class | What the PS says to detect it from |
|---|---|---|
| **a** | Volumetric / protocol DDoS — SYN floods, UDP reflection/amplification, spoofed-source floods | Flow-level rate and **source-IP entropy** statistics |
| **b** | Botnet C2 beaconing | **Periodicity and inter-arrival analysis** on flows repeating at regular intervals toward a small destination set |
| **c** | DGA domains and DNS tunnelling | **Entropy / n-gram analysis** of query names, plus query-length and record-type anomalies |
| **d** | Malware inside encrypted sessions | **TLS/QUIC metadata alone** — JA3/JA3S **or** JA4 fingerprints, packet-size and timing sequences. No decryption. |
| **e** | Reconnaissance and port scanning | **Fan-out** from a single source across many destination ports or hosts |
| **f** | Data exfiltration | **Asymmetric flow-volume anomalies**, unusual outbound-to-inbound byte ratios |

Your documents map to all six correctly. The methods the PS names (entropy, periodicity/IAT, n-gram, JA3/JA4, fan-out, byte ratios) are exactly the methods your dossier chose. That part is right, and it means your feature engineering is aligned with what the evaluator expects to see.

Note the PS says "JA3/JA3S **or** JA4". Implementing the JA4 family is a legitimate *exceed*, not a deviation — but see the licensing note in `02_Audit_Of_Your_Documents.md`, finding **E8**.

### Expected solution — the deliverables list

The PS names four deliverables:

1. **A working prototype delivered as a source repository**, implementing ingest → feature extraction → model inference → alert output.
2. **Accompanying documentation** of the model(s) used, the features engineered, and the **training/validation approach**.
3. **A simple dashboard** showing live or replayed detections with **severity and confidence**.
4. Adherence to five architectural constraints (below).

"**Simple dashboard**" is the third scoping fact. Not a five-persona RBAC platform with a CISO compliance workspace, a key-destruction log view, and a kill-chain force-directed graph.

"**Live or replayed**" is an explicit permission to build a replay-driven demo. Take it. Replay is also the only thing that works at a nodal centre.

### The five architectural constraints — these are the scoring rubric

| ID | Constraint | What it means for your build |
|---|---|---|
| **C-a** | **Read-only ingest.** Any design that assumes a return path, a live query to the source, or an inline block is out of scope. | No active probing, no DNS resolution of observed domains, no reputation-API lookups, no blocking. Your code must have no outbound network calls in the detection path — and you should be able to *prove* it. |
| **C-b** | **No payload decryption.** TLS/QUIC analysed from metadata only. | Parse the unencrypted ClientHello/ServerHello handshake fields (legal and expected). Never touch application data. Enforce this structurally, not by convention. |
| **C-c** | **Streaming, not batch.** Process incrementally, raise alerts with bounded latency, not an end-of-run report. | Every detector must be an online algorithm. No "load the whole PCAP into a DataFrame and score it." State must be bounded. |
| **C-d** | **Defined throughput target.** Solutions must **state and demonstrate** the traffic rate they were tested against (e.g. flows/sec or Mbps sustained). | This is the one constraint most teams will fumble. "State and demonstrate" means a number *and* a reproducible way to see it. Put it on the dashboard. |
| **C-e** | **Standardized alert schema.** Alerts must be structured records — for instance timestamp, flow identifier, threat class, confidence score, supporting evidence feature. | Five required fields. STIX 2.1 with `x_` extensions is a good way to exceed this cheaply. |

### The dataset hint the PS gives you

The PS's own dataset field names the tooling it expects:

- **Benign load:** `iperf3`, `Ostinato`, or `TRex`
- **Attack traffic:** `hping3` (SYN/UDP floods), `Slowloris` (slow HTTP exhaustion), `dnscat2`/`iodine` (DNS tunnelling), DGA samples from published algorithms (e.g. via DGArchive) or a sandboxed C2 emulator for realistic beaconing timing
- **Feature extraction:** flow-level features

Your dossier's Phase 4.2 rig matches this list almost exactly. That is good — you were reading the same source. Use the PS's own tool names in your PPT; it signals you read the brief.

---

## 3. The compliance matrix — use this as your checklist

Score yourself honestly against this before 30 September. Anything not green is a gap a screener can see.

| Req | Requirement | Evidence you must be able to point at |
|---|---|---|
| R1 | Ingests one-directional IP traffic from simulated data | Two input adapters: PCAP replay + flow-record (NetFlow/IPFIX/sFlow-style) replay |
| R2 | Detects class (a) volumetric/protocol DDoS | Working detector + a demo scenario + measured precision/recall |
| R3 | Detects class (b) C2 beaconing | Working detector + a **jittered** beacon scenario (jitter is the hard case) |
| R4 | Detects class (c) DGA + DNS tunnelling | Working detector + both a high-entropy and a **dictionary** DGA scenario |
| R5 | Detects class (d) encrypted-session malware | Working detector from TLS metadata only + a fingerprint-spoofing scenario |
| R6 | Detects class (e) recon/port scanning | Working detector + both a **fast** and a **slow** scan scenario |
| R7 | Detects class (f) data exfiltration | Working detector + both a bulk and a **slow-drip** scenario |
| R8 | Classifies and **scores** | Calibrated confidence, not raw model output |
| R9 | Near real time | Measured p50/p99 wire-to-alert latency, published |
| R10 | Supporting evidence per alert | Per-alert feature attribution, rendered in readable language |
| R11 | Visualisation dashboard | Running UI, live or replayed, severity + confidence visible |
| R12 | Source repository | Public repo, README, one-command run |
| R13 | Model documentation | Model card: architecture, hyperparameters, features |
| R14 | Feature documentation | Full feature dictionary with definitions and rationale |
| R15 | **Training/validation approach documented** | Split protocol, leakage controls, **class prevalence stated**, metrics justified |
| R16 | C-a read-only ingest | Demonstrable: no outbound sockets in the detection path |
| R17 | C-b no decryption | Demonstrable: payload discarded at the parse boundary |
| R18 | C-c streaming | Demonstrable: bounded memory over a long run, incremental alerts |
| R19 | C-d stated + demonstrated throughput | A number, on screen, reproducible by the judge |
| R20 | C-e standardized alert schema | Schema-validated records, five required fields present |

**R15 and R19 are where most teams lose points, and where your current documents are weakest.** R15 is barely addressed anywhere in the five files. R19 is claimed but with inconsistent numbers across documents.

---

## 4. What the PS does *not* ask for

Stated plainly, so you can stop defending it:

- Designing, specifying, or verifying a hardware data diode
- Line-rate kernel-bypass packet capture
- Multi-node horizontal scaling
- 180-day data retention, storage economics, or cryptographic erasure
- CERT-In incident reporting workflows or IT Act §70 compliance
- Air-gapped model update channels or offline signing infrastructure
- Role-based access control across five personas
- Hardware security modules
- An offline language model

**Every one of these is still allowed as an enhancement.** Some are genuinely good ideas — the tamper-evident ledger in particular, because the PS's own background paragraph raises chain of custody. But they must be presented as *"and additionally we did X"*, never as core scope, and they must not consume build time that R1–R20 needs. `06_Differentiators_And_Demo.md` ranks them.
