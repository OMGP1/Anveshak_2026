# Prototype Build Specification

Buildable as written. Everything here maps to a requirement in `01_Problem_Statement_Verified.md` §3.

---

## 1. Repository layout

```
sih26145/
├── README.md                    ← one-command run, architecture diagram, results table
├── docker-compose.yml           ← engine + api + ui, `docker compose up`
├── Makefile                     ← make demo | make bench | make train | make test
├── pyproject.toml
│
├── engine/
│   ├── sources/
│   │   ├── base.py              ← ReplaySource interface
│   │   ├── pcap_source.py       ← dpkt-based PCAP replay          [R1]
│   │   ├── flowrecord_source.py ← NetFlow/IPFIX/sFlow-style CSV/JSON  [R1]
│   │   └── replay_clock.py      ← virtual clock, speed multiplier, seek  [G2]
│   ├── decode/
│   │   ├── packet.py            ← L2/L3/L4 headers → FlowMetadata
│   │   ├── tls.py               ← ClientHello/ServerHello parse → JA4
│   │   ├── dns.py               ← query name, qtype, length
│   │   └── metadata.py          ← FlowMetadata: NO payload field   [C-b, R17]
│   ├── state/
│   │   ├── flow_table.py        ← LRU, hard cap, orientation bit   [E3 fix]
│   │   ├── beacon_table.py      ← separate, long TTL, lazy alloc   [E2,E5 fix]
│   │   ├── cms.py               ← standard linear update, mergeable [E1 fix]
│   │   ├── hll.py               ← global m=2^12, per-key m=2^8      [E4 fix]
│   │   ├── entropy.py           ← sliding 1s/5s/60s
│   │   └── welford.py
│   ├── features/
│   │   ├── ddos.py  beaconing.py  dga.py  encrypted.py  scan.py  exfil.py
│   │   └── registry.py          ← the feature dictionary          [R14]
│   ├── models/
│   │   ├── tier1.py             ← LightGBM + isotonic calibration [R8]
│   │   ├── tier2.py             ← ONNX 1D-CNN over SPLT
│   │   ├── anomaly.py           ← benign-only IsolationForest / AE
│   │   ├── rules.py             ← deterministic high-confidence rules
│   │   └── gate.py              ← Tier1→Tier2 promotion
│   ├── explain.py               ← LightGBM pred_contrib → NL template  [R10]
│   ├── alerts/
│   │   ├── schema.py            ← STIX 2.1 + x_ extensions        [R20, C-e]
│   │   ├── ledger.py            ← hash chain + Ed25519 head sig
│   │   └── verify.py            ← CLI: verify chain integrity
│   ├── metrics.py               ← throughput, latency histogram, RSS  [R19, C-d]
│   └── pipeline.py              ← the streaming loop
│
├── api/
│   ├── main.py                  ← FastAPI: /alerts /ws /replay /metrics
│   └── store.py                 ← DuckDB
│
├── ui/                          ← React + Vite + TS               [R11]
│   └── src/views/{Analyst,Operations}.tsx
│
├── data/
│   ├── scenarios/               ← 9 committed PCAPs, one per scenario
│   ├── models/                  ← trained artefacts, committed
│   └── reference/
│       ├── domain_bigrams.json  ← Markov model from Tranco top-1M
│       └── ja4_tcp_reference.json ← JA4 → expected TCP-fp family table
│
├── training/
│   ├── generate_traffic.sh      ← the attack rig — run ONCE, offline
│   ├── build_dataset.py         ← temporal split, prevalence control [G3,G4]
│   ├── train_tier1.py  train_tier2.py  train_anomaly.py
│   └── evaluate.py              ← PR-AUC, per-class F1, reliability diagram
│
├── bench/
│   ├── throughput.py            ← the C-d harness
│   └── RESULTS.md               ← hardware spec + measured numbers  [R19]
│
└── docs/
    ├── MODEL_CARD.md            ← architecture, hyperparams        [R13]
    ├── FEATURES.md              ← full feature dictionary          [R14]
    ├── TRAINING.md              ← split protocol, leakage, prevalence [R15]
    ├── DETECTION_CEILING.md     ← what is physically unobservable
    └── ARCHITECTURE.md          ← C4 diagrams
```

If a screener clones this and runs `make demo`, they see a working system in under two minutes. That alone puts you ahead of most submissions.

---

## 2. The input contract (G1 — build this first)

### PCAP adapter
```python
class PcapSource(ReplaySource):
    """Reads a pcap/pcapng, yields FlowMetadata in timestamp order."""
    def __init__(self, path, speed=1.0, realtime=False): ...
    def __iter__(self) -> Iterator[FlowMetadata]: ...
```

### Flow-record adapter
Accept a normalised flow-record row — the common subset of NetFlow v5/v9, IPFIX, and sFlow:

| Field | Type | Notes |
|---|---|---|
| `ts_start`, `ts_end` | float (epoch) | |
| `src_ip`, `dst_ip` | str | |
| `src_port`, `dst_port` | int | |
| `proto` | int | 6/17/1 |
| `packets`, `bytes` | int | |
| `tcp_flags` | int | OR of flags seen |
| `direction_hint` | str, optional | ingress/egress if the exporter provides it |

Provide a converter so both adapters feed the identical downstream pipeline. Then say in your PPT: *"we accept both packet captures and exported flow records, matching the three input types the problem statement names."* That's a direct, checkable hit on R1.

### Replay controller (G2)
```
POST /replay/start   {scenario, speed, mode: "virtual"|"realtime"}
POST /replay/pause
POST /replay/seek    {t}
GET  /replay/status
```
Virtual mode replays as fast as the engine can consume (this is your throughput benchmark). Realtime mode honours original packet timing (this is your demo).

### The `FlowMetadata` boundary (C-b enforcement)
```python
@dataclass(frozen=True, slots=True)
class FlowMetadata:
    ts_ns: int
    proto: int
    src_ip: int; dst_ip: int; src_port: int; dst_port: int
    length: int
    tcp_flags: int
    # L7 metadata ONLY — never payload bytes
    tls: TLSMeta | None      # ja4, version, alpn, sni_present (bool, not value)
    dns: DNSMeta | None      # qname, qtype, qname_len
    # There is deliberately no `payload` field. This is the enforcement.
```

Write this in your README. "No payload decryption" becomes a property of the type system rather than a promise.

---

## 3. Feature dictionary (R14)

~52 features. Every one is derivable from passive metadata. Ship this table as `docs/FEATURES.md`.

### Flow-structural (12)
`duration`, `pkts_fwd`, `pkts_rev`, `bytes_fwd`, `bytes_rev`, `bytes_per_pkt_fwd`, `bytes_per_pkt_rev`, `flags_seen_bitmap`, `completeness_flag`, `directionality`, `initiator_is_lo`, `orientation_confidence`

### DDoS — class (a) (9)
| Feature | Definition |
|---|---|
| `syn_synack_ratio_1s` | SYN count ÷ max(1, SYN-ACK count), 1s sliding |
| `pps_to_dst_ewma_dev` | (current pps − EWMA) ÷ EWMA σ, per destination, α=0.1 |
| `src_entropy_1s/5s/60s` | Normalised Shannon entropy of source IPs, sliding |
| `entropy_explosion_score` | Positive deviation of `src_entropy` from its own EWMA |
| `entropy_collapse_score` | Negative deviation (reflection/amplification signature) |
| `src_cardinality_per_dst` | HLL estimate, distinct sources → one destination |
| `amplification_ratio` | reply bytes ÷ request bytes, UDP only |

### Beaconing — class (b) (8)
| Feature | Definition |
|---|---|
| `iat_mean`, `iat_std`, `iat_cv` | Coefficient of variation is the key one — low CV means regular |
| `iat_skew`, `iat_kurtosis` | Welford online, 3rd/4th moments |
| `ls_peak_power` | Lomb-Scargle max normalised power |
| `ls_peak_period_s` | Period at that peak |
| `ls_fap` | False-alarm probability of the peak — this is what makes it *statistical* rather than a threshold |
| `dst_stability` | 1 ÷ distinct destinations contacted by this source in the window |

### DGA + DNS tunnelling — class (c) (9)
| Feature | Definition |
|---|---|
| `qname_char_entropy` | Shannon entropy over characters |
| `qname_bigram_ll` | Mean log-likelihood under a bigram Markov model trained on Tranco top-1M. **This is what catches dictionary DGAs that entropy misses.** |
| `qname_len`, `label_count`, `max_label_len` | |
| `digit_ratio`, `consonant_run_max` | |
| `qtype_txt_null_ratio` | Fraction of TXT/NULL queries from this source vs. its own baseline |
| `subdomain_cardinality` | Per-(source, registered domain) HLL. Tunnelling needs high subdomain cardinality **regardless of encoding**, which is why this survives base32 evasion. |

### Encrypted sessions — class (d) (7)
| Feature | Definition |
|---|---|
| `ja4` | TLS ClientHello fingerprint (BSD-licensed) |
| `tcp_fp` | p0f-style: initial TTL, window size, MSS, options order, window scale |
| `fingerprint_consistency_score` | **The differentiator.** Does this JA4 co-occur with this TCP fingerprint family in the reference table? |
| `ja4_claims`, `tcpfp_claims` | Human-readable labels, both emitted when they disagree |
| `tls_version`, `alpn`, `ext_count` | |
| `splt_seq` | 20 × (signed length, IAT) → Tier 2 |

### Port scanning — class (e) (5)
`vertical_fanout` (distinct dst-ports per (src,dst), HLL), `horizontal_fanout` (distinct dst-hosts per (src,port), HLL), `strobe_score` (few ports × many hosts), `rst_response_ratio`, `mean_bytes_per_flow` (probes are tiny)

### Exfiltration — class (f) (5)
`out_in_byte_ratio`, `out_in_ratio_ewma_7d`, `dst_novelty_score` (first-seen recency), `upload_burst_score`, `sustained_asymmetry_duration`

### Context (3)
`sampling_active`, `sampling_ratio`, `shedding_tier` — so an alert raised during degraded operation says so. Keep this; it's one of the better ideas in your original documents.

---

## 4. Detector specifications

### (a) Volumetric DDoS
Rule layer fires on `pps_to_dst_ewma_dev > 4σ` **AND** (`entropy_explosion_score` high OR `entropy_collapse_score` high) **AND** `syn_synack_ratio_1s > threshold`. Model layer scores in parallel. Alert carries which sub-type (explosion → spoofed flood; collapse → reflection/amplification).

Keep both a rule and a model, and report both. A "rules vs. ML vs. ensemble" ablation table is a strong slide — it shows you didn't reach for ML where a threshold is better, which is a judgement call evaluators notice.

### (b) C2 beaconing — **note the corrected state design**
```
On each packet for a flow:
  if flow passes beacon pre-filter (≥4 pkts, low bytes, stable dst, IAT > 1s):
      ensure entry in BeaconTable[(src, dst, dport)]   ← lazy alloc
      append IAT to its 64-sample ring
  if ring has ≥ 12 samples and time since last analysis > 60s:
      run Lomb-Scargle over a log-spaced frequency grid (512 trial freqs)
      compute false-alarm probability of the peak
      if FAP < 1e-3 and dst_stability high:  → alert
```
State the **maximum detectable period** explicitly: with a 6-hour beacon-table TTL and 12 minimum samples, you detect periods up to ~30 minutes reliably. Say that number out loud in the documentation. Claiming unlimited coverage is what gets you caught.

Budget the Lomb-Scargle cost: 512 frequencies × 64 samples ≈ 33k trig ops per evaluation. On the promoted subset only, this is negligible — but state the number, because "have you costed your periodogram" is a fair question.

### (c) DGA + DNS tunnelling
Score = weighted combination of `qname_char_entropy` and `qname_bigram_ll`. **Both are required.** High-entropy algorithmic DGAs score on entropy; dictionary DGAs (Suppobox-style) have near-normal entropy and are only caught by the bigram likelihood. Demo both — showing that your detector catches the one your competitors' entropy-only detector misses is worth 30 seconds of demo time.

Tunnelling: `subdomain_cardinality` above an EWMA-adaptive per-(source, registered-domain) baseline, **combined with** `qtype_txt_null_ratio` anomaly. Maintain a CDN allowlist so legitimate wildcard use doesn't fire — and log suppressions rather than silently dropping them.

### (d) Encrypted-session malware
Two independent paths, and the fusion is the point:
1. **Behavioural:** SPLT(20) → Tier-2 1D-CNN.
2. **Cross-layer consistency:** JA4 (application/TLS library) vs. TCP fingerprint (OS kernel). Look up the pair in the reference table. A JA4 claiming Chrome-on-Windows against a Linux-family TCP fingerprint is a strong spoofing indicator **that requires no destination reputation data** — which matters, because reputation lookups would violate constraint C-a.

Emit both claims side by side in the evidence. This is your best original idea; make it visible in the UI.

### (e) Port scanning
Three separate features, never collapsed: vertical (many ports, one host), horizontal (one port, many hosts), strobe (few ports, many hosts). Multi-scale HLL windows (1s / 60s / 1h) catch both fast `nmap` and slow scans. Report which pattern fired.

### (f) Exfiltration
EWMA of the outbound:inbound byte ratio per (source, destination) over a long window — **not** a single-window threshold, which slow-drip exfiltration walks straight past. Combine with destination novelty. Allowlist known-asymmetric destinations (backups, CDNs) or your false-positive rate is unusable.

---

## 5. Alert schema (R20 / C-e)

The PS requires five fields: timestamp, flow identifier, threat class, confidence score, supporting evidence. Wrap them in STIX 2.1:

```json
{
  "type": "indicator",
  "spec_version": "2.1",
  "id": "indicator--<uuid>",
  "created": "2026-09-07T10:14:32.501Z",
  "name": "Suspected spoofed-source SYN flood",
  "description": "Elevated SYN:SYN-ACK ratio with high source-IP entropy over 1s, consistent with a spoofed-source volumetric flood against 10.20.4.17:443.",
  "indicator_types": ["anomalous-activity"],
  "pattern": "[network-traffic:dst_ref.value = '10.20.4.17' AND network-traffic:dst_port = 443]",
  "pattern_type": "stix",
  "valid_from": "2026-09-07T10:14:32.501Z",
  "confidence": 87,

  "x_flow_identifier": {
    "proto": "TCP", "src_ip": "<spoofed — low attribution confidence>",
    "dst_ip": "10.20.4.17", "dst_port": 443,
    "directionality": "FWD_ONLY", "completeness_flag": false,
    "window_start": "...", "window_end": "..."
  },
  "x_threat_class": "volumetric-ddos-syn-flood",
  "x_severity": "HIGH",
  "x_confidence_calibrated": true,
  "x_model_lineage": {
    "model_id": "tier1-lgbm-v1.2.0",
    "model_hash": "sha256:...",
    "dataset_version": "2026-09-01-synthetic-v3"
  },
  "x_supporting_evidence": [
    {"feature": "syn_synack_ratio_1s", "value": 41.2, "shap": 0.34},
    {"feature": "src_entropy_1s",      "value": 0.97, "shap": 0.21},
    {"feature": "completeness_flag",   "value": 0,    "shap": 0.09}
  ],
  "x_detection_context": {"sampling_active": false, "shedding_tier": "none"},
  "x_prev_hash": "sha256:...",
  "external_references": [
    {"source_name": "mitre-attack", "external_id": "T1498.001",
     "description": "Direct Network Flood"}
  ],
  "labels": ["cii-relevant"]
}
```

Validate every emitted alert against the STIX 2.1 schema in CI. A non-conformant alert fails the build. That's a two-line CI job and it's a real, checkable claim.

**MITRE ATT&CK mapping** (`external_references`) is nearly free and looks professional. Suggested: T1498/T1498.001 (network DoS), T1071.001/T1571 (C2 channels), T1568.002 (domain generation algorithms), T1572 (protocol tunnelling), T1046 (network service discovery), T1048 (exfiltration over alternative protocol).

---

## 6. Ledger (theme tie-in, ~80 lines)

```
alerts.jsonl:
  each line = {record: {...}, prev_hash: "sha256:...", hash: "sha256:..."}
  hash = SHA256(canonical_json(record) || prev_hash)

Every 100 records (or hourly):
  write a signed anchor: {chain_head, count, ts, sig: Ed25519(...)}

CLI:  python -m engine.alerts.verify alerts.jsonl
      → walks the chain, checks anchors, reports PASS / FAIL at record N
```

Call it a **"hash-chained append-only alert ledger,"** not a Merkle tree (finding E6). State O(n) verification, bounded by anchor spacing.

The demo is 20 seconds: open the JSONL, change one byte in an old record, run `verify`, watch it name the exact record where the chain breaks. That's memorable, and it directly answers the PS's own "preserves a clean chain of custody for forensic use."

---

## 7. Training and validation (R15 / G3 / G4 — currently your weakest area)

This is deliverable #2 in the problem statement and it's barely covered in your existing documents. Write `docs/TRAINING.md` covering:

**Data generation.** Run `training/generate_traffic.sh` once, in a Docker lab, offline. It produces PCAPs using the tools the PS itself names: `iperf3`/`Ostinato` for benign background, `hping3` for SYN/UDP floods, `Slowloris`, `dnscat2`/`iodine` for tunnelling, DGArchive-derived name lists replayed as DNS queries, `nmap` plus a custom slow-scan script, and a chunked-upload exfiltration script. Commit the resulting PCAPs (trimmed and small) so nothing needs generating at demo time.

**Splitting — temporal, not random.** Split by capture session and time window, never randomly across flows. Random splitting leaks: flows from the same attack burst land in both train and test and your reported accuracy becomes fiction. This is the single most common flaw in published NIDS results and saying you avoided it is a strong signal.

**Prevalence — state it, twice.** Train on a rebalanced set with class weights (your 10:1 FN:FP cost ratio is a reasonable default and you've justified it well). But **construct the test set at a realistic prevalence** — 1 attack flow per 1,000 to 10,000 benign — and report every metric against that. Then your PR-AUC argument holds together. Right now your documents argue for PR-AUC on the basis of <0.01% real-world prevalence while planning to measure on a synthetic set of unstated balance. Fixing this is half a day and it closes your most exposed flank (finding G4).

**Metrics.** PR-AUC and per-class F1 as headline; precision and recall per threat class; ROC-AUC internal only. Plus a **reliability diagram** for the calibration claim — a calibration curve on a slide is unusually persuasive because almost nobody produces one.

**Add one public benchmark.** CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15, or CTU-13 for the botnet class. One extra day, and it gives you a number comparable to published literature instead of only self-generated results. (If you use CIC-IDS2017, note that its labelling has been criticised and corrected versions have been published — mentioning that you're aware of it is itself a credibility signal.)

**Ablation table.** Rules only / ML only / rules + ML, per threat class. Shows engineering judgement rather than reflexive model-throwing.

---

## 8. Throughput and latency harness (R19 / C-d)

This is the constraint most teams fumble and the cheapest one to win.

```
bench/throughput.py
  --scenario  <pcap>
  --mode      virtual          # consume as fast as possible
  --duration  300
  reports:  flows/sec sustained (p50, p5, min)
            packets/sec, Mbps
            wire-to-alert latency: p50, p95, p99, p999
            peak RSS
            per-stage timing breakdown
```

`bench/RESULTS.md` must record the exact hardware (CPU model, cores, RAM, OS, Python version), the exact command line, and the measured numbers. A judge should be able to re-run it verbatim.

**Measure latency wire-to-alert** — from the packet's own timestamp to alert emission — not feature-extraction-to-alert. Your documents already insist on this (item 75) and they're right; just make sure the code actually does it.

**Report p50 and p99 as measured facts**, not as an SLO you pre-committed to (finding E7). And put the live counter **on the dashboard** during the demo. Every other team will have a number on a slide. You'll have one moving on screen while the judge watches.

---

## 9. The nine demo scenarios

One committed PCAP each. These double as your test corpus and your demo menu.

| # | Scenario | Proves |
|---|---|---|
| 1 | Benign baseline, 5 min | False-positive rate; steady-state memory |
| 2 | SYN flood, spoofed sources | (a) entropy explosion |
| 3 | UDP/DNS reflection | (a) entropy collapse — the *other* sub-type |
| 4 | Slowloris | (a) low-rate protocol exhaustion |
| 5 | **Jittered C2 beacon (±30%)** | (b) Lomb-Scargle beats FFT — your best technical demo |
| 6 | DGA burst — high-entropy **and** dictionary families | (c) why entropy alone is insufficient |
| 7 | DNS tunnelling (`iodine`) | (c) subdomain cardinality survives encoding evasion |
| 8 | **JA4-spoofed TLS from a Linux host** | (d) cross-layer disagreement — your best original idea |
| 9 | `nmap -sS` fast scan + a slow scan | (e) multi-scale windows |
| 10 | Slow-drip exfiltration | (f) EWMA beats single-window thresholds |

Scenario 1 running alongside any attack scenario is also your **false-positive demonstration** — run benign traffic for the full session and show the alert count stays at zero.

---

## 10. Build order

Strictly this order. Each step produces something demonstrable.

1. `FlowMetadata` + PCAP source + flow table → prints flows. **You have ingest.**
2. Rule-based DDoS + scan detectors → prints alerts. **You have detection.**
3. FastAPI + WebSocket + a bare React alert list. **You have a demo.**
4. Metrics + the on-screen throughput/latency meter. **You have constraint C-d.**
5. Sketches (CMS, HLL, entropy) → the remaining rule detectors.
6. Feature extraction → LightGBM Tier 1 + calibration. **You have ML.**
7. SHAP evidence + the NL template. **You have explainability.**
8. STIX schema + hash-chained ledger + `verify`. **You have the theme tie-in.**
9. Beacon table + Lomb-Scargle. **You have your best demo.**
10. JA4 + TCP fingerprint + consistency score. **You have your best idea.**
11. Tier 2 + anomaly layer.
12. Polish, docs, benchmark run.

**Steps 1–4 are the minimum viable submission.** If everything goes wrong, steps 1–4 plus honest documentation still satisfies most of the PS. Get there first, then extend.
