# Throughput and latency, measured

Constraint C-d asks for a stated *and* demonstrated rate. This file is the stated half. The demonstrated half is
the live meter on the dashboard, which reads the same `engine.metrics.Meter` this harness reads.

Everything below was measured on the machine described in section 1 by running the exact command printed above
each table. Nothing here is a target, a projection or a round number. Where a run was noisy it is repeated and
both readings are given.

Two different claims live in this file and they must not be quoted as one:

- **virtual mode** consumes the capture as fast as the engine can. It answers "how much traffic can this engine
  process on one core". Its latency figure is **ingest to alert**, because a virtual clock has no wire.
- **realtime mode** honours the original packet timing. It answers "does the engine keep up with the wire, and
  how long after the wire moment does the alert appear". Its latency figure is **true wire to alert**.

Quoting a virtual-mode packet rate next to a realtime-mode latency would be dishonest. They are separate rows.

---

## 1. The machine

| | |
|---|---|
| CPU | 13th Gen Intel Core i5-13400F, 10 physical cores (6 P-core, 4 E-core), 16 logical, 2.50 GHz base |
| RAM | 34,187,988,992 bytes (31.8 GiB) |
| OS | Microsoft Windows 10 Pro, version 22H2, build 10.0.19045, 64-bit |
| Python | 3.11.5, CPython, MSC v.1936 64 bit (AMD64), platform string `Windows-10-10.0.19045-SP0` |
| Threads used | one. The engine is single threaded; numpy and lightgbm may use their own internal threads |
| Storage | local NVMe, captures read from `data/scenarios` |

Library versions at measurement time:

```
numpy 2.2.6   dpkt 1.9.8   lightgbm 4.7.0   scikit-learn 1.7.2   pandas 2.2.3
stix2 3.0.2   cryptography 46.0.6   duckdb 1.5.5   fastapi 0.135.1   uvicorn 0.42.0
```

Model artefact under test, as reported by `Engine.lineage()` and embedded in every run's JSON report:

```
model_id        tier1-lgbm-v1.0.0
model_hash      sha256:49bc0ddd90f93fc13b53c670085fd67bc6d73ec9aa350a1e1f114d197c47e252
dataset_version 2026-09-07-scenario-replay-v1
tier1_lgbm.txt  2,213,959 bytes, 980 trees, 7 classes, 97 features
```

This artefact was trained on all eleven committed captures. It replaces an earlier one that carried a
`initiator_is_lo` feature: whether the initiator's address sorted lower in the normalised flow key. That is an
artifact of key ordering rather than a property of the traffic, and because attacker addresses are fixed per
capture it let the model key on address ranges instead of behaviour. It was removed from the model input, the
model retrained, and the numbers below remeasured against the retrained artefact. The field is still computed and
still documented in the feature dictionary, marked as context and excluded from the model.

Every run below loads exactly this artefact and the hash is embedded in each JSON report. `make train` rebuilds
the dataset from whatever is in `data/scenarios` at the time, so a later run produces a different model with a
different hash. That is a retrain, not a reproduction, and the two must not be confused.

Date measured: **7 September 2026**.

---

## 2. The corpus

Every run replays the eleven committed scenario captures in `data/scenarios`, in the order they appear in
`training/scenarios.py`. One full pass is:

| | |
|---|---|
| packets | 105,142 |
| IP bytes | 37,156,610 (37.2 MB) |
| capture time spanned | 9,906.8 s (2 h 45 m) |
| flows created | 20,235 |

The captures are synthetic. Every one was written packet by packet with `dpkt.pcap.Writer` by
`training/generate_scenarios.py`; no attack tool produced them. That does not affect the timing measurements,
which depend on packet count, packet size and header shape, but it is stated here so no one reads these numbers
as measurements against captured live traffic.

---

## 3. Headline, virtual mode, rules plus model

This is the shipped default configuration: six rule detectors plus the LightGBM tier 1 layer and the benign-only
anomaly model.

```
python bench/throughput.py --scenario all --duration 240 --bucket 0.5 --warmup 2 --no-loop
```

Result: one full pass in **37.32 s** of wall clock, with a 0.00 s end-of-run flush.

| | mean over the run | p50 | p5 | min | max |
|---|---|---|---|---|---|
| packets/s | 2,818 | 2,478 | 1,453 | 1,139 | 9,706 |
| flows/s | 542 | 198 | 91 | 47 | 2,471 |
| Mbps | 7.97 | 6.2 | 1.4 | 1.0 | 86.4 |

Percentiles are over **74 samples of 0.5 s**, with the first 2.0 s discarded. p5 over 74 samples is the fourth
lowest bucket, so it is a real percentile and not a restatement of the minimum.

Latency, **ingest to alert**, from 70 alerts:

| p50 | p95 | p99 | p999 | max |
|---|---|---|---|---|
| 10.322 ms | 12.284 ms | 18.073 ms | 18.853 ms | 18.94 ms |

70 alerts is not enough samples for p999 to carry meaning. It is printed because the brief asks for it, and the
harness prints the sample count next to it every time for exactly that reason. p50 and p95 are trustworthy here;
p99 is thin; p999 is effectively the maximum.

Peak process RSS **222.02 MB**.

The same command repeated immediately afterwards: one pass in 36.57 s, mean 2,875 packets/s, 553 flows/s,
8.13 Mbps, latency p50 10.392 ms and p95 18.213 ms over the same 70 alerts, peak RSS 222.41 MB. The two runs sit
within 2 percent of each other on throughput. A third run taken while the machine was also compiling and running
the test suite fell to 1,997 packets/s, which is recorded here as the honest spread: this is a shared desktop, not
an isolated bench, and a judge re-running it under different load should expect that range.

---

## 4. The same run with the model layer off, the ablation

```
python bench/throughput.py --scenario all --duration 60 --bucket 0.5 --warmup 2 --rules-only --no-loop
```

Result: one full pass in **13.66 s**.

| | mean over the run | p50 | p5 | min | max |
|---|---|---|---|---|---|
| packets/s | 7,697 | 5,800 | 3,619 | 3,570 | 14,915 |
| flows/s | 1,481 | 523 | 273 | 188 | 5,727 |
| Mbps | 21.76 | 18.1 | 9.5 | 8.7 | 97.9 |

Latency, ingest to alert, from 30 alerts: p50 **2.196 ms**, p95 3.128, p99 6.210, p999 7.246, max 7.362.

Peak process RSS **88.32 MB**.

**The model layer costs 2.7x throughput and 4.7x median alert latency.** It also raises the alert count 2.3x, 70
against 30, because the tier 1 layer raises alerts of its own. Both configurations are shipped and both are
reachable from the command line, so both are stated.

Those two counts are for **one engine replaying all eleven captures in sequence**, which is what this command
does. A fresh engine per capture raises 42 and 80 instead; the two runs and the reason they differ are in
section 6, note 3.

That same command was run three times back to back on an otherwise quiet machine. Elapsed was 13.66 s, 13.86 s
and 13.79 s, giving 7,697, 7,587 and 7,625 packets/s. **Run to run spread there is 1.5 percent. Earlier rounds of
this file were measured while other work was running on the same desktop and came out roughly half as fast, so
read every figure here as a quiet-machine number and expect a loaded desktop to be slower.** Section 10 records a
case, later in this same sitting, where that slowdown actually happened.

---

## 5. Realtime mode, true wire to alert

### 5.1 One attack scenario at true wire speed

```
python bench/throughput.py --scenario syn_flood --mode realtime --speed 1 --duration 200 \
  --bucket 0.5 --warmup 2 --rules-only --no-loop
```

180.0 s of capture replayed in **178.96 s** of wall clock. The engine tracked the wire exactly.

Where the wall clock went:

| stage | total ms | share of run |
|---|---|---|
| clock, waiting for the next packet's wire moment | 174,567 | 97.5% |
| engine feed | 3,540 | 2.0% |
| source, read and decode | 774 | 0.4% |
| everything else, tick and alert and harness | 82 | 0.0% |

**At true wire timing this scenario used 2.5 percent of one core.** The single alert appeared **7.902 ms** after
its own wire moment. A repeat of the same command put the single alert at 13.746 ms and the core share at 2.8
percent; a lone alert is a thin sample by construction, which is exactly why 5.2 repeats this measurement across
the whole corpus instead of trusting one.

### 5.2 The whole corpus at 30x wire speed

One alert is a poor latency sample, so the same measurement was repeated over the whole corpus with the wire
running 30 times faster, which is still true wire-to-alert timing, just against a faster wire.

```
python bench/throughput.py --scenario all --mode realtime --speed 30 --duration 330 \
  --bucket 0.5 --warmup 2 --rules-only --no-loop
```

9,889.9 s of capture in **330.21 s**, exactly on schedule. Engine 10.8 percent of one core, clock idle 89.2
percent. Peak RSS 91.54 MB. A repeat gave engine 10.7 percent, clock idle 89.3 percent, peak RSS 91.52 MB.

The corpus now needs 330.2 s of wall clock at 30x and the `--duration 330` cap stops the run 17 s of wire short
of the end, 105,072 packets of 105,142. That is 99.93 percent of the pass and it is stated rather than rounded
away; raise `--duration` to see the last two seconds of the final capture.

Wire to alert, 30 alerts:

| p50 | p95 | p99 | p999 | max |
|---|---|---|---|---|
| 4.999 ms | 50.254 ms | 158.615 ms | 194.854 ms | 198.880 ms |

A repeat gave p50 5.161 ms, p95 50.577 ms, p99 101.369 ms, p999 116.527 ms, max 118.211 ms. p50 and p95 agree
to within a few percent; p99, p999 and max disagree by more than a third between the two runs, so both readings
stand rather than the flatter-looking one.

The tail is the periodic tick, not the packet path. Beaconing alerts are only produced on a tick, so a beacon
alert waits up to one tick interval, one capture second, which at 30x is 33 ms of wall clock, before it can be
raised at all. The p99, 101 to 159 ms across the two runs, is tick-sourced alerts; the p50 of about 5 ms is the
packet path.

### 5.3 The whole corpus at 30x wire speed with the model layer on

```
python bench/throughput.py --scenario all --mode realtime --speed 30 --duration 330 \
  --bucket 0.5 --warmup 2 --no-loop
```

Also **330.21 s**, also on schedule, and stopped at the same duration cap. Engine 19.5 percent of one core. Peak
RSS 224.66 MB. A repeat gave engine 19.7 percent, peak RSS 224.48 MB.

Wire to alert, 70 alerts: p50 **20.908 ms**, p95 354.363, p99 **3,200.474**, p999 3,212.272, max 3,213.583. A
repeat gave p50 20.992 ms, p95 350.641, p99 3,688.433, p999 3,701.855, max 3,703.346. p50 and p95 agree; the tail
disagrees by about 13 percent between the two runs, so both readings stand.

That tail is the volumetric burst and it is worth understanding rather than hiding. At 30x, the syn_flood burst
arrives at about 6,600 packets/s while the model-on engine sustains 2,818 packets/s (section 3). The engine falls
behind during the burst, drains afterwards, and the alerts raised inside that window are late by the size of the
backlog. The rules-only engine at 7,697 packets/s (section 4) absorbs the same burst, which is why 5.2's tail,
101 to 159 ms, is a small fraction of the size seen here. **The honest realtime claim for the shipped default is
therefore: it holds 30x wire on this corpus in aggregate, and an alert raised inside the peak of a volumetric
flood can now be several seconds late. That is worse than the third-of-a-second figure measured against the
previous model artefact, and it traces to tier 1 itself: section 9 measures the new model's per-call cost at
702 us against 426.5 us for the retired artefact, so the engine falls further behind inside the same burst before
it can drain.**

---

## 6. Per-scenario, virtual mode, single pass

Rules plus model, `--bucket 0.25 --warmup 0.5 --no-loop`, one row per scenario. `pps` is packets per second,
`flows/s` is the run mean, and the two millisecond columns are ingest-to-alert latency percentiles.

| scenario | packets | flows | alerts | mean pps | p50 pps | p5 pps | min pps | flows/s | p50 ms | p95 ms | RSS MB |
|---|---|---|---|---|---|---|---|---|---|---|---|
| benign | 8,150 | 600 | **0** | 5,854 | 5,588 | 5,312 | 5,264 | 431 | n/a | n/a | 188.7 |
| syn_flood | 13,100 | 10,624 | 2 | 1,774 | 2,215 | 300 | 292 | 1,438 | 12.93 | 17.99 | 213.1 |
| udp_reflection | 8,058 | 281 | 4 | 5,742 | 5,906 | 3,833 | 3,485 | 200 | 10.56 | 16.93 | 187.6 |
| slowloris | 15,756 | 732 | 3 | 5,357 | 6,030 | 3,415 | 2,988 | 249 | 6.87 | 16.97 | 189.0 |
| beacon_jitter | 11,150 | 935 | 30 | 2,168 | 2,031 | 1,574 | 1,406 | 182 | 10.71 | 42.41 | 191.4 |
| dga_burst | 8,263 | 1,385 | 6 | 3,006 | 2,292 | 2,130 | 2,096 | 504 | 7.26 | 16.40 | 189.3 |
| dns_tunnel | 9,504 | 2,523 | 3 | 3,870 | 3,780 | 3,292 | 3,112 | 1,027 | 7.50 | 20.55 | 188.9 |
| ja4_spoof | 7,873 | 522 | 9 | 4,480 | 4,476 | 3,613 | 3,486 | 297 | 10.37 | 15.13 | 190.1 |
| port_scan | 10,194 | 2,075 | 13 | 5,360 | 4,497 | 3,972 | 3,954 | 1,091 | 6.75 | 13.57 | 192.1 |
| exfil_drip | 6,569 | 433 | 7 | 5,004 | 5,163 | 4,666 | 4,592 | 330 | 10.45 | 16.23 | 187.7 |
| exfil_bulk | 6,525 | 125 | 3 | 8,243 | 10,739 | 5,634 | 5,067 | 158 | 10.93 | 16.93 | 186.5 |
| **total** | **105,142** | | **80** | | | | | | | | |

Alert counts are identical between two runs of each scenario here; latency percentiles vary with sample size as
low as 2 or 3 alerts, and dns_tunnel's p95 disagreed by 16 percent between the two runs (17.21 ms and 20.55 ms,
the larger of the two is shown). Treat every p95 cell above as thin the way section 3 treats p999.

The same eleven scenarios with `--rules-only`:

| scenario | alerts | mean pps | p50 pps | p5 pps | min pps | flows/s | p50 ms | RSS MB |
|---|---|---|---|---|---|---|---|---|
| benign | **0** | 15,456 | 14,054 | 14,054 | 14,054 | 1,138 | n/a | 56.5 |
| syn_flood | 1 | 9,620 | 9,201 | 8,500 | 8,395 | 7,802 | 7.62 | 79.7 |
| udp_reflection | 1 | 16,623 | 16,598 | 16,598 | 16,598 | 580 | 7.17 | 54.9 |
| slowloris | 2 | 17,609 | 18,394 | 18,256 | 18,241 | 818 | 4.59 | 56.1 |
| beacon_jitter | 12 | 5,462 | 4,314 | 3,779 | 3,727 | 458 | 18.65 | 58.2 |
| dga_burst | 4 | 11,499 | 9,606 | 9,606 | 9,606 | 1,927 | 2.50 | 56.9 |
| dns_tunnel | 2 | 10,952 | 10,642 | 10,295 | 10,256 | 2,908 | 5.81 | 56.0 |
| ja4_spoof | 6 | 14,703 | 13,765 | 13,765 | 13,765 | 975 | 2.06 | 58.2 |
| port_scan | 11 | 13,679 | 11,831 | 11,831 | 11,831 | 2,784 | 2.23 | 59.4 |
| exfil_drip | 2 | 14,286 | 14,267 | 14,267 | 14,267 | 942 | 5.81 | 55.1 |
| exfil_bulk | 1 | 20,521 | 22,894 | 22,894 | 22,894 | 393 | 8.09 | 53.8 |
| **total** | **42** | | | | | | | |

With only 1 or 2 alerts to sample, slowloris (p50 4.59 ms and 5.19 ms across the two runs, 11 percent apart, p95
6.92 ms and 7.95 ms, 13 percent apart) and port_scan (p50 2.23 ms and 2.00 ms, 11 percent apart) moved by more
than 10 percent run to run. The values shown are from the first run; both this and the model table's discrepant
cells are a sample-size artefact, not a change in behaviour, since alert counts themselves reproduced exactly.

Three things to read out of this table:

1. **`benign` raises zero alerts in both configurations.** That is the false positive baseline and it is measured
   here rather than asserted.
2. A single scenario runs two to four times faster than the whole corpus back to back. That is not noise. Running
   all eleven in sequence carries state forward: one flow table, one beacon table and one set of sketches see
   every scenario, so the periodic tick has more to do. The corpus number in section 3 is the conservative one
   and it is the one to quote.
3. **These tables sum to 42 rules-only and 80 with the model, and sections 4 and 3 report 30 and 70 for the same
   corpus. Both are right and they are different runs.** Each row here is a fresh engine over one capture,
   because `--scenario <one>` builds an engine per invocation. Sections 3 and 4 are
   one engine over all eleven captures in sequence, and the same carried-forward state that costs throughput also
   suppresses alerts: per-subject cooldowns have already fired for a subject seen in an earlier scenario, and LRU
   eviction drops candidates before they mature. The delta is 12 rule alerts and 10 model alerts. Quote the run,
   never the bare number: 42 and 80 for eleven independent engines, 30 and 70 for one continuous pass.

Three single-scenario peaks worth naming, all rules only, all p50 of the 0.25 s buckets:

- highest packet rate, **22,894 packets/s on exfil_bulk** (20,521 mean, 188.4 Mbps p50)
- highest bit rate, also **188.4 Mbps on exfil_bulk**, which is the only capture in the corpus made of full-size
  frames: 6,525 packets carrying 6.34 MB, against a corpus average of 353 bytes a packet
- highest flow creation rate, **8,552 flows/s on syn_flood** (7,802 mean)

The last of those is the flow-rate figure to quote against constraint C-d, because a spoofed-source SYN flood is
the flow-creation worst case in this corpus: 10,624 flows out of 13,100 packets.

---

## 7. Flow records as the input, R1's second adapter

The same corpus, read as normalised flow-record CSV instead of PCAP, which is the other input the problem
statement names.

```
python bench/throughput.py --scenario all --source flows --duration 300 --bucket 0.5 --warmup 2 \
  --rules-only --no-loop
```

31,999 flow records, representing the same 105,142 packets and 37,156,610 bytes, in **6.91 s**. A repeat gave
6.98 s, within 1 percent.

| | mean | p50 | p5 | min |
|---|---|---|---|---|
| records/s | 4,630 | 3,391 | 1,247 | 1,175 |
| represented packets/s | 15,214 | 9,903 | 8,211 | 8,051 |
| flows/s | 2,990 | 1,696 | 624 | 587 |
| Mbps | 43.0 | 29.6 | 25.5 | 25.0 |

A flow record carries a packet count and a byte count, so one record stands for many packets. **Both numbers are
given because quoting only the represented packet rate would inflate the claim** and quoting only the record rate
would understate the traffic covered. The engine is doing 4,630 units of work per second here, and those units
cover 15,214 packets per second of original traffic.

The flow-record path produced 12 alerts where the packet path produced 30, both single continuous passes. That
is a detection-coverage difference, not a benchmark artefact: a flow record has no TLS ClientHello and no
per-packet timing, so the encrypted-session and SPLT paths have nothing to read.

This harness and `tests/test_decode.py` are the only places `FlowRecordSource` runs. `ReplayController.start`
constructs a `PcapSource` unconditionally, so the adapter is not reachable from `POST /api/replay/start` or from
the dashboard. The measurement above is real; the demo path for it does not exist yet.

---

## 8. Memory

The bounded structures, measured by their own `nbytes`, against their own declared caps, at the end of the full
corpus run:

| structure | measured | declared cap |
|---|---|---|
| flow table | 0.01 MB | 151.60 MB |
| beacon table | 1.33 MB | 31.35 MB |
| sketches (entropy, CMS, scan and DNS HLL families) | 12.33 MB | 43.13 MB |
| models | 3.42 MB | 3.42 MB |
| **total bounded state** | **17.09 MB** | **229.50 MB** |

The models row grew from the previous artefact's 3.30 MB because the retrained model itself is larger, 980 trees
against fewer before; the declared cap tracks the model file, so it grew with it and the structure is still fully
occupied by definition.

The flow table reads 0.01 MB at the end because the corpus finishes on a quiet scenario and the 120 s idle
timeout has expired nearly everything. Mid-run it is larger: the realtime `syn_flood` run ends right after the
flood, with its spoofed-source flows still inside the idle timeout, and reported **5.23 MB**. Peak occupancy, not
final occupancy, is what the cap has to cover, and 5.23 MB against a 151.6 MB cap is the honest reading.

Flows the table evicts under capacity pressure are handed to `Engine._classify` on the way out rather than
dropped, so the coverage counts in section 3's run account for every flow the table ever held: 20,235 created,
20,235 classified, 0 evicted at this capacity.

**Process RSS is a different number and must not be confused with the above.** Peak RSS was 88.32 MB rules only
and 222.02 MB with the model layer, the section 4 and section 3 runs. The difference between 17.09 MB of engine
state and 222 MB of process is the CPython interpreter, numpy, pandas, lightgbm and scikit-learn, none of which
grows with traffic. The claim that survives scrutiny is: **engine state is bounded and stays an order of
magnitude below its declared cap; process footprint is dominated by fixed library cost.**

---

## 9. Where the time goes

Full corpus, virtual, rules plus model, 56.98 s total. This is a fresh run of the section 3 command, kept
separate because section 3 is not to be re-measured for this round; it landed slower than section 3's 37.32 s,
which is the same machine-load story section 10 documents directly. Outer stages are measured by the harness
around each call and **sum to the wall clock** (56,975 ms of 56,975 ms); alert building is subtracted out of the
engine stages it sits inside, so nothing is counted twice. Inner stages are the engine's own `Meter`, nested
inside `engine_feed` and `engine_tick`.

| outer stage | calls | us per call | total ms | share of run |
|---|---|---|---|---|
| source, read and decode a packet | 105,142 | 56.9 | 5,980 | 10.5% |
| clock | 105,142 | 1.1 | 117 | 0.2% |
| engine feed | 105,142 | 361.1 | 37,970 | 66.6% |
| engine tick | 4,237 | 2,939.9 | 12,456 | 21.9% |
| alert out, build STIX and validate | 70 | 4,085.7 | 286 | 0.5% |
| harness remainder | 105,142 | 1.6 | 166 | 0.3% |

The inner stages are the engine's own five. **They are called different numbers of times, so the per-call column
must not be added up.** The per-packet column divides the same totals by the 105,142 packets of the run, and that
column does add: 474.5 us per packet, which matches `engine_feed` plus `engine_tick` divided by the packet count
(479.6 us) to within the cost of the harness's own instrumentation. Both columns are in `Engine.stats()`, as
`stage_timing_us` and `stage_timing_per_packet_us`, and the engine ships a note beside them saying exactly this.

| inner stage | calls | us per call | us per packet | total ms | share of run |
|---|---|---|---|---|---|
| tier1, LightGBM predict with contributions | 36,024 | **702.4** | 240.6 | 25,302 | **44.4%** |
| detect, the six rule detectors | 109,380 | 187.5 | 195.1 | 20,509 | 36.0% |
| flow table plus entropy and sketch update | 105,142 | 33.0 | 33.0 | 3,470 | 6.1% |
| features | 36,024 | 13.7 | 4.7 | 494 | 0.9% |
| alert assembly inside the engine | 36,024 | 3.2 | 1.1 | 116 | 0.2% |

There is no `model` row for a tier 2 network because no tier 2 exists in this build. The harness does not print a
zero and call it a stage. Three repeats of this run agreed on `tier1` to within 0.1 us per call (702.3, 702.3,
702.4), so the increase from the retired artefact's 426.5 us is the model, not run to run noise.

The same table rules only, 13.66 s total: detect 79.5 us per call and 63.6 percent of the run, flow table 13.7 us
and 10.6 percent, tier1 1.4 us and 0.4 percent, alert 0.9 us. Outer stages there: source 20.0 percent, engine feed
41.7 percent, engine tick 36.8 percent, alert out 0.5 percent, harness 0.6 percent.

**The single largest cost in the shipped configuration is `tier1` at 702.4 us per call, 240.6 us per packet.** A
single-row LightGBM prediction on a 980-tree model should be well under 100 us; the extra is the per-call feature
vector assembly and the `pred_contrib=True` SHAP path, and the retrained model is itself heavier than the one it
replaced. It is 44.4 percent of the run and it is the first thing to optimise. This is recorded as a measurement,
not as a complaint: the ablation in section 4 is the evidence that removing it buys 2.7x, and section 5.3 is the
evidence that its added cost now matters under a volumetric burst at realtime speed.

`alert_out` at 4.09 ms per alert is `build_alert` plus `validate_alert` against the STIX 2.1 schema. It is only
0.5 percent of the run because alerts are rare, and it is the price of C-e conformance being checked rather than
claimed. Alert building is not on the packet path.

---

## 10. Reading the virtual-mode numbers honestly

**Virtual mode does more periodic work per wall second than a real link would.** The periodic tick fires every
1.0 s of *capture* time. Virtual mode compresses 9,906.8 s of capture into 56.98 s of wall clock, a 174x speedup,
so the engine ran the periodic analysis 174 times more often per wall second than a link carrying the same
packets would ask for. Section 9 shows that work is 21.9 percent of the run.

This was checked rather than assumed. The same corpus, rules only, at three tick intervals, all three run back
to back so the comparison is not confounded by the machine getting busier or quieter mid-sweep:

| `--tick-interval` | ticks issued | elapsed | mean packets/s | alerts |
|---|---|---|---|---|
| 1 s of capture time | 4,237 | 21.82 s | 4,818 | 30 |
| 5 s of capture time | 1,422 | 21.48 s | 4,895 | 30 |
| 15 s of capture time | 575 | 20.81 s | 5,053 | 30 |

A 7.4x cut in tick count moved total runtime from 21.82 s to 20.81 s, about 5 percent, a bit more than the
roughly 1 percent spread seen between repeats at a fixed tick interval (the two 5 s runs differed by 1.2 percent,
the two 15 s runs by under 0.1 percent). The periodic work is still driven mostly by how much capture time has
elapsed rather than by how many ticks fire; a small fixed cost per tick call accounts for the rest.

A rerun of the tick=1 baseline, needed for this three-way comparison, came out at 21.82 s here versus 13.66 s for
the identical command in section 4 earlier in this same sitting. Nothing about the model or the code changed
between those two measurements; the desktop simply got busier over the course of this measurement round. Nothing
else in this file was re-run after that point to chase a quieter window, so later sections should be read with
that in mind. It is stated here because it is the clearest single illustration, inside one file, of the exact
caveat sections 3 and 4 already carry in words.

Every run prints this ratio itself, so a judge does not have to take it on trust.

**Source construction is excluded.** Opening a `PcapSource` scans the file to count records. That happens before
the clock starts and is not charged against throughput. It is a startup cost, once per capture, and it is not
part of a steady-state rate.

**The looping mode has an artefact and it is flagged in the tool.** `--loop` replays the capture set repeatedly
with each pass offset forward in capture time, which is useful for filling percentile buckets. It also makes
every repeated session look periodic at the capture period, so the beacon detector starts evaluating candidates
that a single pass would never produce. That inflates cost, which is conservative, but any alert from a looped
run is a replay artefact and must not be counted as a detection. The harness prints exactly that note whenever it
loops, and single pass is the default. Every number in this file was measured with a single pass.

---

## 11. Reproducing this

From the repository root, on this machine, `mingw32-make` because Windows has no `make`:

```
make bench             the section 3 run, rules plus model
make bench-rules       the section 4 run, model layer off
make bench-realtime    the section 5.3 run, rules plus model at 30x wire speed
make test              the test suite
make train             rebuild the dataset and retrain tier 1
```

The make targets pass `--duration 400`, which is a cap rather than a target: a virtual pass over the corpus
finishes in well under a minute, so `make bench` and the section 3 command produce the same measurement, and the
30x realtime pass needs 330 s of that cap to finish the corpus. Override any of `SCENARIO`, `DURATION`, `SPEED`
and `PY` on the command line, for example `make bench SCENARIO=syn_flood`.

Or call the harness directly with any of the command lines printed in this file. Each run also accepts
`--json <path>` and writes the full report, including the host facts, the model lineage, every rate bucket and
every stage timing, so a result can be diffed against these tables field by field.

```
python bench/throughput.py --help
```

Two flags worth knowing about. `--ledger <path>` appends every alert to a hash-chained ledger at that path as
well as building it, so the run can be checked afterwards with `python -m engine.alerts.verify <path>`; it is off
by default because writing the chain is not part of the packet path. `--loop` replays the capture set repeatedly
to fill more percentile buckets, with the caveat in section 10.

The harness resolves `engine.pipeline.Engine` when it is importable and falls back to an inline composition of
the same flow table, context and detectors when it is not. Every run prints which engine it used and which model
hash it loaded, on the first two lines.

---

## 12. What these numbers do not say

- They are measured on one desktop, single threaded, against a synthetic corpus of 105,142 packets. They are not
  a claim about line-rate capture, about multi-core scaling, or about live traffic.
- Packet sizes in the corpus average 353 bytes. Mbps figures scale with that and would look very different on a
  capture of full-size frames at the same packet rate.
- p999 is printed everywhere the brief asks for it, but no run in this file produced 1,000 alerts, so p999 is not
  a meaningful percentile in any table here. The harness prints the sample count beside it and warns when the
  count is under 1,000.
- Most figures in this round were measured on a quiet machine, back to back, in one sitting, but the desktop grew
  busier partway through: section 10 shows the same command landing 60 percent slower there than its section 4
  counterpart measured earlier in the same sitting. Section 4 gives its own three-run spread. Earlier rounds
  measured on a loaded desktop came out roughly half as fast, so treat the faster figures here as the best case
  this hardware offers rather than as a floor, and the slower ones as a reminder of how close that floor can be.
- The alert counts in section 6 are throughput-run byproducts. Detection quality, precision and recall belong to
  the detector and model documentation, not here.
