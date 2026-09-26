# Network Watch: what it is and how to use it

## 1. The idea in one sentence

**Network Watch reads live or saved network traffic, looks for suspicious behavior, and explains its alerts so a person can investigate.**

## Live monitor: start passive real-time analysis

Open **Live monitor** in the navbar, using engine mode (`?mock=0`). Choose a local interface, keep the `ip` filter or narrow it, then choose **Start monitoring**. Wireshark/dumpcap and Npcap are required on Windows. Select the interface attached to the traffic mirror or data diode; a normal Wi-Fi interface only sees traffic available to that adapter.

The six detector families run together. Alerts are saved automatically to `data/alerts.jsonl`, or the configured state folder, before the dashboard receives their notification. On **Alerts**, **Download JSON** exports the complete stored history as a JSON array; **Download JSONL** exports one alert per line. These buttons export all saved records, not just the current browser filters or 400 visible alerts.

Live monitoring and replay share one engine, so stop one before starting the other. Live capture cannot be paused without missing traffic. **Stop monitoring** ends capture and keeps saved alerts. API restart or development auto-reload also stops capture; it does not resume automatically.

Watch the queue, stale-packet drops, and truncation counters. Driver drop counts are unavailable and must not be assumed to be zero. The live p99 metric includes metadata queueing, detection, and persistence; it excludes driver buffering and the observation period required to recognize a pattern.

This live path supports IPv4. Encrypted content is never decrypted; TLS and QUIC metadata visibility differs, and a validated QUIC malware classifier is not included. A physical one-way boundary requires a mirror/data diode deployment; software alone cannot provide it. The repository guide `docs/LIVE_MONITORING_26145.md` maps all NTRO requirements and records the measured limits.

It is a network threat detection prototype for SIH 2026. It uses rules and machine-learning models to analyze visible network information: addresses, ports, packet sizes, timing, DNS fields, and available encrypted-session metadata. It groups related packets into conversations called **flows**.

The dashboard is a window into the analysis. It does not automatically block traffic. A replay reads a local capture file; it does not transmit the captured attack packets onto a network.

## 2. Which dashboard am I using?

| View | Purpose | Local address |
| --- | --- | --- |
| Simple dashboard | Learning, demonstrations, and quick alert review | `http://127.0.0.1:8000/simple/?mock=0` |
| Original / advanced dashboard | Detailed analyst, operations, and training controls | `http://127.0.0.1:8000/?mock=0` |

The original dashboard is preserved in `ui/`. The simplified copy lives in `ui-simple/`. **Both views share one detection engine**, so starting, pausing, or stopping a real replay affects both. Open the original using **Advanced view** in the desktop navbar or **Original dashboard** in the footer.

**Engine mode** shows results from the local detection API. An “Engine connected” badge means the browser’s live connection is open; it does not mean a network has been declared safe.

**Sample mode** is a browser-only illustration. Alerts, scores, throughput, and record verification are simulated, and no model is running. It is useful for learning the interface, not evaluation. Use **Connect to engine** or `?mock=0` to leave it. This setting does not change the original dashboard’s sample-mode preference.

## 3. Start the site

With the project’s Python dependencies installed, open a terminal in `SIH2026_prototype` and build the simplified frontend:

```powershell
cd ui-simple
npm ci
npm run build
cd ..
python -m api.main
```

Visit `http://127.0.0.1:8000/simple/?mock=0`.

The original dashboard requires its own build in `ui/` if it has not already been built. If the API was running before the new dashboard was added, restart it after building to load the new mount.

For development, keep the API running and run `npm run dev` in `ui-simple/` from a second terminal. Open `http://127.0.0.1:5174/simple/`. The original UI’s development port is 5173. A frontend-only demonstration is available at `http://127.0.0.1:5174/simple/?mock=1` without the Python API.

## 4. Overview: understand the big picture

Start here when explaining the system. The diagram shows the three stages: **observe traffic → find unusual patterns → explain the alert**.

| Item | What it means |
| --- | --- |
| Packets analyzed | The number of packets read in the current or latest replay |
| Alerts in this replay | Suspicious observations emitted during that replay; these are not necessarily unique attacks |
| Alert processing · p99 | A measured processing-time threshold met by 99% of alerts; a dash means no alert measurements are available |
| Traffic through the engine | Recent updates of the engine-reported packet rate |
| Six category cards | Counts by threat family within the most recent loaded alerts |

The chart displays the API’s reported rate over successive updates. The replay API currently reports a run-average packet rate; the line is not an independent instantaneous network bandwidth measurement. Its values depend on replay pace, elapsed time, and the machine. After processing finishes, an elapsed-time-based rate can decrease even when the packet total stays fixed.

The p99 measurement covers alert processing after packet arrival inside the replay engine. It does not include all the time needed to observe a long pattern, such as repeated beacon check-ins, or browser rendering time. Use benchmark reports for formal throughput and latency claims.

The in-browser list keeps up to **400 alerts** and **240 metric updates**. Category counts can include earlier replays after loading or reconnecting, whereas the replay counter refers to the current/latest replay. Stored alert IDs are deduplicated, so replaying the same capture does not necessarily add new stored records.

## 5. Run a demo: see detection happen

1. Choose **Run a demo** in the navbar.
2. Select a scenario card. Each card describes the intended behavior, packet count, and original capture duration.
3. Choose a replay pace:
   - **Walkthrough** uses the capture’s timing at 1× speed. This gives you time to explain and pause. Very long individual gaps may be capped by the replay engine.
   - **Quick replay** processes the file as fast as the engine can, without waiting for capture timing.
4. Click **Start replay**. Watch progress and the number of alerts.
5. Use **Pause**, **Resume**, or **Stop replay** while the replay is active.
6. Choose **Review the alerts** to inspect the results.

Start with the **benign baseline** as a normal-traffic comparison, then try a **SYN flood** for a clear attack example. Longer scenarios may need time to collect enough observations. Attack captures exercise particular detectors; their labels describe the sample’s intended behavior, not a guarantee that every configuration will flag it correctly.

Starting a new replay resets the run’s metrics. Saved alert history remains in the engine’s store. Pause and stop do not remove saved alerts. To present a normal example after an attack replay, point to the current replay’s alert counter; old saved records can still appear in history.

## 6. Alerts: explain one result

Search by a name, description, or IP address, or filter by a threat category. Select an alert from the list. On a small screen, the details appear below the scrollable results.

| Field | How to explain it |
| --- | --- |
| Severity | A priority hint for investigation: low, medium, high, or critical |
| Detection score | A 0–100 confidence value attached to this observation |
| Observed connection | The source and destination endpoints involved; aggregate alerts may have no individual ports |
| Protocol and visibility | The network protocol and whether both directions were observed |
| Detector | The rule/model path that produced the alert |
| Capture time | The time associated with the recorded traffic, which can be historical |
| Why it was flagged | Recorded feature values with short explanations |
| Technical record | The full alert, all evidence, model lineage, and detection context |

The simple evidence view shows up to six signals. Expand **Technical record & all evidence** to see the full record. If a term has no glossary entry, use its recorded feature name and full context rather than inventing an explanation.

**A score of 90 is not “90% system accuracy.”** A calibrated model score depends on its calibration data. Rule scores are confidence or threshold-strength indicators and may not be probabilities. Treat either as evidence to review in context. A suspicious encrypted connection alone does not prove malware.

**Check records** verifies the stored alert chain and available signatures. Passing means record-integrity checks passed; it does not establish that every detection is correct. Sample mode only simulates this result.

## 7. The six threat categories

| Category | Plain-language meaning | Example signals |
| --- | --- | --- |
| Traffic floods / DDoS | Traffic tries to overwhelm a destination | SYN handshakes, packet-rate spikes, UDP reflection/amplification, unusual or potentially spoofed source patterns |
| Repeated check-ins / beaconing | A device contacts a destination with suspicious regularity | Connection intervals, periodicity, jitter, stable destinations |
| Unusual DNS activity | Domain queries look generated or may carry hidden data | Query lengths, entropy, letter-pair patterns, record-type anomalies, query/reply behavior |
| Suspicious encrypted traffic | Encrypted connections have unusual visible behavior | Available TLS metadata, packet-size sequences, timing, TLS/QUIC limitations |
| Network probing / scanning | A source tries many ports or hosts | Destination and port fanout within time windows |
| Possible data leakage / exfiltration | Outbound transfer patterns are unusual | Outgoing/incoming byte ratios, destination novelty, sustained transfers |

These are detection categories, not claims of perfect coverage. The engine inspects visible metadata without decrypting application content. Partial observation, encrypted handshakes, ordinary unusual traffic, and previously unseen environments can affect results. Source-pattern anomalies suggest spoofing; passive metadata does not authenticate the true origin of each packet.

## 8. How to talk about model quality

The live dashboard does not have ground-truth labels for every observation. It cannot derive precision, recall, or F1 from its alert totals.

| Metric | Question it answers | Formula |
| --- | --- | --- |
| Precision | Of the flagged examples, how many really were malicious? | TP / (TP + FP) |
| Recall / detection rate | Of the malicious examples, how many did we detect? | TP / (TP + FN) |
| F1 | How well do precision and recall balance? | 2 × precision × recall / (precision + recall) |
| False-positive rate | Of the benign examples, how many were flagged incorrectly? | FP / (FP + TN) |

TP = correctly flagged malicious examples; FP = benign examples flagged incorrectly; FN = missed malicious examples; TN = correctly unflagged benign examples. Undefined denominators need explicit handling in an evaluation report. For multiclass results, state whether numbers are per class, macro, weighted, or pooled.

Use held-out labeled evaluations for model-quality claims. In the repository, see `docs/ACCURACY_IMPROVEMENT_2026-09-08.md` and the linked evaluation/benchmark artifacts. That report describes a candidate that was not promoted to the serving model; do not present its metrics as the active dashboard model’s performance. Check an alert’s model lineage to identify the model associated with it.

Synthetic replays demonstrate specific behaviors. A quiet benign sample alone is insufficient to establish a low false-positive rate on real traffic.

## 9. A two-minute presentation script

**0:00 — The problem.** “Network activity can hide floods, scanning, command-and-control check-ins, and possible data leakage. We want alerts people can understand.”

**0:20 — The approach.** On Overview: “We read traffic, build flows, and examine visible patterns with rules and models. Each alert contains evidence.”

**0:40 — The demonstration.** On Run a demo: select a SYN flood and choose Quick replay. “This is a saved local capture. It lets us repeat the demonstration without sending attack traffic.”

**1:00 — The evidence.** On Alerts: select a result. “Here is the affected connection, the detector’s score, and the measured signals that triggered the alert.” Wait for the replay if the machine is still processing.

**1:30 — The measurement.** On Overview: “These are packet counts and processing measurements from this replay on this machine. Model precision and recall come from a separate labeled evaluation.”

**1:50 — The limits.** “The system helps an analyst investigate. It can miss attacks and raise false alarms, and it does not decrypt encrypted application content.”

## 10. Test the detector with local traffic

Keep the API running, stop any active capture/replay, and open another terminal in `SIH2026_prototype`:

```powershell
python -m tools.attack_lab live --scenario mixed
```

This separate lab tool owns every receiving socket on `127.0.0.1`. It starts a narrowly filtered loopback capture, sends 128 synthetic DNS TXT queries and probes 96 owned UDP ports at a maximum of 35 datagrams/second, then checks for both DNS and scanning alerts. It stops its capture after the check. Watch **Live monitor** and **Alerts**; no manual interface selection is needed for this test.

`--scenario dns-tunnel` or `--scenario scan` tests either pattern alone. `--scenario benign` sends ordinary local telemetry and expects zero alerts. `--api-port 8001` selects a different local API port. Existing captures/replays are left running; stop them before running the tool.

For all six classes, run `python -m tools.attack_lab offline`. It interleaves supplied synthetic captures through the live detector preset without sending packets. It needs no API, uses its own alert store, and does not populate the running dashboard. The dashboard's **Run a demo** page provides individual visible replays.

Every invocation prints PASS/FAIL and saves a separate folder under `data/attack-lab/` with `report.json`, `alerts.json`, and `alerts.jsonl`. The report lists expected, observed, missing and additional classes. Old saved alerts cannot pass a new live test because results are matched to its capture-session UUID. Missing detections and setup errors remain failures; thresholds and model files are not modified by the test.

This checks prototype behavior on small synthetic patterns; it does not establish precision/recall, real-malware coverage, or physical one-way isolation. The live sender cannot target other hosts. See `docs/ATTACK_LAB.md` in the repository for full instructions and troubleshooting.

## 11. Troubleshooting

| Symptom | What to do |
| --- | --- |
| Engine unavailable | Start `python -m api.main` from `SIH2026_prototype`, check that port 8000 is free, and choose Retry connection |
| API says the simple dashboard is not built | Run `npm ci` and `npm run build` inside `ui-simple/`, then restart the API |
| Original dashboard is not built | Build `ui/` separately; its files are independent of this copy |
| Values look surprisingly high or change randomly | Check for the Sample mode banner; switch to `?mock=0` for engine measurements |
| Start replay is disabled | Wait for a connection or pending action; stop the active replay before starting another |
| Replay is slow | Use Quick replay for a short demonstration; Walkthrough intentionally waits between recorded packets |
| Replay stops unexpectedly | Check `/api/health` and the Python terminal for a replay error; a stopped run is not necessarily a completed run |
| No alerts appear | Clear filters, confirm the selected sample, and allow time for observation windows; benign captures can legitimately produce no alerts |
| Old alerts appear | Saved history spans replays; check capture timestamps and distinguish history counts from the run’s alert counter |
| “Cross-origin mutation refused” | Open the app at the documented address with its API proxy; do not serve the built files from an unrelated origin |
| Cannot see all navigation items on a phone | Open Menu in the header; the original dashboard and guide are also linked in the footer |

For detailed operational diagnostics and training controls, use the preserved original dashboard. This simplified view is intended to make the system easier to understand and demonstrate.
