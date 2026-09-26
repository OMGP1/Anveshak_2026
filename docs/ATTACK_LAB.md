# Attack lab: test the detector and inspect the result

`tools/attack_lab.py` is a separate operator tool for repeatable detection checks. It sends small synthetic DNS-tunnelling and UDP-scanning patterns to sockets it owns on this computer, then verifies alerts from the real passive capture pipeline. An offline mode interleaves all six attack families using the supplied captures.

## Quick live test

From `SIH2026_prototype`, keep the API running in one terminal:

```powershell
python app.py
```

Open **http://127.0.0.1:8000/simple/?mock=0#/live**. Stop any existing capture or replay. In a second terminal, also in `SIH2026_prototype`, run:

```powershell
python -m tools.attack_lab live --scenario mixed
```

The tool selects the local loopback adapter, reserves its own receiving sockets, starts a narrowly filtered capture, sends 224 datagrams at no more than 35 per second, waits for detections, and stops the capture it started. Watch **Live monitor** for packet counts and **Alerts** for evidence. Expect roughly 10–25 seconds including startup and capture delivery.

**Do not manually start Wi-Fi capture for this test.** The generated traffic is between local loopback sockets, so the tool selects loopback itself. A pre-existing monitoring session is left running and the tool exits with an explanation. Restart your normal mirror-interface monitoring after the lab finishes.

Wireshark/dumpcap and Npcap are required on Windows, as for ordinary live monitoring. The tool needs the direct local development API. It does not bypass a production gateway or role checks. For a development API on another local port, use `--api-port 8001` with the port you configured.

### macOS setup: dumpcap and capture permission are separate

Install the command-line capture tools with Homebrew; the graphical application is not required:

```sh
brew install wireshark
brew install --cask wireshark-chmodbpf
```

The second command requires administrator approval. It installs Wireshark's standard BPF access helper and adds the installing user to its capture-access group. **Reboot after installing it**, as required by the [Homebrew package instructions](https://formulae.brew.sh/cask/wireshark-chmodbpf). Wireshark also documents the [macOS ChmodBPF requirement](https://www.wireshark.org/docs/wsug_html_chunked/ChBuildInstallOSXInstall.html). This permission enables packet capture for that account; use it only on an authorized workstation. Do not run the API as root, make `/dev/bpf*` world-readable, or disable macOS security protections.

From a new terminal, verify the executable and loopback capture capability:

```sh
/opt/homebrew/bin/dumpcap --version
/opt/homebrew/bin/dumpcap -D
/opt/homebrew/bin/dumpcap -i lo0 -L
```

The `-L` command checks link-layer capabilities; it does not start packet collection. An interface appearing in `-D` does **not** prove permission to capture it. On Intel Homebrew use `/usr/local/bin/dumpcap`; a Wireshark application installation normally uses `/Applications/Wireshark.app/Contents/MacOS/dumpcap`.

Restart the API from the repository copy you are testing, then run the lab in a second terminal:

```sh
# API terminal, from SIH2026_prototype:
python3 -m api.main

# Second terminal, from the same copy:
python3 -m tools.attack_lab live --scenario mixed
```

Discovery checks PATH, the Wireshark application, and both common Homebrew locations. If using a custom executable, set `SIH_DUMPCAP` to its executable path **before starting the API**. Setting it only in the attack-lab terminal cannot change the already-running API's environment. An invalid explicit override is reported rather than silently replaced with another binary.

Mac verification on 8 September: dumpcap 4.6.8 was installed and listed `lo0`, but its capability check reported `/dev/bpf0: Permission denied`. Therefore a successful mixed live run on this Mac is **not claimed** until administrator setup and a new run complete. The Npcap results below belong to the earlier Windows validation, not this Mac.

## Available tests

| Command | Traffic and expected result |
| --- | --- |
| `python -m tools.attack_lab live --scenario mixed` | 128 DNS queries interleaved with probes to 96 owned UDP ports; both DNS and scanning classes expected |
| `python -m tools.attack_lab live --scenario dns-tunnel` | 128 distinct long synthetic `.test` names using TXT records; DNS-tunnelling class expected |
| `python -m tools.attack_lab live --scenario scan` | One small UDP datagram to each of 96 owned ports; scanning class expected |
| `python -m tools.attack_lab live --scenario benign` | 64 ordinary small datagrams to one owned receiver; zero alerts expected |
| `python -m tools.attack_lab offline` | Interleaves all 11 supplied PCAPs through the live detector preset, inference, and persistent alert output; all six classes expected |

The offline command needs neither a running API nor capture privileges. It preserves original capture timestamps, so beaconing and sustained-exfiltration windows can be tested without waiting through their full wall-clock histories. It sends no network packets and does not add records to the running dashboard. Use **Run a demo** in the dashboard for a visible replay of an individual scenario.

The offline workload includes SYN/spoofed-source floods, UDP reflection, beaconing, DNS DGA/tunnelling, encrypted-session indicators, scanning, and exfiltration. These are synthetic fixtures; a class-level pass does not prove every subtype fired or establish real-malware coverage.

## Read the result

Each invocation creates a new folder under **`data/attack-lab/<UTC timestamp>-<run ID>/`**:

| File | Contents |
| --- | --- |
| `report.json` | PASS/FAIL, run/session identity, expected and observed classes, missing/additional classes, packet counts, errors and limitations |
| `alerts.json` | A plain JSON array of alerts from this test only |
| `alerts.jsonl` | The same alerts, one plain JSON record per line |
| `alerts.duckdb`, `alerts.ledger.jsonl`, related signing files | Offline mode's independent database and signed ledger |

Live alerts also remain in the API's normal persistent store and dashboard history. The tool filters records by the newly created capture session UUID; old alerts cannot make a failed new test pass. It never clears the existing alert history. Its plain JSONL export differs from the normal API ledger, whose lines contain an alert under `record` alongside chain metadata.

**PASS** for a positive live test requires every expected class, complete processing of the sent observations, no reported application queue/stale/decoder losses, schema-valid persisted alerts, and successful cleanup of the owned session. Additional classes are listed separately. **PASS** for the benign control requires zero alerts. A missed expected class, a capture problem, or a false alert on the benign control produces **FAIL**. Driver-level drops remain unknown even on a passing run.

Exit codes are `0` for pass, `1` for an unsuccessful verification, `2` for a setup/runtime error, and `130` for Ctrl+C. Error and interrupted runs still save their report and any collected alerts. The console prints the report location. Capture cleanup uses a session-specific stop request, so a stale cleanup cannot stop a newer monitoring session.

## Scope and one-way deployment

The traffic generator lives outside the passive engine and API request handlers. There is no dashboard button that transmits attack packets from the monitoring service. It only targets hard-coded `127.0.0.1`, owns all destination sockets, makes no external DNS lookups, and has no arbitrary-host, spoofing, high-rate flood, or unlimited-duration option. DNS receivers use an available local port among 5353, 53 and 5355; DNS alerts retain the observed destination port.

Loopback validation exercises generation, Npcap/dumpcap capture, metadata extraction, detection, persistence and dashboard delivery on one workstation. It does not test a physical data diode or a remote mirrored feed. Production-enclave isolation remains a deployment property.

These are functional detection checks, not precision, recall, F1, throughput certification, or a promise to detect every attack. Detector thresholds and serving model files are unchanged by the tool. Offline mode uses `config/engine-live.json` plus the operator's `SIH_ENGINE_CONFIG` overrides, if configured. Input capture hashes and configuration are saved with its report.

## Earlier Windows/Npcap validation: 8 September 2026

All four live commands were exercised using actual Npcap/dumpcap loopback capture:

| Test | Processed datagrams | Alerts observed | Result |
| --- | --- | --- | --- |
| Mixed | 224 | 2 DNS, 1 scanning | PASS |
| DNS tunnel | 128 | 2 DNS | PASS |
| UDP scan | 96 | 1 scanning | PASS |
| Benign | 64 | 0 | PASS |

Every live run reported zero application queue/stale drops and stopped its capture successfully. The offline command processed 105,142 packets and saved 66 alerts across all six classes, with a valid signed ledger. The API/live/tool regression selection passed 52 tests, including rejection of stale session stops, old-alert contamination, missing classes and benign false alerts. The simplified dashboard build and browser checks at widths 320, 390, 768 and 1440 passed.

Individual run reports and alerts are retained under `data/attack-lab/`; the consolidated record is `bench/attack-lab-validation-20260908.json`. These observations apply to this implementation and the supplied synthetic inputs, not arbitrary attacks or deployment environments.

## Troubleshooting

| Result | Next step |
| --- | --- |
| API connection refused | Start `python app.py`; use `--api-port` if you changed its port |
| A capture or replay is already running | Stop it in the dashboard before starting this separate lab session |
| No loopback capture interface | Check the Npcap/dumpcap installation; use offline mode while resolving capture setup |
| dumpcap not found on macOS | Install `brew install wireshark`; restart the API after updating its environment. See macOS setup above. |
| `/dev/bpf0: Permission denied` on macOS | Administrator installs `wireshark-chmodbpf`, then reboot and restart the API from a new terminal. Interface listing alone does not prove capture permission. |
| Cannot reserve a DNS receiver | Another service owns the supported DNS ports or permissions prevent binding; use offline mode or an isolated lab installation |
| Missing DNS or scan class | Inspect `missing_classes`, capture counts/drops, and operator detector configuration; do not lower thresholds merely to make a test pass |
| Old API ignores session-specific cleanup | Restart the API after updating Python code before using this tool |
| Alerts are visible but report fails | Read `capture_check_passed`, `missing_classes`, `error` and `cleanup_error`; one alert alone does not establish a complete pass |
| Offline test takes longer | Inference and durable JSON writing run on this workstation; follow its packet-count progress |
