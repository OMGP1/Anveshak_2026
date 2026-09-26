# Additional attack coverage

This is a defensive review of the [MHDDoS registered methods](https://github.com/MatrixTM/MHDDoS/blob/main/start.py), inspected on 2026-09-07. No attack tool was installed or run. No public target or third-party network was tested.

The reviewed `Methods` sets register 47 distinct names, while the [project README](https://github.com/MatrixTM/MHDDoS) advertises 57. The application records the names actually present in the sets. The source URL follows `main`; repeat the inventory review when upstream changes.

## Coverage categories

| Methods | Current defensive coverage |
|---|---|
| SYN | Existing SYN-flood family has synthetic regression coverage, not tool-generated validation |
| MEM, NTP, DNS, ARD, CLDAP, CHAR, RDP | Partial aggregate UDP-reflection evidence; one synthetic reflection shape now tested at all seven service-port variants, not seven independently validated protocol attacks |
| SLOW, CONNECTION | Partial connection-exhaustion heuristics; established slow application sessions remain a blind spot |
| CPS | Optional TCP SYN-attempt rate anomaly, including churn below the packet-rate floor; retransmissions and completed connections are not distinguished |
| TCP, UDP, VSE, MINECRAFT, MCBOT, FIVEM, FIVEM-TOKEN, TS3, MCPE, ICMP, OVH-UDP | Optional transport-rate alarms; no exact protocol or tool attribution |
| CFB, BYPASS, GET, POST, OVH, STRESS, DYN, HEAD, NULL, COOKIE, PPS, EVEN, GSB, DGB, AVB, CFBUAM, APACHE, XMLRPC, BOT, BOMB, DOWNLOADER, KILLER, TOR, RHEX, STOMP | Application behavior is not distinguishable from the current passive metadata input, especially through encryption |

These coverage assessments are our inference from the engine's observable fields, not claims made or validated by MHDDoS. A shared transport signature does not prove a particular method. A normal flash crowd can resemble a flood; an encrypted application attack can resemble normal traffic.

## Implemented addition

`engine/detect/protocol_flood.py` implements a bounded, optional monitor grouped by destination and transport protocol. It learns occupied one-second windows, applies rate floors and baseline-deviation thresholds, clips upward baseline adaptation, and applies a shared per-destination/protocol cooldown. TCP, UDP, and ICMP produce explicit `*-rate-anomaly` subtypes under the existing DDoS class. A separate SYN-without-ACK counter can produce `tcp-syn-rate-anomaly` below the volume floor. It counts attempts, including retransmissions, not authenticated users, HTTP requests, or completed connections.

Enable it using `SIH_ENGINE_CONFIG=config/engine-extended.json`; `engine-production.json` also enables it. With no profile it is disabled. Site calibration and independent attack captures remain absent.

The two supplied profiles use these starting thresholds, not measured universal operating points:

| Signal | Baseline branch | Absolute branch, including cold start |
|---|---|---|
| Packet rate | At least 2,500 packets/s and 6 sigma after 10 occupied windows | At least 25,000 packets/s |
| SYN-attempt rate | At least 100 attempts/s and 6 sigma after 10 occupied windows | At least 1,000 attempts/s |

Absolute limits remain active after warmup. Set an absolute setting to zero to disable that branch; set `minimum_syn_pps` and `absolute_syn_pps` both to zero to disable the SYN branch. Invalid/non-finite thresholds fail construction. The profiles cap state at 4,096 destination/protocol buckets and use a 60-second cooldown. A separately bounded pending-window index lets idle ticks avoid scanning retained baselines; relative LRU alert order is preserved. Eviction loses that bucket's baseline and cooldown, so it can miss baseline-only attacks or permit new cold-start alarms under destination churn. Counters expose evictions, pending windows, and skipped late packets.

A later packet or engine tick closes each occupied second once. Quiet gaps no longer dilute its rate. Normal replay EOF ticks through the final second before storing results; cancellation does not simulate EOF. The monitor never invents zero-traffic training windows. It rejects observations older than the tick watermark or the destination's open second; this is an explicit zero-reordering-buffer policy, not lossless out-of-order handling. A live adapter must advance event-time watermarks safely, including idle periods. The dashboard currently supports replay, not a continuously running live-capture daemon.

Aggregate flow exports are skipped because they lack per-packet timing. Short edge windows are conservatively counted over one second; sub-second peak rates are not inferred. Below-threshold attacks, indistinguishable benign flash crowds, first-seen attacks below absolute limits, and attacks split across fixed-second boundaries remain limitations.

The dashboard and `/api/detection-coverage` show all 47 names, family-detector availability under the loaded profile/input, and **0 exact tool methods validated**. Choosing flow exports disables the extended packet-timing claims in the UI. An enabled family detector is not a per-method guarantee. The seven reflection tests substitute source ports 11211, 123, 53, 3283, 389, 19, and 3389 into the same decoded synthetic metadata; they neither construct real service replies nor validate amplification factors for each protocol.

The existing serving booster, calibrator, anomaly forest, and metadata are preserved. New rule subtypes are explicitly **not calibrated probabilities** and cannot be relabelled calibrated merely because the existing classifier agrees on the broad DDoS class. Tick alerts from different destinations are scored separately, preserving evidence attribution. See [`test_extended_detection.py`](../tests/test_extended_detection.py) for executable offline proof.

## Required additional telemetry

HTTP methods, paths, response codes, application errors, and challenge outcomes require authorized application or reverse-proxy logs. Decrypted content is outside the stated metadata-only engine boundary. Any future log-ingestion feature must preserve that distinction and have its own data contract, labels, privacy review, and tests.

Per-method validation should use retained authorized captures or constructed offline metadata fixtures with known labels. Do not use this repository to direct live flood traffic toward external systems. No offensive execution instructions are included.
