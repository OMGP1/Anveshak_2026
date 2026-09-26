# Novelty, Offline SOC Copilot, and multi-analyst operations

## Implemented scope

The engine now has an independent `NoveltyMonitor` beside the known-rule/LightGBM decision path. It observes bounded five-second flow windows even when no known detector fires or the known classifier is absent/benign. Cadence work uses a due heap and fixed tick budget; close, idle expiry, capacity eviction, and EOF finalize partial windows through the normal alert owner. Overload and unsupported windows are counted and never labelled benign.

`unknown-suspicious` is an alert-only taxonomy. `engine.types.THREAT_CLASSES` remains the fixed seven-class model order. Novelty context records the raw score, finite-sample benign-tail fraction, calibration size, score meaning, model/baseline hashes, observation quality, window, group, policy version, and review state. Its numeric confidence field is an uncalibrated review-priority score, not attack probability. Unknown alerts have no fabricated MITRE technique or CVE.

The companion lives outside the existing five-file serving manifest. Production loading requires its own exact two-artifact manifest, Ed25519 signature, and `SIH_NOVELTY_PUBLIC_KEY`. A missing or corrupt companion fails visibly and cannot produce scores. The production config leaves novelty disabled and shadow-only until approved data, evaluation, signature, and enablement are supplied.

The API also owns transactional collaboration state in a separate single-writer database. Case commands carry an expected version and idempotency key; claim conflicts have one winner. The case mutation, audit delta, and durable event cursor commit together. Original STIX alerts are immutable. Reconnect clients recover deltas through `GET /api/cases/events`; operator/admin sockets receive committed case deltas, while viewers do not receive hidden case state.

The Offline SOC Copilot supports five fixed intents: `explain_alert`, `summarise_window`, `compare_alerts`, `explain_term`, and `draft_incident_report`. One worker runs at a time and four jobs may queue. Retrieval is limited to twenty records through `AlertStore`; each snapshot records an insertion boundary, exact counts, ledger generation, hashes, and integrity state. The runtime receives no SQL, capture, filesystem, signing, training, browser, or production-network tool.

No language-model package is bundled. The implemented baseline renders approved typed claims deterministically and is therefore the always-available fallback and evaluation baseline. Report drafts keep human-attested values separate, show missing awareness/contact data, and remain `not_submitted`. Exporting does not record external submission.

## Enabling and training a novelty candidate

Use only explicitly approved benign captures. The command below creates a candidate directory without changing serving models:

```text
python -m training.novelty --benign-pcap approved-day-1.pcap --benign-pcap approved-day-2.pcap --output candidate/novelty --signing-key offline-release-key.pem
```

Training windows and later calibration windows are chronological and disjoint inside each capture. The metadata report records source hashes and row counts. Keep signing private keys off the application host. Copy only a reviewed candidate plus signature into the read-only model mount, pin the public key independently, then enable the `novelty` block in a reviewed engine config. Never point candidate training at live anomalies or treat absence of an alert as a benign label.

Evaluate a locked test table containing the exact `novelty-v1` columns plus `label`, `family`, and `split`:

```text
python -m bench.zero_day --model-dir candidate/novelty --dataset locked-zero-day-test.parquet --output result.json
```

The harness reports per-family recall, precision, row false alerts, PR-AUC/AUROC, and scoring rate. A production decision additionally requires grouped false alerts per sensor-day, natural-prevalence results, later benign changes, known-detector regression, end-to-end persistence/UI latency, overload/loss accounting, restart/disk tests, and the agreed 24-hour soak. Failure keeps novelty shadow-only.

## API summary

- `POST /api/cases/{alert_id}/commands`: claim, release, annotate, change status, or review with optimistic version and idempotency.
- `POST /api/alerts/{alert_id}/reviews`: append one authorised review event without changing the alert.
- `GET /api/cases/events?after=N`: durable reconnect cursor.
- `POST /api/copilot/query`, `GET /api/copilot/jobs/{id}`, `POST .../cancel`: bounded jobs and fallback.
- `GET /api/reports/{id}` and `/export`: internal draft/provenance; report review is a distinct lifecycle action.
- `GET /api/novelty/status`: coverage, baseline, drift, skip, queue, and shadow state.

The Go gateway strips spoofable trust headers and supplies the authenticated actor and role. Viewers may read alerts and request bounded copilot explanations. Operators/admins may mutate cases and reports. Only admins retain training permission. The API repeats these checks instead of trusting UI visibility.

## Management LAN

`compose.production.yml` remains loopback-bound by default. The reviewed overlay `compose.management-lan.yml` binds only `10.10.40.10:8443` and uses `anveshak.soc.internal:8443`. The offline DNS/DHCP reference, host firewall reference, and physical/network checklist are under `deploy/management-lan/`.

Source configuration cannot prove optical isolation, switch private VLANs, a transparent firewall, offline CA custody, trusted time, or the absence of BMC/maintenance bypasses. Those are deployment acceptance items. Local credentials currently provide per-user identity and viewer/operator/admin enforcement; Keycloak/OIDC remains a migration gate and must not be claimed as implemented.

## Verification

Run:

```text
python -m pytest -q
cd gateway && go test ./...
cd ../ui && npm run build
cd ../ui-simple && npm run build
```

Focused contract tests cover independent novelty scoring, unknown STIX compatibility, case conflicts/idempotency, append-only review events, evidence-linked copilot fallback, and report exports. Existing detector/model regression tests must continue to pass byte-for-byte artifact and deterministic replay checks.
