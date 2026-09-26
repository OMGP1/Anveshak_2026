# Hardened single-node deployment

This is an implemented deployment profile, not field certification. The [readiness record](PRODUCTION_READINESS.md) lists remaining gates. Never attach the enclave to the monitored network. Operator HTTPS is a separate management path, not a return channel to captured endpoints.

## Components and trust boundaries

```text
Read-only classic PCAP → Rust validator/framer → bounded OS pipe → Python metadata decoder
Read-only flow CSV ────────────────────────────────────────────→ Python flow adapter
                                                                      ↓
                                                        stateful detectors and models
                                                                      ↓
                                                      fsynced ledger → DuckDB index
                                                                      ↓
Browser ← HTTPS / WSS → Go authenticated gateway → private HTTP / WS API
```

Rust emits one validated frame at a time, reuses a bounded allocation (maximum 16 MiB), and stops on malformed lengths, truncated records, invalid timestamps, or backwards timestamps. It preserves raw packet bytes and exact integer timestamps through a private subprocess pipe. Python retains the existing DNS/TLS/QUIC metadata decoder and detector state. No payload is returned by the dashboard. No network transmission or payload decryption is added to the engine.

The native path supports classic PCAP only. Python mode retains PCAPNG support and its prior backwards-timestamp clamping. Select `Rust PCAP ingest` explicitly or use `config/engine-production.json` to make Rust the default PCAP backend. Missing native binaries fail explicitly; no silent native fallback occurs. Framing in Rust does not imply that Python inference became native or faster; compare the recorded benchmarks.

Go owns operator-network HTTP, TLS, sessions, roles, proxying, and connection admission. It uses the standard-library [reverse proxy](https://pkg.go.dev/net/http/httputil). It never contacts the source or destination of observed traffic.

## Build and provision locally

From `SIH2026_prototype/`, after installing Python requirements and building `ui/dist`:

```sh
cargo build --release --offline --manifest-path native/pcap-audit/Cargo.toml
cd gateway
go test -race ./...
go vet ./...
go build -trimpath -o sih-gateway .
cd ..
python3 -m tools.prepare_deployment .runtime
```

Provisioning creates a new private directory and refuses an existing destination. It copies—not overwrites—the five serving artifacts, signs a SHA-256 manifest with Ed25519, generates a backend secret and three random role tokens, and creates a 30-day self-signed lab TLS certificate. Integrity signing is not model-quality approval. Keep the model signing private key offline; neither process needs it. Replace lab certificates with an organization-issued certificate before real deployment.

On this workspace the locally downloaded Go executable is `.tools/go/bin/go`; Rust is available under the installed rustup toolchain. These tool directories are ignored and are not runtime dependencies. Reproducible releases should use reviewed toolchain versions and image digests.

Start the API in one terminal:

```sh
export SIH_PRODUCTION=1
export SIH_GATEWAY_SECRET_FILE="$PWD/.runtime/secrets/backend-token"
export SIH_MODEL_PUBLIC_KEY="$PWD/.runtime/secrets/model-trust.pub"
export SIH_MODEL_DIR="$PWD/.runtime/models"
export SIH_STATE_DIR="$PWD/.runtime/state"
export SIH_ENGINE_CONFIG="$PWD/config/engine-production.json"
export OMP_NUM_THREADS=2 OPENBLAS_NUM_THREADS=2 MKL_NUM_THREADS=2
python3 -m api.main
```

Start Go in a second terminal from the same project directory:

```sh
./gateway/sih-gateway -public-host localhost:8443 \
  -users .runtime/secrets/gateway-users.json \
  -backend-secret .runtime/secrets/backend-token \
  -audit .runtime/state/gateway-audit.jsonl \
  -cert .runtime/secrets/tls.crt -key .runtime/secrets/tls.key
```

Open `https://localhost:8443/?mock=0`, trust the local lab certificate only for this test, and use the assigned token from the private `operator-credentials.json` file. Never paste tokens into URLs or commit them. The provisioned shared role identities are for a local lab; issue separate token-hash records and unique IDs per person before team use. Restart Go to apply revocations and clear existing sessions.

| Role | Permissions |
|---|---|
| viewer | Authenticated dashboard, read API, WebSocket stream |
| operator | Viewer access plus replay start/pause/resume/stop |
| admin | Operator access plus isolated candidate training |

Tokens are random 256-bit secrets; Go stores only their SHA-256 digests in its user file. Browser login exchanges a token for a 30-minute, HttpOnly, Secure, SameSite=Strict cookie. Sessions are bounded and in memory; restart logs everyone out. Programmatic clients may use a bearer role token over TLS. `POST /logout` revokes the current cookie. Do not reuse the backend secret as a human credential.

The backend requires the shared secret and an allowed role for HTTP and WebSocket access. Go strips client-supplied identity/proxy headers and injects trusted values. The backend secret belongs only to these two services. Leave the API bound to loopback outside containers; do not publish its port.

## Resource and failure policy

| Resource | Implemented bound |
|---|---|
| Go accepted connections | 256 |
| Go concurrent requests/upgrades | 128 |
| Browser sessions | 128, expires after 30 minutes |
| Login attempts | 30 per minute globally (protect management reachability separately) |
| Request/header body | 1 MiB general body; 4 KiB login body; 16 KiB headers |
| HTTP deadlines | 5 s read-header; 15 s read; 30 s write/idle; 15 s upstream response headers |
| WebSocket clients | 32 in Python; 2 s bounded send per broadcast; explicit resync after queue loss |
| Notification queue | 1,024 entries; durable alert storage precedes notification |
| Replay | One serialized controller, one inference worker; new starts stop the old worker |
| Training | One worker, 2 numerical threads, 600 s timeout, 20 retained runs, input/disk admission checks |
| Stateful flows | 200,000 slots in the supplied profile |

Go action logs contain timestamp, assigned user ID, method/path, and a hash chain. Login and mutation requests fail closed if the audit append or sync fails. Credentials, query strings, bodies, and packets are excluded. An action record means a request was accepted for forwarding, not that its backend operation succeeded. Off-host archival/checkpoints are needed to detect a privileged attacker rewriting an entire local log or deleting its tail.

Signed model manifests are verified before serving loads, including before pickle deserialization. Mount artifacts read-only and pin the trust public key outside the model directory. A malicious or compromised authorized signer remains trusted; signing does not make arbitrary pickle safe. Do not point serving paths at candidate directories. Automatic promotion is intentionally absent.

## Container profile

```sh
# Match these to the non-root owner of the provisioned files on the deployment host.
export SIH_UID="$(id -u)" SIH_GID="$(id -g)"
mkdir -p data/lab-runs
docker compose -f compose.production.yml config --quiet
docker compose -f compose.production.yml up --build -d
```

Use a dedicated non-root service identity on Linux; do not set UID 0. Compose defaults to UID/GID 10001, so provision ownership accordingly. The API has no published port; its network is `internal`. The gateway has a separate operator network and publishes only localhost:8443 by default. [Compose networking documentation](https://docs.docker.com/compose/how-tos/networking/) describes the service-network model. Internal networking is not a hardware diode; deployment routing/firewall policy must still exclude monitored addresses. PCAP transfer should use a separately managed, read-only mount.

Containers have read-only root filesystems, dropped capabilities, no-new-privileges, PID and log limits, and tmpfs. API plus training share 2 CPUs/4 GiB; Go has 1 CPU/256 MiB. These are starting resource budgets, not demonstrated load capacity. Training is disabled automatically unless explicitly enabled. Keep training off during latency-critical operation or move the existing isolated candidate workflow to a separately budgeted offline host.

Image tags are not immutable release pins. Before deployment, lock reviewed base-image digests, build in a trusted registry, inventory dependencies, scan the resulting images, and validate under the target runtime. Compose syntax was checked locally; the Docker daemon was unavailable, so image builds and container isolation were not executed here.

## Backup, restart, and rollback

The ledger is authoritative. Each alert append flushes and fsyncs before index insertion. On restart, the ledger and signatures are checked before appending; missing database rows are rebuilt transactionally with stable insertion cursors. Conflicting index records or corrupt/truncated ledger tails stop startup. Evidence is never silently truncated or rewritten. A persistence error stops further appends until restart/reconciliation.

Stop both processes cleanly, then snapshot to a new private destination:

```sh
python3 -m tools.backup_state snapshot .runtime/state .runtime/backups/snapshot-001
python3 -m tools.backup_state restore .runtime/backups/snapshot-001 .runtime/restored-state-001
```

The snapshot refuses a live DuckDB writer/WAL, hashes copied files, and verifies the copied ledger. Restore checks hashes/signatures and rebuilds a new DuckDB index from the ledger. Point `SIH_STATE_DIR` or the Compose state mount at the restored directory; keep the original untouched. Snapshot manifests themselves require protected/off-host storage. Model credentials, TLS credentials, and reviewed candidate archives need separate encrypted backup and access policy.

Keep a previous signed model directory and its separately pinned trust key for rollback. Stop inference, verify that bundle, switch both paths, restart, and rerun the smoke checks. Never overwrite a live model bundle file by file. Do not run multiple Uvicorn workers or multiple writers against one state directory. Horizontal scaling requires explicit per-source/per-destination aggregation semantics; naïve five-tuple sharding loses threat evidence.

Set disk/retention alerts and archive reviewed training runs and stopped, verified state snapshots before capacity is exhausted. Retention deletion, automated failover, multi-node aggregation, long-duration soak, and representative field qualification are not implemented acceptance proofs.

## Full-stack check

```sh
SIH_STACK_TEST=1 SIH_BROWSER_TEST=1 python3 -m pytest -q tests/test_stack_integration.py -s
```

This starts only ephemeral local services, uses fresh secrets and an isolated Chrome profile, verifies TLS/roles/WebSocket/Rust replay, renders the inventory, and clicks candidate training. Chrome defaults to the macOS application path; override `SIH_CHROME` elsewhere. The browser alone bypasses validation of the temporary self-signed certificate; the HTTPS/WSS clients independently validate that certificate and require TLS 1.3. The test shuts down its processes and reports its evidence directory. It is not an internet exposure test.
