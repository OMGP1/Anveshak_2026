import { useEffect, useState } from "react";
import { USE_MOCK } from "./api";
import type { Engine } from "./useEngine";
import type { LiveEngine } from "./useLive";

const CLASSES = [
  ["volumetric-ddos", "Traffic floods"],
  ["c2-beaconing", "C2 beaconing"],
  ["dga-dns-tunnelling", "DNS anomalies"],
  ["encrypted-malware", "Encrypted traffic"],
  ["recon-scanning", "Network scanning"],
  ["data-exfiltration", "Possible data leakage"],
];
const format = (n: number | undefined) =>
  n === undefined ? "—" : n.toLocaleString();

export function LivePage({
  engine,
  live,
}: {
  engine: Engine;
  live: LiveEngine;
}) {
  const [selected, setSelected] = useState("");
  const [filter, setFilter] = useState("ip");
  const { refreshInterfaces } = live;
  useEffect(() => {
    void refreshInterfaces();
  }, [refreshInterfaces]);
  const status = live.status;
  const capture = status?.capture;
  const currentInterface = selected || capture?.interface || "";
  const drops = (capture?.queue_dropped ?? 0) + (capture?.stale_dropped ?? 0);
  const replayRunning =
    engine.status.running && status?.active_source !== "live";
  return (
    <>
      <header className="page-heading">
        <span className="eyebrow">Passive live monitoring</span>
        <h1>Watch traffic as it arrives.</h1>
        <p>
          Read traffic from a local capture interface, analyze all six threat
          categories together, and save each alert automatically. Choose the
          interface connected to your mirror or data diode.
        </p>
      </header>
      {USE_MOCK ? (
        <div className="notice">
          <p>
            Live capture needs the real engine.{" "}
            <a href="?mock=0#/live">Connect to the engine</a> to select a local
            interface.
          </p>
        </div>
      ) : (
        <>
          {(live.error || status?.error) && (
            <div className="notice error-notice" role="alert">
              <p>{live.error || status?.error}</p>
            </div>
          )}
          {replayRunning && (
            <div className="notice">
              <p>
                A replay is running. Stop it on <a href="#/demo">Run a demo</a>{" "}
                before starting live capture.
              </p>
            </div>
          )}
          <div className="live-layout">
            <section className="panel live-controls">
              <div className="panel-top">
                <h2>Capture controls</h2>
                <span
                  className={`tag ${status?.running ? "teal" : "neutral"}`}
                  role="status"
                >
                  {status?.running ? "Monitoring live" : "Capture stopped"}
                </span>
              </div>
              <label className="field-label" htmlFor="capture-interface">
                Local capture interface
              </label>
              <select
                id="capture-interface"
                value={currentInterface}
                disabled={!!status?.running || live.busy}
                onChange={(e) => setSelected(e.target.value)}
              >
                <option value="">Choose an interface</option>
                {live.devices?.interfaces.map((device) => (
                  <option key={device.id} value={device.id}>
                    {device.name}
                  </option>
                ))}
              </select>
              <p className="field-help">
                An ordinary Wi-Fi adapter sees traffic available to that
                machine. A network-wide view needs a correctly configured mirror
                or data diode.
              </p>
              <button
                className="text-button"
                disabled={live.listing || !!status?.running}
                onClick={() => void refreshInterfaces()}
              >
                {live.listing ? "Finding interfaces…" : "Refresh interfaces"}
              </button>
              {live.devices?.error && (
                <p className="field-help" role="alert">
                  {live.devices.error}
                </p>
              )}
              <label className="field-label" htmlFor="capture-filter">
                Capture filter
              </label>
              <input
                id="capture-filter"
                value={filter}
                maxLength={512}
                disabled={!!status?.running || live.busy}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="ip"
              />
              <p className="field-help">
                Use <code>ip</code> for IPv4, or narrow it, for example{" "}
                <code>host 192.0.2.10</code>. IPv6 is excluded from this live
                path until full address attribution is supported.
              </p>
              {status?.running ? (
                <button
                  className="button secondary full-width"
                  disabled={live.busy}
                  onClick={() => void live.stop()}
                >
                  {live.busy ? "Stopping…" : "Stop monitoring"}
                </button>
              ) : (
                <button
                  className="button primary full-width"
                  disabled={
                    live.busy ||
                    !engine.connected ||
                    !live.devices?.available ||
                    !currentInterface ||
                    replayRunning
                  }
                  onClick={() => void live.start(currentInterface, filter)}
                >
                  {live.busy ? "Starting…" : "Start monitoring"}
                </button>
              )}
              <p className="field-help">
                Capture runs until you stop it or the API shuts down. Live
                capture cannot be paused without missing traffic.
              </p>
            </section>
            <section className="panel live-summary">
              <span className="eyebrow">What happens to the traffic</span>
              <h2>Observe. Analyze. Save.</h2>
              <ol className="live-steps">
                <li>
                  <strong>Read the mirrored packets</strong>
                  <p>
                    The capture helper delivers a local, read-only stream. The
                    detector never probes a source, completes a handshake, or
                    sends a block command.
                  </p>
                </li>
                <li>
                  <strong>Look for concurrent threats</strong>
                  <p>
                    All detector families examine the same stream. Different
                    hosts and threat classes can raise alerts during the same
                    session.
                  </p>
                </li>
                <li>
                  <strong>Preserve the findings</strong>
                  <p>
                    Alerts are saved to the JSON-lines ledger before they appear
                    here. Download stored records as JSON or JSONL on the Alerts
                    page.
                  </p>
                </li>
              </ol>
              <a className="button secondary" href="#/alerts">
                Review & export alerts →
              </a>
            </section>
          </div>
          <div className="section-heading">
            <h2>This live session</h2>
            <span className="muted">
              {status?.started_at
                ? `Started ${new Date(status.started_at * 1000).toLocaleTimeString()}`
                : "Waiting for a capture"}
            </span>
          </div>
          <div className="stats-grid">
            <section className="stat-card">
              <span className="stat-label">Packets read from capture</span>
              <strong className="stat-value">
                {format(capture?.packets_received)}
              </strong>
              <p>Packets delivered by the capture helper.</p>
            </section>
            <section className="stat-card">
              <span className="stat-label">Packets processed / second</span>
              <strong className="stat-value">
                {status?.active_source === "live"
                  ? format(engine.metrics?.packets_per_s)
                  : "—"}
              </strong>
              <p>Recent processing rate over approximately five seconds.</p>
            </section>
            <section className="stat-card">
              <span className="stat-label">Alerts raised</span>
              <strong className="stat-value">{format(status?.alerts)}</strong>
              <p>Each alert is persisted before its live notification.</p>
            </section>
          </div>
          <div className="live-class-grid">
            {CLASSES.map(([id, label]) => (
              <div className="panel" key={id}>
                <span>{label}</span>
                <strong>{format(status?.class_counts[id] ?? 0)}</strong>
              </div>
            ))}
          </div>
          <section className="panel live-latency">
            <h2>Time to save an alert · p99</h2>
            <strong className="stat-value">
              {engine.metrics?.live_latency_ms?.count
                ? `${format(engine.metrics.live_latency_ms.p99)} ms`
                : "—"}
            </strong>
            <p className="field-help">
              Includes metadata queueing, detection, and durable alert output.
              Excludes capture-driver buffering and the observation window
              needed to recognize a pattern, such as several minutes of beacon
              check-ins.
            </p>
          </section>
          <section className="panel capture-quality">
            <div className="panel-top">
              <h2>Capture quality & capacity</h2>
              <span className={`tag ${drops ? "critical" : "neutral"}`}>
                {drops ? "Traffic was dropped" : "Reported queue drops: 0"}
              </span>
            </div>
            <dl className="glossary">
              <div>
                <dt>Metadata queue</dt>
                <dd>
                  {format(capture?.queue_depth)} /{" "}
                  {format(capture?.queue_capacity)} packets waiting
                </dd>
              </div>
              <div>
                <dt>Dropped or stale packets</dt>
                <dd>
                  {format(capture ? drops : undefined)} · overload is visible,
                  so missing observations are not mistaken for complete
                  coverage.
                </dd>
              </div>
              <div>
                <dt>Capture truncation</dt>
                <dd>
                  {format(capture?.truncated_packets)} packets exceeded the
                  snapshot length. Some DNS or TLS metadata may be unavailable.
                </dd>
              </div>
              <div>
                <dt>Driver-level drops</dt>
                <dd>
                  Not available from this capture pipe. Zero application drops
                  does not establish lossless capture.
                </dd>
              </div>
            </dl>
            <p className="section-note">
              The software uses bounded queues and detector state. It cannot
              create a physical one-way network boundary; deploy it behind the
              mirror or data diode described in the problem statement.
              Application content is not decrypted or stored.
            </p>
          </section>
          <section className="panel live-lab">
            <h2>Test the detector on this computer</h2>
            <p>
              Keep the API running and stop any active capture or replay. In a
              second terminal, from SIH2026_prototype, run:
            </p>
            <code>python -m tools.attack_lab live --scenario mixed</code>
            <p>
              The lab tool starts its own loopback capture, sends small DNS and
              scanning patterns to sockets it owns, and checks for both alerts.
              Watch <a href="#/alerts">Alerts</a> for the results. Each test
              saves a JSON report and stops its capture afterward.
            </p>
            <p className="field-help">
              Use --scenario benign to check ordinary traffic, or run python -m
              tools.attack_lab offline to test all six classes from saved
              captures. Offline tests save a separate report.
            </p>
          </section>
        </>
      )}
    </>
  );
}
