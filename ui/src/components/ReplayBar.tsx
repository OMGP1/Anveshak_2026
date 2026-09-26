import type { ReplayMode, ReplayStatus, Scenario, SourceKind } from "../api";
import { formatClock, formatCount, formatDuration, percent, type Theme } from "../threats";
import Panel from "./Panel";
import ThreatBadge from "./ThreatBadge";

const SPEEDS = [0.5, 1, 2, 5, 10, 25];

export type ReplayControls = {
  source: SourceKind;
  onSource: (source: SourceKind) => void;
  choice: string;
  speed: number;
  mode: ReplayMode;
  onChoice: (scenario: string) => void;
  onSpeed: (speed: number) => void;
  onMode: (mode: ReplayMode) => void;
};

type Props = {
  scenarios: Scenario[];
  status: ReplayStatus;
  controls: ReplayControls;
  alerts: number;
  busy: boolean;
  theme: Theme;
  onStart: (scenario: string, speed: number, mode: ReplayMode, source?: SourceKind) => void;
  onPause: () => void;
  onResume: () => void;
  onStop: () => void;
};

export default function ReplayBar(props: Props) {
  const { scenarios, status, controls, alerts, busy, theme, onStart, onPause, onResume, onStop } = props;
  const { choice, speed, mode } = controls;

  const running = scenarios.find((s) => s.id === status.scenario) ?? null;
  const selected = scenarios.find((s) => s.id === choice) ?? null;
  const shown = status.running || status.progress > 0 ? (running ?? selected) : selected;
  const elapsed = shown ? shown.duration_s * status.progress : 0;

  return (
    <Panel
      title="Replay control"
      caption="Pick a captured scenario and play it through the engine. Nothing is generated, nothing is sent back."
      tip={
        "The problem statement allows live or replayed detection. Every scenario here is a committed capture file. " +
        "Virtual mode consumes the file as fast as the engine can, which is the throughput benchmark. " +
        "Realtime mode honours the original packet timing, which is the demo. Speed multiplies the capture clock."
      }
      right={
        shown ? (
          <span className="chip">
            <b>{formatCount(shown.packets)}</b> packets
          </span>
        ) : null
      }
    >
      <div className="replay">
        <label className="field-inline">
          <span>Input</span>
          <select className="input" value={controls.source} disabled={status.running}
            onChange={(event) => controls.onSource(event.target.value as SourceKind)}>
            <option value="pcap">PCAP packets</option><option value="rust-pcap">Rust PCAP ingest</option>
            <option value="flows">Flow CSV (reduced visibility)</option>
          </select>
        </label>
        <label className="field-inline">
          <span>Scenario</span>
          <select
            className="input"
            value={choice}
            disabled={status.running}
            onChange={(e) => controls.onChoice(e.target.value)}
          >
            {scenarios.length === 0 && <option value="">no scenarios loaded</option>}
            {scenarios.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field-inline narrow">
          <span>Speed</span>
          <select
            className="input"
            value={speed}
            disabled={status.running}
            onChange={(e) => controls.onSpeed(Number(e.target.value))}
          >
            {SPEEDS.map((s) => (
              <option key={s} value={s}>
                {s}x
              </option>
            ))}
          </select>
        </label>
        <div className="field-inline narrow">
          <span>Clock</span>
          <div className="segmented">
            <button
              type="button"
              className={mode === "realtime" ? "active" : ""}
              disabled={status.running}
              onClick={() => controls.onMode("realtime")}
            >
              Realtime
            </button>
            <button
              type="button"
              className={mode === "virtual" ? "active" : ""}
              disabled={status.running}
              onClick={() => controls.onMode("virtual")}
            >
              Virtual
            </button>
          </div>
        </div>
        <div className="replay-buttons">
          <button
            type="button"
            className="button primary"
            disabled={busy || status.running || !choice}
            onClick={() => onStart(choice, speed, mode, controls.source)}
          >
            Start
          </button>
          <button
            type="button"
            className="button"
            disabled={busy || !status.running}
            onClick={status.paused ? onResume : onPause}
          >
            {status.paused ? "Resume" : "Pause"}
          </button>
          <button type="button" className="button danger" disabled={busy || !status.running} onClick={onStop}>
            Stop
          </button>
        </div>
      </div>

      <div
        className="progress"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={Math.round(status.progress * 100)}
      >
        <div className="progress-fill" style={{ width: `${Math.min(100, status.progress * 100)}%` }} />
      </div>
      <div className="progress-meta">
        <span className="mono">{formatClock(status.clock_ts)}</span>
        <span className="muted small">
          {shown ? `${formatDuration(elapsed)} of ${formatDuration(shown.duration_s)}` : "no capture loaded"}
        </span>
        <span className="muted small">{percent(status.progress, 0)} through the capture</span>
        <span className="muted small">
          {status.mode} clock at {status.speed}x
        </span>
        <span className="chip">
          <b>{alerts}</b> {alerts === 1 ? "alert" : "alerts"} in the queue
        </span>
      </div>

      {shown && (
        <div className="scenario-note">
          <ThreatBadge id={shown.threat_class} theme={theme} />
          <span className="muted small">proves: {shown.proves}</span>
          <span className="mono small muted">{shown.file}</span>
        </div>
      )}
    </Panel>
  );
}
