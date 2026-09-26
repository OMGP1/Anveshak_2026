import type { ReplayStatus } from "../api";
import { formatClock, type Theme } from "../threats";

export type View = "analyst" | "operations";

type Props = {
  view: View;
  onView: (view: View) => void;
  status: ReplayStatus;
  connected: boolean;
  apiUp: boolean;
  mock: boolean;
  theme: Theme;
  onToggleTheme: () => void;
};

export default function Header(props: Props) {
  const { view, onView, status, connected, apiUp, mock, theme, onToggleTheme } = props;
  const state = status.running ? (status.paused ? "paused" : "running") : status.progress > 0 ? "finished" : "";
  const label = status.running ? (status.paused ? "PAUSED" : "REPLAYING") : status.progress > 0 ? "DONE" : "IDLE";

  return (
    <header className="header">
      <div className="brand">
        <span className={status.running && !status.paused ? "dot live" : "dot"} />
        <div>
          <h1>Unidirectional threat detection</h1>
          <div className="caption hide-narrow">SIH26145, NTRO. passive metadata from a one-way tap</div>
        </div>
      </div>
      <div className="chips hide-narrow">
        <span className="chip">read-only ingest</span>
        <span className="chip">payload discarded at parse</span>
        <span className="chip">streaming, bounded state</span>
      </div>
      <div className="controls">
        {mock && <span className="badge warn">mock data</span>}
        <span className={state ? `live-pill ${state}` : "live-pill"}>
          <span className="dot" />
          {label}
          <span className="mono">{formatClock(status.clock_ts)}</span>
        </span>
        <span className={connected ? "chip" : "chip offline"} title="websocket to the engine">
          {connected ? "stream up" : "stream down"}
        </span>
        {!apiUp && (
          <span className="chip offline" title="the rest api did not answer">
            api down
          </span>
        )}
        <div className="segmented" role="tablist" aria-label="View">
          <button
            type="button"
            role="tab"
            aria-selected={view === "analyst"}
            className={view === "analyst" ? "active" : ""}
            onClick={() => onView("analyst")}
          >
            Analyst
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={view === "operations"}
            className={view === "operations" ? "active" : ""}
            onClick={() => onView("operations")}
          >
            Operations
          </button>
        </div>
        <button type="button" className="button" onClick={onToggleTheme}>
          {theme === "dark" ? "Light" : "Dark"}
        </button>
      </div>
    </header>
  );
}
