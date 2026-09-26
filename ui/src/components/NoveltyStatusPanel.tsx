import type { MetricsSnapshot } from "../api";
import Panel from "./Panel";

export default function NoveltyStatusPanel({ metrics }: { metrics: MetricsSnapshot | null }) {
  const novelty = metrics?.novelty;
  return (
    <Panel
      title="Zero-Day Analysis"
      caption="Unknown and unusual network behaviour — analyst review required."
      tip="This independent companion evaluates eligible flow windows even when known rules do not fire. Rarity is not attack probability."
    >
      {!novelty ? <div className="empty">Waiting for engine status.</div> : (
        <>
          <div className="row">
            <span className="chip">{novelty.status}</span>
            <span className="chip">{novelty.shadow ? "shadow only" : "review alerts enabled"}</span>
            <span className="chip">{novelty.scored}/{novelty.eligible} windows scored</span>
            <span className="chip">{novelty.skipped} skipped</span>
            <span className="chip">{novelty.alerts} alerts</span>
            <span className="chip">drift {novelty.drift_warning ? "warning" : "not observed"}</span>
          </div>
          {(novelty.status !== "ready" || novelty.coverage_degraded) && (
            <div className="caption">
              Coverage is limited: {novelty.status === "baseline-unavailable" ? "no approved companion baseline is loaded. " : ""}
              Unsupported and skipped windows are not called benign.
            </div>
          )}
        </>
      )}
    </Panel>
  );
}
