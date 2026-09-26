import type { Alert } from "../api";
import type { Engine } from "../useEngine";
import type { Theme } from "../threats";
import ReplayBar, { type ReplayControls } from "../components/ReplayBar";
import ThroughputMeter from "../components/ThroughputMeter";
import ThreatStrip from "../components/ThreatStrip";
import AlertQueue from "../components/AlertQueue";
import EvidencePanel from "../components/EvidencePanel";
import InvestigationPanel from "../components/InvestigationPanel";
import NoveltyStatusPanel from "../components/NoveltyStatusPanel";

type Props = {
  engine: Engine;
  controls: ReplayControls;
  theme: Theme;
  filter: string | null;
  onFilter: (id: string | null) => void;
  selectedId: string | null;
  following: boolean;
  onSelect: (alert: Alert) => void;
};

export default function AnalystView(props: Props) {
  const { engine, controls, theme, filter, onFilter, selectedId, following, onSelect } = props;
  const shown = filter ? engine.alerts.filter((a) => a.x_threat_class === filter) : engine.alerts;
  const selected = shown.find((a) => a.id === selectedId) ?? null;

  return (
    <div className="view">
      <ReplayBar
        scenarios={engine.scenarios}
        status={engine.status}
        controls={controls}
        alerts={engine.alerts.length}
        busy={engine.busy}
        theme={theme}
        onStart={engine.start}
        onPause={engine.pause}
        onResume={engine.resume}
        onStop={engine.stop}
      />
      <ThroughputMeter metrics={engine.metrics} history={engine.history} status={engine.status} theme={theme} />
      <ThreatStrip counts={engine.counts} theme={theme} selected={filter} onSelect={onFilter} />
      <NoveltyStatusPanel metrics={engine.metrics} />
      <div className="split">
        <AlertQueue
          alerts={shown}
          total={engine.alerts.length}
          selectedId={selectedId}
          filter={filter}
          theme={theme}
          onSelect={onSelect}
        />
        <EvidencePanel alert={selected} theme={theme} following={following} />
      </div>
      <InvestigationPanel alert={selected} />
    </div>
  );
}
