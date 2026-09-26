import type { Engine } from "../useEngine";
import type { Theme } from "../threats";
import MemoryPanel from "../components/MemoryPanel";
import LatencyPanel from "../components/LatencyPanel";
import StageTimingPanel from "../components/StageTimingPanel";
import QueuePanel from "../components/QueuePanel";
import LedgerPanel from "../components/LedgerPanel";
import CoveragePanel from "../components/CoveragePanel";
import DataTrainingPanel from "../components/DataTrainingPanel";

type Props = { engine: Engine; theme: Theme };

export default function OperationsView({ engine, theme }: Props) {
  return (
    <div className="view">
      <DataTrainingPanel />
      <MemoryPanel metrics={engine.metrics} history={engine.history} theme={theme} />
      <div className="grid-2">
        <LatencyPanel metrics={engine.metrics} theme={theme} />
        <StageTimingPanel metrics={engine.metrics} theme={theme} />
      </div>
      <div className="grid-2">
        <QueuePanel metrics={engine.metrics} history={engine.history} theme={theme} />
        <LedgerPanel ledger={engine.ledger} busy={engine.ledgerBusy} onVerify={engine.verifyLedger} />
      </div>
      <CoveragePanel coverage={engine.coverage} theme={theme} />
    </div>
  );
}
