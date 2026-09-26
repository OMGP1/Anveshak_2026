import { flowLabel, type Alert } from "../api";
import { activateOnEnter, formatTime, severityTone, threat, type Theme } from "../threats";
import Panel from "./Panel";
import ThreatBadge from "./ThreatBadge";

type Props = {
  alerts: Alert[];
  total: number;
  selectedId: string | null;
  filter: string | null;
  theme: Theme;
  onSelect: (alert: Alert) => void;
};

export default function AlertQueue({ alerts, total, selectedId, filter, theme, onSelect }: Props) {
  const calibrated = alerts.some((a) => a.x_confidence_calibrated);

  return (
    <Panel
      className="queue-card"
      title="Alert queue"
      caption="Newest first. Every row is one structured alert record. Select a row to see why it fired."
      tip={
        "Each alert carries the five fields the problem statement requires: capture timestamp, flow identifier, " +
        "threat class, a confidence and the supporting evidence. " +
        (calibrated
          ? "Confidence is a probability after isotonic calibration, so 80 percent means roughly eight in ten " +
            "such alerts are real, not a raw model score. "
          : "This build reports the detector's raw score, not a calibrated probability. Isotonic calibration is " +
            "applied only when a trained tier-1 model is loaded, and these records say so in the clear. ") +
        "Severity is the operational priority, confidence is the belief. " +
        "The capture clock restarts with every scenario, so after a page reload rows written by earlier runs can " +
        "sit below newer ones. Press Start to scope the queue to one run again."
      }
      right={
        <span className="chip">
          <b>{alerts.length}</b>
          {filter ? ` of ${total} shown` : " alerts"}
        </span>
      }
    >
      <div className="table-wrap queue-wrap">
        <table className="table">
          <thead>
            <tr>
              <th title="the capture clock, which restarts with each scenario">Capture clock</th>
              <th>Threat class</th>
              <th>Severity</th>
              <th className="num">Confidence</th>
              <th>Flow</th>
              <th>What fired</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => {
              const open = () => onSelect(alert);
              return (
                <tr
                  key={alert.id}
                  className={alert.id === selectedId ? "clickable selected" : "clickable"}
                  tabIndex={0}
                  onClick={open}
                  onKeyDown={activateOnEnter(open)}
                >
                  <td className="mono">{formatTime(alert.created)}</td>
                  <td>
                    <ThreatBadge id={alert.x_threat_class} theme={theme} short />
                  </td>
                  <td>
                    <span className={`badge ${severityTone(alert.x_severity)}`}>{alert.x_severity}</span>
                  </td>
                  <td className="num">
                    <div className="conf">
                      <span className="conf-track">
                        <span className="conf-fill" style={{ width: `${alert.confidence}%` }} />
                      </span>
                      <span className="mono">{alert.confidence}%</span>
                    </div>
                  </td>
                  <td className="mono flow-cell" title={flowLabel(alert.x_flow_identifier)}>
                    {flowLabel(alert.x_flow_identifier)}
                  </td>
                  <td className="summary-cell" title={alert.description}>
                    {alert.name}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {alerts.length === 0 && (
          <div className="empty">
            {filter
              ? `No ${threat(filter).label} alerts in this run.`
              : "No alerts yet. Start a scenario to see the queue fill."}
          </div>
        )}
      </div>
    </Panel>
  );
}
