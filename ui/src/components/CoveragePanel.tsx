import type { Coverage } from "../api";
import { chartColours, percent, type Theme } from "../threats";
import Panel from "./Panel";

type Props = { coverage: Coverage | null; theme: Theme };

export default function CoveragePanel({ coverage, theme }: Props) {
  const colours = chartColours(theme);

  if (!coverage || coverage.reasons.length === 0) {
    return (
      <Panel
        title="Coverage and what we cannot see"
        caption="The share of observed traffic this system can classify, and the share it honestly cannot."
        tip={
          "This split is measured on the flows of the current run. Until one has been replayed there is nothing " +
          "to divide up, so the panel reports that rather than showing a made-up hundred percent."
        }
      >
        <div className="empty">No flows classified yet. Start a replay and this fills in.</div>
      </Panel>
    );
  }

  const segments = [
    {
      key: "high",
      label: "Classified with high confidence",
      value: coverage.high_confidence,
      colour: colours.good,
      note: "enough metadata to name the class and stand behind the score",
    },
    {
      key: "low",
      label: "Classified with low confidence",
      value: coverage.low_confidence,
      colour: colours.warn,
      note: "scored, but the evidence is thin. treat as a lead, not a finding",
    },
    {
      key: "opaque",
      label: "Unclassifiable, opaque",
      value: coverage.unclassifiable_opaque,
      colour: colours.neutral,
      note: "no observable signal survives, for the reasons listed below",
    },
  ];
  const total = segments.reduce((sum, s) => sum + s.value, 0) || 1;
  const share = coverage.high_confidence / total;

  return (
    <Panel
      title="Coverage and what we cannot see"
      caption="The share of observed traffic this system can classify, and the share it honestly cannot."
      tip={
        "A detector that claims to see everything is not being straight with you. " +
        "This bar splits the traffic seen in this run three ways. " +
        "The opaque slice is traffic where the signal is physically unavailable from passive metadata, " +
        "and the reasons underneath say exactly why. We report it rather than scoring it and hoping."
      }
      right={<span className={`badge ${shareTone(share)}`}>{percent(share, 0)} high-confidence share</span>}
    >
      <div className="coverage-bar">
        {segments.map((s) => (
          <div
            key={s.key}
            className="coverage-seg"
            style={{ width: `${(s.value / total) * 100}%`, background: s.colour }}
            title={`${s.label}: ${percent(s.value / total, 1)}`}
          />
        ))}
      </div>
      <div className="coverage-legend">
        {segments.map((s) => (
          <div key={s.key} className="coverage-item">
            <span className="swatch" style={{ background: s.colour }} />
            <div>
              <div className="coverage-value">{percent(s.value / total, 1)}</div>
              <div className="coverage-label">{s.label}</div>
              <div className="small muted">{s.note}</div>
            </div>
          </div>
        ))}
      </div>

      <h3>Why traffic goes opaque</h3>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Reason</th>
              <th className="num">Share</th>
              <th>What it means</th>
            </tr>
          </thead>
          <tbody>
            {coverage.reasons.map((reason) => (
              <tr key={reason.code}>
                <td>{reason.label}</td>
                <td className="num mono">{percent(reason.fraction, 1)}</td>
                <td className="small muted">{reason.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

// a low share is an honest result, not a pass, so the badge must not read green
function shareTone(share: number): "ok" | "warn" | "danger" {
  if (share >= 0.5) return "ok";
  if (share >= 0.2) return "warn";
  return "danger";
}
