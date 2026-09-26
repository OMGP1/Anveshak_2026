import { useState } from "react";
import { flowIsAggregate, flowLabel, type Alert } from "../api";
import { featureGloss } from "../featureGloss";
import { chartColours, formatDateTime, formatMs, severityTone, threat, type Theme } from "../threats";
import Panel from "./Panel";
import ThreatBadge from "./ThreatBadge";

type Props = { alert: Alert | null; theme: Theme; following?: boolean };

export default function EvidencePanel({ alert, theme, following }: Props) {
  const [raw, setRaw] = useState(false);
  const colours = chartColours(theme);

  if (!alert) {
    return (
      <Panel
        className="evidence-card"
        title="Evidence"
        caption="Select an alert in the queue to see the features that produced it."
        tip={
          "Every alert is explained by the features that moved the decision, in plain words. " +
          "Nothing here comes from probing the source or looking anything up: it is all passively observed metadata."
        }
      >
        <div className="empty">No alert selected.</div>
      </Panel>
    );
  }

  const info = threat(alert.x_threat_class);
  const flow = alert.x_flow_identifier;
  const aggregate = flowIsAggregate(flow);
  const evidence = [...alert.x_supporting_evidence].sort((a, b) => Math.abs(b.shap) - Math.abs(a.shap));
  const novelty = alert.x_detection_context.novelty;
  const scale = Math.max(...evidence.map((e) => Math.abs(e.shap)), 0.01);

  return (
    <Panel
      className="evidence-card"
      title="Evidence"
      caption="Why this alert fired: the features that moved the decision, the sentence, and the record behind it."
      tip={
        "Bars show decision evidence. Novelty alerts use robust baseline deviations, not TreeSHAP. " +
        "Model and ensemble alerts use per-decision TreeSHAP contributions when available. " +
        "Rule alerts use threshold margins, not SHAP. The value column is the observed feature."
      }
      right={
        <>
          {following && <span className="chip">following newest</span>}
          <button type="button" className="button small" onClick={() => setRaw(!raw)}>
            {raw ? "Hide record" : "Raw STIX"}
          </button>
        </>
      }
    >
      <div className="evidence-head">
        <div className="evidence-name">{alert.name}</div>
        <div className="row">
          <ThreatBadge id={alert.x_threat_class} theme={theme} />
          <span className={`badge ${severityTone(alert.x_severity)}`}>{alert.x_severity}</span>
          <span className="badge">{alert.confidence}% confidence</span>
          <span className="chip">{alert.x_confidence_calibrated ? "calibrated" : "uncalibrated score"}</span>
          <span className="chip">{alert.x_detector}</span>
          <span className="chip">alert {formatMs(alert.x_latency_ms)} after the packet</span>
        </div>
      </div>

      <p className="sentence">{alert.description}</p>

      {novelty && (
        <>
          <h3>Zero-Day Analysis — analyst review required</h3>
          <div className="kv">
            <div><span>Decision</span><b>{novelty.decision}</b></div>
            <div><span>Benign-tail fraction</span><b className="mono">{novelty.benign_tail_fraction}</b></div>
            <div><span>Meaning</span><b>{novelty.score_meaning}</b></div>
            <div><span>Evidence quality</span><b>{novelty.direction_coverage}; {novelty.missing_fields.length} missing fields</b></div>
            <div><span>Baseline</span><b className="mono">{novelty.baseline_hash}</b></div>
            <div><span>Group windows</span><b>{novelty.group_windows}</b></div>
          </div>
          <div className="caption">
            Unusual behaviour may be an unfamiliar attack or a legitimate change. It is not proof of a zero-day exploit.
          </div>
        </>
      )}

      <h3>Supporting features</h3>
      <div className="contrib">
        {evidence.map((item) => {
          const width = (Math.abs(item.shap) / scale) * 50;
          const positive = item.shap >= 0;
          return (
            <div key={item.feature} className="contrib-row">
              <div className="contrib-name">
                <span className="mono">{item.feature}</span>
                <span className="contrib-gloss">{featureGloss(item.feature) || "observed metadata feature"}</span>
              </div>
              <div className="contrib-track">
                <span className="contrib-zero" />
                <span
                  className="contrib-bar"
                  style={{
                    width: `${width}%`,
                    left: positive ? "50%" : `${50 - width}%`,
                    background: positive ? colours.danger : colours.coolText,
                  }}
                />
              </div>
              <div className="contrib-value mono">{fmtValue(item.value)}</div>
              <div className="contrib-shap mono" style={{ color: positive ? colours.danger : colours.coolText }}>
                {positive ? "+" : ""}
                {item.shap.toFixed(2)}
              </div>
            </div>
          );
        })}
      </div>
      <div className="caption">
        Right of the line raises suspicion, left of the line lowers it. Values are the measured feature.
      </div>

      <h3>Flow identifier</h3>
      <div className="kv">
        <div>
          <span>{aggregate ? "Subject" : "Flow"}</span>
          <b className="mono">{flowLabel(flow)}</b>
        </div>
        <div>
          <span>Protocol</span>
          <b>{flow.proto}</b>
        </div>
        <div>
          <span>Direction</span>
          <b>{flow.directionality}</b>
        </div>
        <div>
          <span>Both directions seen</span>
          <b>{flow.completeness_flag ? "yes" : "no, one-way only"}</b>
        </div>
        <div>
          <span>Window start</span>
          <b className="mono">{windowLabel(flow.window_start)}</b>
        </div>
        <div>
          <span>Detected at</span>
          <b className="mono">{formatDateTime(alert.created)}</b>
        </div>
      </div>
      {aggregate && (
        <div className="caption">
          This detector works over a window rather than one five-tuple, so no single port applies to the subject.
        </div>
      )}

      <h3>Reference and lineage</h3>
      <div className="kv">
        {alert.external_references.map((ref) => (
          <div key={ref.external_id}>
            <span>{ref.source_name}</span>
            <b>
              {ref.external_id}, {ref.description}
            </b>
          </div>
        ))}
        <div>
          <span>Signal used</span>
          <b>{info.signal}</b>
        </div>
        <div>
          <span>Model</span>
          <b className="mono">{alert.x_model_lineage.model_id}</b>
        </div>
        <div>
          <span>Dataset</span>
          <b className="mono">{alert.x_model_lineage.dataset_version}</b>
        </div>
        <div>
          <span>Conditions</span>
          <b>
            {alert.x_detection_context.sampling_active
              ? `sampled at ${alert.x_detection_context.sampling_ratio}`
              : "full rate, no sampling"}
            , shedding {alert.x_detection_context.shedding_tier}
          </b>
        </div>
      </div>

      {raw && <pre className="raw mono">{JSON.stringify(alert, null, 2)}</pre>}
    </Panel>
  );
}

// a window stamped in 1970 is a producer bug, and printing it contradicts the alert
function windowLabel(iso: string): string {
  return Number(iso.slice(0, 4)) >= 2000 ? formatDateTime(iso) : "not recorded by this build";
}

function fmtValue(v: number): string {
  if (v === 0) return "0";
  const a = Math.abs(v);
  if (a < 0.001 || a >= 100000) return v.toExponential(1);
  if (a < 1) return v.toFixed(3);
  if (a < 100) return v.toFixed(2);
  return v.toFixed(0);
}
