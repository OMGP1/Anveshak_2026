import { useEffect, useState } from "react";
import {
  readCase,
  readCopilotJob,
  sendCaseCommand,
  startCopilot,
  type Alert,
  type CaseRecord,
  type CopilotJob,
} from "../api";
import Panel from "./Panel";

const freshKey = () => crypto.randomUUID?.() ?? `${Date.now()}-${Math.random()}`;

export default function InvestigationPanel({ alert }: { alert: Alert | null }) {
  const [caseRecord, setCaseRecord] = useState<CaseRecord | null>(null);
  const [note, setNote] = useState("");
  const [review, setReview] = useState("inconclusive");
  const [reason, setReason] = useState("");
  const [job, setJob] = useState<CopilotJob | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setJob(null);
    setError(null);
    if (!alert) {
      setCaseRecord(null);
      return;
    }
    readCase(alert.id).then(setCaseRecord).catch((value) => setError((value as Error).message));
  }, [alert]);

  useEffect(() => {
    if (!alert) return;
    const refresh = (event?: Event) => {
      const detail = event instanceof CustomEvent ? event.detail as { alert_id?: string } : null;
      if (detail?.alert_id && detail.alert_id !== alert.id) return;
      readCase(alert.id).then(setCaseRecord).catch((value) => setError((value as Error).message));
    };
    window.addEventListener("case-delta", refresh);
    window.addEventListener("case-resync", refresh);
    return () => {
      window.removeEventListener("case-delta", refresh);
      window.removeEventListener("case-resync", refresh);
    };
  }, [alert]);

  useEffect(() => {
    if (!job || (job.state !== "queued" && job.state !== "running")) return;
    const timer = window.setInterval(() => {
      readCopilotJob(job.id).then(setJob).catch((value) => setError((value as Error).message));
    }, 400);
    return () => window.clearInterval(timer);
  }, [job]);

  const command = (payload: Parameters<typeof sendCaseCommand>[1]) => {
    if (!alert) return;
    setBusy(true);
    setError(null);
    sendCaseCommand(alert.id, payload)
      .then((result) => setCaseRecord(result.case))
      .catch((value) => setError((value as Error).message))
      .finally(() => setBusy(false));
  };

  const explain = (intent: "explain_alert" | "draft_incident_report") => {
    if (!alert) return;
    setBusy(true);
    startCopilot({ intent, alert_ids: [alert.id] })
      .then(setJob)
      .catch((value) => setError((value as Error).message))
      .finally(() => setBusy(false));
  };

  return (
    <Panel
      title="Collaborative investigation and Offline SOC Copilot"
      caption="Committed case actions use optimistic versions. Copilot output is evidence-linked assistance, never a changed verdict."
      tip="Case updates are saved before they are broadcast. Copilot requests use fixed retrieval and never receive SQL, shell, capture, or response tools."
    >
      {!alert ? (
        <div className="empty">Select an alert to claim, review, annotate, or explain it.</div>
      ) : (
        <>
          {error && <div className="card error">{error}</div>}
          <div className="row">
            <span className="chip">case version {caseRecord?.version ?? 0}</span>
            <span className="chip">owner {caseRecord?.owner ?? "unclaimed"}</span>
            <span className="chip">status {caseRecord?.status ?? "open"}</span>
            <span className="chip">review {caseRecord?.review_label ?? "pending"}</span>
            <button className="button" disabled={busy || Boolean(caseRecord?.owner)} onClick={() =>
              command({ action: "claim", expected_version: caseRecord?.version ?? 0, idempotency_key: freshKey() })}>
              Claim case
            </button>
          </div>
          <div className="field-inline">
            <span>Annotation</span>
            <input className="input" value={note} maxLength={4000} onChange={(event) => setNote(event.target.value)} />
            <button className="button" disabled={busy || !note.trim()} onClick={() => {
              command({ action: "annotate", expected_version: caseRecord?.version ?? 0,
                idempotency_key: freshKey(), note });
              setNote("");
            }}>Save note</button>
          </div>
          <div className="field-inline">
            <span>Review</span>
            <select className="input" value={review} onChange={(event) => setReview(event.target.value)}>
              <option value="inconclusive">Inconclusive</option>
              <option value="suspicious-needs-investigation">Needs investigation</option>
              <option value="confirmed-benign">Confirmed benign</option>
              <option value="confirmed-malicious">Confirmed malicious</option>
            </select>
            <input className="input" placeholder="Required rationale" value={reason} maxLength={4000}
              onChange={(event) => setReason(event.target.value)} />
            <button className="button" disabled={busy || !reason.trim()} onClick={() => {
              command({ action: "review", expected_version: caseRecord?.version ?? 0,
                idempotency_key: freshKey(), label: review, reason });
              setReason("");
            }}>Record review</button>
          </div>
          <div className="row">
            <button className="button primary" disabled={busy} onClick={() => explain("explain_alert")}>
              Explain this alert
            </button>
            <button className="button" disabled={busy} onClick={() => explain("draft_incident_report")}>
              Draft report
            </button>
            {job && <span className="chip">copilot {job.state}</span>}
          </div>
          {job?.error && <div className="card error">{job.error}</div>}
          {job?.result?.briefing && <pre className="raw mono">{job.result.briefing}</pre>}
          {job?.result?.report?.report_id && (
            <div className="row">
              <a className="button" href={`/api/reports/${encodeURIComponent(job.result.report.report_id)}/export?format=markdown`}>
                Export Markdown draft
              </a>
              <a className="button" href={`/api/reports/${encodeURIComponent(job.result.report.report_id)}/export?format=json`}>
                Export JSON + provenance
              </a>
            </div>
          )}
        </>
      )}
    </Panel>
  );
}
