import { useCallback, useEffect, useState } from "react";
import { USE_MOCK } from "../api";
import Panel from "./Panel";

type FileCheck = { kind: string; path: string; exists: boolean; bytes: number; sha256: string | null; hash_status: string };
type Inventory = {
  ok: boolean; scope: string; hash_note: string; errors: string[];
  scenarios: { id: string; name: string; provenance: string; packets: number; flow_records: number;
    dashboard_available: boolean; ok: boolean; errors: string[]; files: FileCheck[] }[];
  training_dataset: { ok: boolean; rows?: number; features?: number; errors: string[] };
  problem_statement?: { note: string; generators: { tool: string; bundled_scenarios: string[]; status: string }[];
    lab_runs: { id: string; generator: string; integrity_ok: boolean; records?: number; packets_reported?: number;
      application_bytes?: number; detections?: { threat_class: string; confidence: number }[]; limitations?: string }[] };
};
type Training = { state: string; enabled?: boolean; gateway_session?: boolean; auto_train?: boolean; id?: string; error?: string;
  profile?: string; pr_auc?: number; gates?: { passed: boolean; failures: string[] } };
type Methods = { source: string; reviewed: string; note: string; registered_methods: number;
  exact_methods_validated: number;
  runtime: { extended_enabled: boolean; syn_attempt_enabled: boolean; note: string };
  methods: { method: string; family: string; status: string; note: string;
    detector_enabled: boolean; validation: string }[] };

async function read<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, options);
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail || `HTTP ${response.status}`);
  return body as T;
}

export default function DataTrainingPanel() {
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [training, setTraining] = useState<Training | null>(null);
  const [methods, setMethods] = useState<Methods | null>(null);
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const refresh = useCallback(async () => {
    setBusy(true);
    try {
      setInventory(await read<Inventory>("/api/datasets"));
      setMethods(await read<Methods>("/api/detection-coverage"));
      setError("");
    } catch (failure) { setError((failure as Error).message); }
    finally { setBusy(false); }
  }, []);
  useEffect(() => {
    if (USE_MOCK) return;
    let live = true;
    let timer: number;
    const poll = async () => {
      try {
        const status = await read<Training>("/api/training");
        if (live) setTraining(status);
        const coverage = await read<Methods>("/api/detection-coverage");
        if (live) setMethods(coverage);
      } catch (failure) { if (live) setError((failure as Error).message); }
      if (live) timer = window.setTimeout(poll, 3000);
    };
    void refresh();
    void poll();
    return () => { live = false; window.clearTimeout(timer); };
  }, [refresh]);
  if (USE_MOCK) return <Panel title="Datasets and training" caption="Real operations are disabled in mock mode." tip="Mock data is not an integrity check.">
    <p>Open with ?mock=0 to audit files or train a candidate.</p>
  </Panel>;
  const start = async () => {
    setBusy(true);
    try {
      setTraining(await read<Training>("/api/training/start", {
        method: "POST", headers: training?.gateway_session ? {} : { Authorization: `Bearer ${token}` },
      }));
      setError("");
    } catch (failure) { setError((failure as Error).message); }
    finally { setBusy(false); }
  };
  return <>
    <Panel title="Extended attack coverage" caption="Defensive review of MHDDoS methods, with explicit detection limits."
      tip="A rate alarm does not prove a specific attack method. The table separates synthetic-tested families from partial or unavailable signals.">
      <p>{methods?.note}</p>
      {methods && <>
        <p>Extended packet-rate alarms: {methods.runtime.extended_enabled ? "enabled" : "disabled"}.
          {" "}SYN-attempt alarms: {methods.runtime.syn_attempt_enabled ? "enabled" : "disabled"}.
          {" "}Exact tool methods validated: {methods.exact_methods_validated}/{methods.registered_methods}.</p>
        <p className="caption">{methods.runtime.note}</p>
      </>}
      <details><summary>Inspect {methods?.registered_methods ?? 0} registered methods</summary>
        <div className="table-wrap"><table className="table"><thead><tr>
          <th>Method</th><th>Family</th><th>Coverage</th><th>Family detector</th><th>Validation / limit</th>
        </tr></thead><tbody>{methods?.methods.map((row) => <tr key={row.method}>
          <td>{row.method}</td><td>{row.family}</td><td>{row.status}</td>
          <td>{row.detector_enabled ? "Enabled" : "Disabled / unavailable"}</td>
          <td>{row.validation}. {row.note}</td>
        </tr>)}</tbody></table></div>
      </details>
    </Panel>
    <Panel title="Dataset inventory" caption="All bundled scenarios, flow exports, labels, and training data."
      tip="SHA-256 compares every byte against existing PCAP and parquet reference hashes. Other hashes establish a local fingerprint only."
      right={<button className="button" onClick={() => void refresh()} disabled={busy}>Verify files</button>}>
      {error && <p role="alert">{error}</p>}
      {inventory ? <>
        <p>{inventory.ok ? "Bundled integrity checks passed." : "Integrity checks failed; inspect the findings below."}</p>
        <p className="caption">{inventory.scope} {inventory.hash_note}</p>
        {inventory.problem_statement && <details open><summary>Problem statement 26145: generator coverage</summary>
          <p>{inventory.problem_statement.note}</p>
          <div className="table-wrap"><table className="table"><thead><tr><th>Named source</th><th>Bundled coverage</th><th>Actual provenance</th></tr></thead>
            <tbody>{inventory.problem_statement.generators.map(row => <tr key={row.tool}>
              <td>{row.tool}</td><td>{row.bundled_scenarios.join(", ")}</td><td>{row.status}</td>
            </tr>)}</tbody></table></div>
          {inventory.problem_statement.lab_runs.map(run => <p key={run.id}>
            Lab {run.id}: {run.generator}, integrity {run.integrity_ok ? "PASS" : "FAIL"}; {run.records} flow intervals,
            {" "}{run.packets_reported} reported packets, {run.application_bytes} application bytes,
            {" "}{run.detections?.length ?? 0} detections. {run.limitations}
          </p>)}
        </details>}
        <p>Training dataset: {inventory.training_dataset.rows?.toLocaleString()} rows,
          {" "}{inventory.training_dataset.features} features. {inventory.training_dataset.ok ? "Verified" : "FAILED"}.</p>
        {[...inventory.errors, ...inventory.training_dataset.errors].map((message) => <p key={message}>{message}</p>)}
        <div className="table-wrap"><table className="table"><thead><tr>
          <th>Scenario</th><th>Origin</th><th>Packets</th><th>Flow records</th><th>Integrity</th>
        </tr></thead><tbody>{inventory.scenarios.map((row) => <tr key={row.id}>
          <td><details><summary>{row.name}</summary>{row.files.map((file) => <p key={file.path}>
            {file.path}: {file.exists ? `${file.bytes.toLocaleString()} bytes` : "MISSING"}; {file.hash_status}
            <br /><code className="wrap">{file.sha256}</code></p>)}</details></td>
          <td>{row.provenance}</td><td>{row.packets.toLocaleString()}</td><td>{row.flow_records.toLocaleString()}</td>
          <td>{row.ok ? "PASS" : row.errors.join("; ")}</td>
        </tr>)}</tbody></table></div>
      </> : <p>Reading dataset inventory…</p>}
    </Panel>
    <Panel title="Model training" caption="Train an isolated quality candidate. Never replaces the serving model automatically."
      tip="Candidates train in a separate process with fixed inputs and resource limits. Synthetic tests cannot certify production accuracy.">
      <p>Status: <strong>{training?.state ?? "loading"}</strong>. Profile: {training?.profile ?? "quality-candidate-v2-temporal-search"}.</p>
      <p className="caption">Six configurations, up to 1,200 boosting rounds, temporal early stopping, 500 anomaly trees.
        Higher settings do not guarantee better accuracy. No self-generated attack labels are used.</p>
      {!training?.gateway_session && <label>Operator token <input type="password" value={token} autoComplete="off"
        onChange={(event) => setToken(event.target.value)} /></label>}{" "}
      <button className="button primary" onClick={() => void start()}
        disabled={busy || training?.state === "running" || !training?.enabled || (!training?.gateway_session && !token) || !inventory?.ok}>
        Train quality candidate
      </button>
      <p className="caption">Token stays in page memory. Enable jobs with SIH_OPERATOR_TOKEN on the server.
        Auto-training watcher: {training?.auto_train ? "enabled" : "disabled"}. It requires a verified dataset change.</p>
      {training?.id && <p>Run: <code>{training.id}</code></p>}
      {training?.error && <p role="alert">{training.error}</p>}
      {training?.pr_auc != null && <p>Strict synthetic PR-AUC at 0.1% attack prevalence: {training.pr_auc}.</p>}
      {training?.gates && <><p>Promotion gates: {training.gates.passed ? "PASS, review still required" : "REJECTED"}.</p>
        <ul>{training.gates.failures.map((reason) => <li key={reason}>{reason}</li>)}</ul></>}
    </Panel>
  </>;
}
