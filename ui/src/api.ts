import type { ThreatClass, Severity } from "./threats";

export type ReplayMode = "virtual" | "realtime";
export type SourceKind = "pcap" | "rust-pcap" | "flows";

export type Scenario = {
  id: string;
  name: string;
  file: string;
  proves: string;
  threat_class: ThreatClass;
  packets: number;
  duration_s: number;
};

export type ReplayStatus = {
  running: boolean;
  paused: boolean;
  scenario: string | null;
  speed: number;
  mode: ReplayMode;
  clock_ts: number | null;
  progress: number;
  alerts: number;
};

export type StartRequest = { scenario: string; speed: number; mode: ReplayMode; source?: SourceKind };

export type EvidenceItem = { feature: string; value: number; shap: number };

export type FlowIdentifier = {
  proto: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  directionality: string;
  completeness_flag: boolean;
  window_start: string;
  window_end: string;
};

export type ExternalReference = { source_name: string; external_id: string; description: string };

export type ModelLineage = { model_id: string; model_hash: string; dataset_version: string };

export type NoveltyContext = {
  schema_version: string;
  decision: "unknown-suspicious" | "novelty-review" | "insufficient-evidence";
  reason_codes: string[];
  raw_anomaly_score: number;
  benign_tail_fraction: number;
  score_direction: string;
  score_meaning: string;
  calibration_count: number;
  model_hash: string;
  baseline_hash: string;
  extractor_version: string;
  threshold_policy_version: string;
  missing_fields: string[];
  observation_source: string;
  direction_coverage: string;
  window_start_ns: number;
  window_end_ns: number;
  group_id: string;
  group_windows: number;
  review_status: string;
  retained_evidence_ref: string;
};

export type DetectionContext = {
  sampling_active: boolean;
  sampling_ratio: number;
  shedding_tier: string;
  evidence_basis?: string;
  novelty?: NoveltyContext;
};

export type CaseRecord = {
  case_id: string;
  alert_id: string;
  owner: string | null;
  status: "open" | "investigating" | "escalated" | "closed";
  version: number;
  review_label: string | null;
  annotations: { id: string; actor: string; created: string; text: string }[];
  created: string;
  updated: string;
};

export type CaseCommand = {
  action: "claim" | "release" | "annotate" | "set_status" | "review";
  expected_version: number;
  idempotency_key: string;
  note?: string;
  status?: string;
  label?: string;
  reason?: string;
};

export type CopilotJob = {
  id: string;
  state: "queued" | "running" | "complete" | "failed" | "cancelled";
  intent: string;
  created: string;
  updated: string;
  result?: { briefing?: string; limitations?: string[]; report?: { report_id: string } } | null;
  error?: string | null;
};

export type Alert = {
  type: "indicator";
  spec_version: "2.1";
  id: string;
  created: string;
  name: string;
  description: string;
  indicator_types: string[];
  pattern: string;
  pattern_type: "stix";
  valid_from: string;
  confidence: number;
  x_flow_identifier: FlowIdentifier;
  x_threat_class: ThreatClass;
  x_subtype: string;
  x_severity: Severity;
  x_confidence_calibrated: boolean;
  x_detector: string;
  x_latency_ms: number;
  x_model_lineage: ModelLineage;
  x_supporting_evidence: EvidenceItem[];
  x_detection_context: DetectionContext;
  x_prev_hash: string;
  external_references: ExternalReference[];
  labels: string[];
};

export type LatencyQuantiles = { p50: number; p95: number; p99: number; p999: number };

export type LatencyBucket = { le_ms: number; count: number };

export type QueueState = {
  depth: number;
  capacity: number;
  dropped: number;
  shedding_tier: string;
  policy?: string;
};

export type MetricsSnapshot = {
  analysis_limits?: { beacon_event_bin_limit: number; beacon_windows_skipped: number;
    late_rate_packets_skipped: number; rate_monitors_evicted: number;
    encrypted_sequence_updates?: number; udp443_sequence_updates?: number;
    model_candidates_without_support?: number };
  uptime_s: number;
  packets: number;
  flows: number;
  alerts: number;
  packets_per_s: number;
  flows_per_s: number;
  mbps: number;
  latency_ms: LatencyQuantiles;
  latency_histogram?: LatencyBucket[];
  rss_mb: number;
  flow_table_entries: number;
  memory_bytes: Record<string, number>;
  memory_caps_bytes: Record<string, number>;
  stage_timing_us: Record<string, number>;
  queue: QueueState;
  novelty?: {
    status: string;
    shadow: boolean;
    eligible: number;
    scored: number;
    unsupported: number;
    skipped: number;
    alerts: number;
    coverage_degraded: boolean;
    drift_warning: boolean;
    drift_js_divergence: number;
  };
};

export type CoverageReason = { code: string; label: string; fraction: number; detail: string };

export type Coverage = {
  high_confidence: number;
  low_confidence: number;
  unclassifiable_opaque: number;
  reasons: CoverageReason[];
};

export type LedgerAnchor = { count: number | null; signature_ok: boolean; head_ok: boolean };

export type LedgerVerdict = {
  ok: boolean;
  records: number;
  broken_at: number | null;
  anchors_ok: boolean;
  head: string;
  anchors?: LedgerAnchor[];
  key_source?: string;
};

export type StreamEvent =
  | { type: "resync"; payload: { reason: string } }
  | { type: "alert"; payload: Alert }
  | { type: "metrics"; payload: MetricsSnapshot }
  | { type: "status"; payload: ReplayStatus }
  | { type: "case_cursor"; payload: number }
  | { type: "case_delta"; payload: { event_id: string; event_sequence: number; alert_id: string } };

export type StreamHandlers = {
  onEvent: (event: StreamEvent) => void;
  onOpen?: () => void;
  onClose?: () => void;
};

export type EngineClient = {
  scenarios: () => Promise<Scenario[]>;
  status: () => Promise<ReplayStatus>;
  start: (request: StartRequest) => Promise<ReplayStatus>;
  pause: () => Promise<ReplayStatus>;
  resume: () => Promise<ReplayStatus>;
  stop: () => Promise<ReplayStatus>;
  alerts: (options?: { since?: string; limit?: number }) => Promise<Alert[]>;
  alert: (id: string) => Promise<Alert>;
  metrics: () => Promise<MetricsSnapshot>;
  coverage: () => Promise<Coverage>;
  verifyLedger: () => Promise<LedgerVerdict>;
  connect: (handlers: StreamHandlers) => () => void;
};

// aggregate detections have no single port, and printing :0 reads as an unfilled field
export function flowLabel(flow: FlowIdentifier): string {
  return `${endpoint(flow.src_ip, flow.src_port)} -> ${endpoint(flow.dst_ip, flow.dst_port)}`;
}

export function flowIsAggregate(flow: FlowIdentifier): boolean {
  return flow.src_port === 0 && flow.dst_port === 0;
}

function endpoint(ip: string, port: number): string {
  return port > 0 ? `${ip}:${port}` : ip;
}

export const IDLE_STATUS: ReplayStatus = {
  running: false,
  paused: false,
  scenario: null,
  speed: 1,
  mode: "realtime",
  clock_ts: null,
  progress: 0,
  alerts: 0,
};

// the mock engine is opt in: ?mock=1 turns it on, ?mock=0 clears it again
export const USE_MOCK = readMockFlag();

function readMockFlag(): boolean {
  const asked = new URLSearchParams(window.location.search).get("mock");
  try {
    if (asked === "1") localStorage.setItem("ui.mock", "1");
    if (asked === "0") localStorage.removeItem("ui.mock");
    return localStorage.getItem("ui.mock") === "1";
  } catch {
    return asked === "1";
  }
}

export class ApiResponseError extends Error {
  constructor(message: string, public readonly status: number) {
    super(message);
    this.name = "ApiResponseError";
  }
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  if (!response.ok) {
    let detail = response.statusText;
    try {
      detail = (await response.json()).detail ?? detail;
    } catch {
      // body was not json, keep the status text
    }
    throw new ApiResponseError(detail, response.status);
  }
  return response.json();
}

function post<T>(url: string, body?: unknown): Promise<T> {
  return request<T>(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

// Vite and the production gateway both proxy /ws on the page's own origin.
function streamUrl(): string {
  const loc = window.location;
  const proto = loc.protocol === "https:" ? "wss:" : "ws:";
  const host = loc.host;
  return `${proto}//${host}/ws`;
}

export const httpClient: EngineClient = {
  scenarios: () => request<Scenario[]>("/api/scenarios"),
  status: () => request<ReplayStatus>("/api/status"),
  start: (req) => post<ReplayStatus>("/api/replay/start", req),
  pause: () => post<ReplayStatus>("/api/replay/pause"),
  resume: () => post<ReplayStatus>("/api/replay/resume"),
  stop: () => post<ReplayStatus>("/api/replay/stop"),
  alerts: (options) => {
    const params = new URLSearchParams();
    if (options?.since) params.set("since", options.since);
    if (options?.limit != null) params.set("limit", String(options.limit));
    const query = params.toString();
    return request<Alert[]>("/api/alerts" + (query ? "?" + query : ""));
  },
  alert: (id) => request<Alert>(`/api/alerts/${encodeURIComponent(id)}`),
  metrics: () => request<MetricsSnapshot>("/api/metrics"),
  coverage: () => request<Coverage>("/api/coverage"),
  verifyLedger: () => request<LedgerVerdict>("/api/ledger/verify"),
  connect: (handlers) => {
    let socket: WebSocket | null = null;
    let retry: number | undefined;
    let closed = false;

    const open = () => {
      socket = new WebSocket(streamUrl());
      socket.onopen = () => handlers.onOpen?.();
      socket.onmessage = (event) => {
        try {
          handlers.onEvent(JSON.parse(event.data) as StreamEvent);
        } catch {
          // a malformed frame is not worth tearing the stream down for
        }
      };
      socket.onclose = () => {
        handlers.onClose?.();
        if (!closed) retry = window.setTimeout(open, 2000);
      };
      socket.onerror = () => socket?.close();
    };

    open();
    return () => {
      closed = true;
      window.clearTimeout(retry);
      if (!socket) return;
      if (socket.readyState === WebSocket.CONNECTING) {
        socket.onopen = () => socket?.close();
      } else {
        socket.close();
      }
    };
  },
};

export async function readCase(alertId: string): Promise<CaseRecord | null> {
  try {
    return await request<CaseRecord>(`/api/cases/${encodeURIComponent(alertId)}`);
  } catch (error) {
    if (error instanceof ApiResponseError && error.status === 404) return null;
    throw error;
  }
}

export function sendCaseCommand(alertId: string, command: CaseCommand): Promise<{ case: CaseRecord }> {
  return post<{ case: CaseRecord }>(`/api/cases/${encodeURIComponent(alertId)}/commands`, command);
}

export function startCopilot(payload: {
  intent: "explain_alert" | "summarise_window" | "compare_alerts" | "explain_term" | "draft_incident_report";
  alert_ids?: string[];
}): Promise<CopilotJob> {
  return post<CopilotJob>("/api/copilot/query", payload);
}

export function readCopilotJob(id: string): Promise<CopilotJob> {
  return request<CopilotJob>(`/api/copilot/jobs/${encodeURIComponent(id)}`);
}
