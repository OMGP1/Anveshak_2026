import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ApiResponseError,
  httpClient,
  IDLE_STATUS,
  USE_MOCK,
  type Alert,
  type Coverage,
  type EngineClient,
  type LedgerVerdict,
  type MetricsSnapshot,
  type ReplayMode,
  type ReplayStatus,
  type Scenario,
  type SourceKind,
} from "./api";
import { mockClient } from "./mock";
import { emptyCounts } from "./threats";

const client: EngineClient = USE_MOCK ? mockClient : httpClient;

const MAX_ALERTS = 400;
const MAX_HISTORY = 240;
const COVERAGE_INTERVAL_MS = 5000;

export type HistoryPoint = {
  t: number;
  flows_per_s: number;
  packets_per_s: number;
  mbps: number;
  p50: number;
  p99: number;
  queue_depth: number;
  total_memory: number;
  memory: Record<string, number>;
};

export type Engine = {
  connected: boolean;
  apiUp: boolean;
  error: string | null;
  scenarios: Scenario[];
  status: ReplayStatus;
  metrics: MetricsSnapshot | null;
  history: HistoryPoint[];
  alerts: Alert[];
  counts: Record<string, number>;
  coverage: Coverage | null;
  ledger: LedgerVerdict | null;
  ledgerBusy: boolean;
  busy: boolean;
  start: (scenario: string, speed: number, mode: ReplayMode, source?: SourceKind) => void;
  pause: () => void;
  resume: () => void;
  stop: () => void;
  verifyLedger: () => void;
};

export function useEngine(onAlert?: (alert: Alert) => void): Engine {
  const [connected, setConnected] = useState(false);
  const [apiUp, setApiUp] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [status, setStatus] = useState<ReplayStatus>(IDLE_STATUS);
  const [metrics, setMetrics] = useState<MetricsSnapshot | null>(null);
  const [history, setHistory] = useState<HistoryPoint[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [coverage, setCoverage] = useState<Coverage | null>(null);
  const [ledger, setLedger] = useState<LedgerVerdict | null>(null);
  const [ledgerBusy, setLedgerBusy] = useState(false);
  const [busy, setBusy] = useState(false);
  const alertHook = useRef(onAlert);
  const runStart = useRef(0);

  useEffect(() => {
    alertHook.current = onAlert;
  }, [onAlert]);

  const fail = useCallback((e: unknown) => {
    setError((e as Error).message);
    // A rejected action (401/403/422) proves the API answered. Do not tell the
    // operator to restart a healthy engine or discard its connection status.
    setApiUp(e instanceof ApiResponseError && e.status < 500);
  }, []);

  // derived from the queue, so a reload cannot leave the strip and the queue disagreeing
  const counts = useMemo(() => {
    const tally = emptyCounts();
    for (const alert of alerts) tally[alert.x_threat_class] = (tally[alert.x_threat_class] ?? 0) + 1;
    return tally;
  }, [alerts]);

  useEffect(() => {
    let live = true;
    const settle = <T,>(promise: Promise<T>, apply: (value: T) => void) => {
      promise.then((value) => live && apply(value)).catch((e) => live && fail(e));
    };
    settle(client.scenarios(), (list) => {
      setScenarios(list);
      setApiUp(true);
    });
    settle(client.status(), setStatus);
    settle(client.alerts({ limit: MAX_ALERTS }), (list) => setAlerts(unique(list)));
    settle(client.metrics(), setMetrics);
    settle(client.coverage(), setCoverage);
    settle(client.verifyLedger(), setLedger);
    return () => {
      live = false;
    };
  }, [fail]);

  useEffect(() => {
    let live = true;
    const recover = () => {
      client.alerts({ limit: MAX_ALERTS }).then((page) => {
        if (live) { setAlerts(unique(page)); setApiUp(true); }
      }).catch((e) => live && fail(e));
    };
    const disconnect = client.connect({
      onOpen: () => {
        setConnected(true);
        recover();
        window.dispatchEvent(new Event("case-resync"));
      },
      onClose: () => setConnected(false),
      onEvent: (event) => {
        if (event.type === "resync") { recover(); return; }
        if (event.type === "status") {
          setStatus(event.payload);
          return;
        }
        if (event.type === "metrics") {
          const snapshot = event.payload;
          setMetrics(snapshot);
          setHistory((points) => [...points, toPoint(snapshot, runStart.current)].slice(-MAX_HISTORY));
          return;
        }
        if (event.type === "case_cursor") return;
        if (event.type === "case_delta") {
          window.dispatchEvent(new CustomEvent("case-delta", { detail: event.payload }));
          return;
        }
        const alert = event.payload;
        setAlerts((list) => unique([alert, ...list]).slice(0, MAX_ALERTS));
        alertHook.current?.(alert);
      },
    });
    return () => { live = false; disconnect(); };
  }, [fail]);

  // the honesty panel moves as the run goes, so refresh it while traffic flows
  useEffect(() => {
    if (!status.running) return;
    const handle = window.setInterval(() => {
      client.coverage().then(setCoverage).catch(fail);
      client.verifyLedger().then(setLedger).catch(fail);
    }, COVERAGE_INTERVAL_MS);
    return () => window.clearInterval(handle);
  }, [status.running, fail]);

  const command = useCallback(
    (run: () => Promise<ReplayStatus>) => {
      setBusy(true);
      run()
        .then((next) => {
          setStatus(next);
          setError(null);
          setApiUp(true);
        })
        .catch(fail)
        .finally(() => setBusy(false));
    },
    [fail],
  );

  const start = useCallback(
    (scenario: string, speed: number, mode: ReplayMode, source: SourceKind = "pcap") => {
      setAlerts([]);
      setHistory([]);
      setMetrics(null);
      runStart.current = Date.now();
      command(() => client.start({ scenario, speed, mode, source }));
    },
    [command],
  );

  const pause = useCallback(() => command(() => client.pause()), [command]);
  const resume = useCallback(() => command(() => client.resume()), [command]);
  const stop = useCallback(() => command(() => client.stop()), [command]);

  const verifyLedger = useCallback(() => {
    setLedgerBusy(true);
    client
      .verifyLedger()
      .then(setLedger)
      .catch(fail)
      .finally(() => setLedgerBusy(false));
  }, [fail]);

  return {
    connected,
    apiUp,
    error,
    scenarios,
    status,
    metrics,
    history,
    alerts,
    counts,
    coverage,
    ledger,
    ledgerBusy,
    busy,
    start,
    pause,
    resume,
    stop,
    verifyLedger,
  };
}

// the store keys nothing, so replaying a scenario twice returns every alert of it twice
function unique(list: Alert[]): Alert[] {
  const seen = new Set<string>();
  const out: Alert[] = [];
  for (const alert of list) {
    if (seen.has(alert.id)) continue;
    seen.add(alert.id);
    out.push(alert);
  }
  return out;
}

function toPoint(snapshot: MetricsSnapshot, since: number): HistoryPoint {
  const memory = snapshot.memory_bytes ?? {};
  let total = 0;
  for (const value of Object.values(memory)) total += value;
  return {
    t: since ? (Date.now() - since) / 1000 : snapshot.uptime_s,
    flows_per_s: snapshot.flows_per_s,
    packets_per_s: snapshot.packets_per_s,
    mbps: snapshot.mbps,
    p50: snapshot.latency_ms.p50,
    p99: snapshot.latency_ms.p99,
    queue_depth: snapshot.queue.depth,
    total_memory: total,
    memory,
  };
}
