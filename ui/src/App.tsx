import { useCallback, useEffect, useRef, useState } from "react";
import { flowLabel, USE_MOCK, type Alert, type ReplayMode, type SourceKind } from "./api";
import { useEngine } from "./useEngine";
import { threat, type Theme } from "./threats";
import Header, { type View } from "./components/Header";
import Toasts, { type Toast } from "./components/Toasts";
import type { ReplayControls } from "./components/ReplayBar";
import AnalystView from "./views/AnalystView";
import OperationsView from "./views/OperationsView";

const TOAST_MS = 6000;
const MAX_TOASTS = 3;

export default function App() {
  const [view, setView] = useState<View>("analyst");
  const [filter, setFilter] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [pinned, setPinned] = useState(false);
  const [choice, setChoice] = useState("");
  const [speed, setSpeed] = useState(1);
  const [mode, setMode] = useState<ReplayMode>("realtime");
  const [source, setSource] = useState<SourceKind>("pcap");
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [theme, setTheme] = useState<Theme>(() => {
    try {
      return localStorage.getItem("theme") === "light" ? "light" : "dark";
    } catch {
      return "dark";
    }
  });
  const nextToastId = useRef(1);
  const viewRef = useRef<View>(view);
  const chosen = useRef(false);

  useEffect(() => {
    viewRef.current = view;
  }, [view]);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem("theme", theme);
    } catch {
      // storage can be blocked, the theme still applies for this page
    }
  }, [theme]);

  const dismissToast = useCallback((id: number) => {
    setToasts((list) => list.filter((t) => t.id !== id));
  }, []);

  // the queue already shows every alert, so only toast from the operations view
  const onAlert = useCallback(
    (alert: Alert) => {
      if (viewRef.current === "analyst") return;
      if (alert.x_severity !== "HIGH" && alert.x_severity !== "CRITICAL") return;
      const id = nextToastId.current++;
      const toast: Toast = {
        id,
        kind: "alert",
        title: alert.name,
        body: `${threat(alert.x_threat_class).label}, ${alert.confidence}% confidence`,
        host: flowLabel(alert.x_flow_identifier),
        at: alert.created,
        alertId: alert.id,
      };
      setToasts((list) => [...list, toast].slice(-MAX_TOASTS));
      window.setTimeout(() => dismissToast(id), TOAST_MS);
    },
    [dismissToast],
  );

  const engine = useEngine(onAlert);

  // until the analyst picks one, the dropdown follows whatever the engine says is loaded
  useEffect(() => {
    if (chosen.current) return;
    const next = engine.status.scenario ?? engine.scenarios[0]?.id ?? "";
    if (next) setChoice(next);
  }, [engine.scenarios, engine.status.scenario]);

  const controls: ReplayControls = {
    source,
    onSource: setSource,
    choice,
    speed,
    mode,
    onChoice: (scenario) => {
      chosen.current = true;
      setChoice(scenario);
    },
    onSpeed: setSpeed,
    onMode: setMode,
  };

  // follow the newest alert until an analyst picks a row, then stay on their choice
  useEffect(() => {
    if (engine.alerts.length === 0) {
      setPinned(false);
      setSelectedId(null);
      return;
    }
    if (!pinned) setSelectedId(engine.alerts[0].id);
  }, [engine.alerts, pinned]);

  const investigate = useCallback((alertId: string) => {
    setView("analyst");
    setPinned(true);
    setSelectedId(alertId);
  }, []);

  return (
    <div className="app no-sidebar">
      <Header
        view={view}
        onView={setView}
        status={engine.status}
        connected={engine.connected}
        apiUp={engine.apiUp}
        mock={USE_MOCK}
        theme={theme}
        onToggleTheme={() => setTheme(theme === "light" ? "dark" : "light")}
      />
      <main className="main">
        {engine.error && engine.apiUp && <div className="card error">{engine.error}</div>}
        {!engine.apiUp && (
          <div className="card error">
            The engine api did not answer{engine.error ? `: ${engine.error}.` : "."} Start it with{" "}
            <span className="mono">python -m api.main</span> from the repository root, then reload. Everything below
            is stale or empty until it does.
          </div>
        )}
        {view === "analyst" ? (
          <AnalystView
            engine={engine}
            controls={controls}
            theme={theme}
            filter={filter}
            onFilter={setFilter}
            selectedId={selectedId}
            following={!pinned}
            onSelect={(alert) => {
              setPinned(true);
              setSelectedId(alert.id);
            }}
          />
        ) : (
          <OperationsView engine={engine} theme={theme} />
        )}
      </main>
      <Toasts toasts={toasts} onDismiss={dismissToast} onInvestigate={investigate} />
    </div>
  );
}
