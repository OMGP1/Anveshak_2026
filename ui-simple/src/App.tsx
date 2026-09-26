import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { USE_MOCK, flowLabel, type Alert, type Scenario } from "./api";
import { featureGloss } from "./featureGloss";
import { useEngine, type Engine } from "./useEngine";
import { useLive } from "./useLive";
import { LivePage } from "./LivePage";

const PAGES = [
  { id: "overview", label: "Overview" },
  { id: "live", label: "Live monitor" },
  { id: "demo", label: "Run a demo" },
  { id: "alerts", label: "Alerts" },
  { id: "guide", label: "How it works" },
] as const;
type Page = (typeof PAGES)[number]["id"];
type IconName =
  | "shield"
  | "arrow"
  | "activity"
  | "alert"
  | "play"
  | "book"
  | "network"
  | "check"
  | "external";
const ORIGINAL_URL = import.meta.env.DEV
  ? "http://127.0.0.1:8000/?mock=0"
  : "/?mock=0";
const GUIDE_URL = `${import.meta.env.BASE_URL}dashboard-guide.md`;
const CATEGORIES = [
  {
    id: "volumetric-ddos",
    name: "Traffic floods",
    short: "DDoS",
    color: "coral",
    description: "Too much traffic aimed at one destination.",
    signals:
      "Packet rates, incomplete SYN handshakes, UDP reflection, and unusual source patterns.",
  },
  {
    id: "c2-beaconing",
    name: "Repeated check-ins",
    short: "Beaconing",
    color: "purple",
    description:
      "A device contacting the same destination at regular intervals.",
    signals:
      "The gaps between connections, their regularity, and a stable destination.",
  },
  {
    id: "dga-dns-tunnelling",
    name: "Unusual DNS activity",
    short: "DNS anomalies",
    color: "blue",
    description: "Suspicious domain lookups or possible data hidden in DNS.",
    signals:
      "Query length, character randomness, letter pairs, record types, and query patterns.",
  },
  {
    id: "encrypted-malware",
    name: "Suspicious encrypted traffic",
    short: "Encrypted traffic",
    color: "amber",
    description: "Unusual patterns in encrypted connections.",
    signals:
      "Visible TLS metadata, packet sizes, and timing sequences. Encrypted content stays unread.",
  },
  {
    id: "recon-scanning",
    name: "Network probing",
    short: "Scanning",
    color: "teal",
    description: "One source trying many ports or destinations.",
    signals:
      "The number and spread of destination ports and hosts contacted in a time window.",
  },
  {
    id: "data-exfiltration",
    name: "Possible data leakage",
    short: "Exfiltration",
    color: "pink",
    description: "Unusual amounts or patterns of outbound data.",
    signals:
      "Outgoing versus incoming bytes, destination novelty, and transfers over time.",
  },
  {
    id: "unknown-suspicious",
    name: "Unknown and unusual behaviour",
    short: "Unknown review",
    color: "purple",
    description: "Behaviour that is rare against the approved benign baseline.",
    signals: "Independent flow windows, observation quality, benign-tail rarity, and persistence. Analyst review is required.",
  },
];

function category(id: string) {
  return (
    CATEGORIES.find((item) => item.id === id) ?? {
      id,
      name: "Normal sample traffic",
      short: "Baseline",
      color: "teal",
      description: "Everyday network activity used as a comparison.",
      signals:
        "A benign baseline helps reveal false alarms; one quiet sample cannot establish a false-positive rate.",
    }
  );
}

function Icon({ name, size = 20 }: { name: IconName; size?: number }) {
  const paths: Record<IconName, ReactNode> = {
    shield: (
      <>
        <path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z" />
        <path d="m8 12 3 3 5-6" />
      </>
    ),
    arrow: (
      <>
        <path d="M4 12h15m-6-6 6 6-6 6" />
      </>
    ),
    activity: <path d="M2 12h4l3-8 6 16 3-8h4" />,
    alert: (
      <>
        <path d="m12 3 10 18H2L12 3Z" />
        <path d="M12 9v5m0 3v.1" />
      </>
    ),
    play: <path d="m8 4 12 8-12 8V4Z" />,
    book: (
      <>
        <path d="M12 6c-3-3-8-2-9-1v14c3-2 6-2 9 0 3-2 6-2 9 0V5c-1-1-6-2-9 1Zm0 0v13" />
      </>
    ),
    network: (
      <>
        <rect x="8" y="2" width="8" height="6" rx="1" />
        <path d="M12 8v5M5 17v-4h14v4" />
        <rect x="2" y="17" width="6" height="5" rx="1" />
        <rect x="16" y="17" width="6" height="5" rx="1" />
      </>
    ),
    check: <path d="m5 12 4 4L19 6" />,
    external: (
      <>
        <path d="M14 3h7v7m0-7L10 14" />
        <path d="M10 3H4a1 1 0 0 0-1 1v16a1 1 0 0 0 1 1h16a1 1 0 0 0 1-1v-6" />
      </>
    ),
  };
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {paths[name]}
    </svg>
  );
}

function readPage(): Page {
  const value = window.location.hash.replace(/^#\/?/, "");
  return PAGES.find((page) => page.id === value)?.id ?? "overview";
}
function count(value?: number) {
  return value === undefined
    ? "—"
    : new Intl.NumberFormat("en", { maximumFractionDigits: 0 }).format(value);
}
function number(value: number) {
  return new Intl.NumberFormat("en", { maximumFractionDigits: 3 }).format(
    value,
  );
}
function date(value: string) {
  return new Date(value).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}
function runLabel(engine: Engine) {
  return engine.status.paused
    ? "Paused"
    : engine.status.running
      ? "Analyzing traffic"
      : engine.status.progress >= 1
        ? "Replay complete"
        : engine.status.scenario
          ? "Replay stopped"
          : "Ready for a replay";
}

function PageHeading({
  eyebrow,
  title,
  children,
}: {
  eyebrow: string;
  title: string;
  children: ReactNode;
}) {
  return (
    <header className="page-heading">
      <span className="eyebrow">{eyebrow}</span>
      <h1>{title}</h1>
      <p>{children}</p>
    </header>
  );
}
function Tag({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: string;
}) {
  return <span className={`tag ${tone}`}>{children}</span>;
}
function Empty({
  title,
  children,
  icon = "activity",
}: {
  title: string;
  children: ReactNode;
  icon?: IconName;
}) {
  return (
    <div className="empty">
      <span className="empty-icon">
        <Icon name={icon} size={26} />
      </span>
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}

export default function App() {
  const engine = useEngine();
  const live = useLive();
  const [page, setPage] = useState<Page>(readPage);
  const [menuOpen, setMenuOpen] = useState(false);
  const mainRef = useRef<HTMLElement>(null);
  useEffect(() => {
    const navigate = () => {
      setPage(readPage());
      setMenuOpen(false);
      window.scrollTo(0, 0);
      mainRef.current?.focus();
    };
    window.addEventListener("hashchange", navigate);
    return () => window.removeEventListener("hashchange", navigate);
  }, []);
  useEffect(() => {
    document.title = `${PAGES.find((item) => item.id === page)?.label} · Network Watch`;
  }, [page]);
  const connection = USE_MOCK
    ? "Sample mode"
    : !engine.apiUp
      ? "Engine unavailable"
      : engine.connected
        ? "Engine connected"
        : "Connecting…";
  return (
    <div className="site-shell">
      <a
        className="skip-link"
        href="#main-content"
        onClick={(event) => {
          event.preventDefault();
          mainRef.current?.focus();
        }}
      >
        Skip to content
      </a>
      <header className="site-header">
        <div className="nav-wrap">
          <a
            className="brand"
            href="#/overview"
            aria-label="Network Watch home"
          >
            <span className="brand-mark">
              <Icon name="shield" size={25} />
            </span>
            <span>
              Network<span className="brand-accent">Watch</span>
              <small>SIH 2026 · Simple dashboard</small>
            </span>
          </a>
          <button
            className="menu-toggle"
            aria-expanded={menuOpen}
            aria-controls="main-nav"
            onClick={() => setMenuOpen(!menuOpen)}
          >
            {menuOpen ? "Close menu" : "Menu"}
          </button>
          <nav
            id="main-nav"
            className={menuOpen ? "main-nav open" : "main-nav"}
            aria-label="Main navigation"
          >
            {PAGES.map((item) => (
              <a
                key={item.id}
                href={`#/${item.id}`}
                aria-current={page === item.id ? "page" : undefined}
              >
                {item.label}
                {item.id === "alerts" && engine.alerts.length > 0 && (
                  <span className="nav-count">{engine.alerts.length}</span>
                )}
              </a>
            ))}
          </nav>
          <a
            className="original-link"
            href={ORIGINAL_URL}
            target="_blank"
            rel="noreferrer"
          >
            Advanced view <Icon name="external" size={14} />
          </a>
        </div>
      </header>
      <div className="status-strip">
        <div className="container status-inner">
          <span
            className={`connection ${engine.connected && !USE_MOCK ? "online" : ""}`}
            role="status"
          >
            <span className="status-dot" />
            {connection}
          </span>
          <span className="status-context">
            {USE_MOCK
              ? "Simulated values · no model is running"
              : live.status?.running
                ? "Live traffic · passive analysis"
                : "Live or replayed traffic · passive analysis"}
          </span>
          <a href={`?mock=${USE_MOCK ? "0" : "1"}#/${page}`}>
            {USE_MOCK ? "Connect to engine" : "Try sample mode"}
            <Icon name="arrow" size={13} />
          </a>
        </div>
      </div>
      <main
        className="container main-content"
        id="main-content"
        ref={mainRef}
        tabIndex={-1}
      >
        {USE_MOCK && (
          <div className="notice sample-notice">
            <Icon name="book" />
            <p>
              <strong>You’re exploring sample mode.</strong> All alerts, scores,
              and performance numbers here are simulated for learning.
            </p>
          </div>
        )}
        {!engine.apiUp && (
          <div className="notice error-notice" role="alert">
            <Icon name="alert" />
            <p>
              <strong>The detection engine is unavailable.</strong> Start it
              with <code>python -m api.main</code> from the project folder, then
              reload. You can also explore sample mode.
            </p>
            <button
              className="button small secondary"
              onClick={() => window.location.reload()}
            >
              Retry connection
            </button>
          </div>
        )}
        {engine.error && engine.apiUp && (
          <div className="notice error-notice" role="alert">
            <Icon name="alert" />
            <p>{engine.error}</p>
          </div>
        )}
        {page === "overview" && <Overview engine={engine} />}
        {page === "live" && <LivePage engine={engine} live={live} />}
        {page === "demo" &&
          (live.status?.running ? (
            <section className="panel">
              <h1>Live monitoring is running</h1>
              <p>
                Stop the live session before starting a replay. The two modes
                share one engine.
              </p>
              <a className="button primary" href="#/live">
                Open live monitor
              </a>
            </section>
          ) : (
            <Demo engine={engine} />
          ))}
        {page === "alerts" && <Alerts engine={engine} />}
        {page === "guide" && <Guide />}
      </main>
      <footer className="site-footer container">
        <span>
          <strong>Network Watch</strong> · A network threat detection prototype
        </span>
        <div>
          <a href={GUIDE_URL} download>
            Download the guide <Icon name="book" size={14} />
          </a>
          <a href={ORIGINAL_URL} target="_blank" rel="noreferrer">
            Original dashboard <Icon name="external" size={14} />
          </a>
        </div>
      </footer>
    </div>
  );
}

function Overview({ engine }: { engine: Engine }) {
  const { metrics, status } = engine;
  const liveSession = !!metrics?.monitor_session;
  const alerts = metrics?.alerts;
  return (
    <>
      <section className="hero">
        <div className="hero-copy">
          <span className="eyebrow">
            <span className="tiny-line" />
            Network security, made understandable
          </span>
          <h1>
            See the traffic.
            <br />
            <span>Understand the threat.</span>
          </h1>
          <p>
            Turn live or replayed network traffic into clear, explainable
            alerts. Watch what gets flagged and explore the evidence behind it.
          </p>
          <div className="button-row">
            <a className="button primary" href="#/demo">
              <Icon name="play" size={17} />
              Run a demo
            </a>
            <a className="button secondary" href="#/live">
              Monitor live <Icon name="arrow" size={17} />
            </a>
          </div>
          <div className="hero-notes">
            <span>
              <Icon name="check" size={15} />
              Six threat categories
            </span>
            <span>
              <Icon name="check" size={15} />
              Evidence with each alert
            </span>
          </div>
        </div>
        <div className="pipeline-card">
          <div className="panel-top">
            <span className="eyebrow">From packets to insight</span>
            <Tag tone="teal">Passive analysis</Tag>
          </div>
          <Pipeline />
          <p className="pipeline-caption">
            Patterns in network metadata become signals you can review.
          </p>
        </div>
      </section>
      <div className="section-heading">
        <div>
          <span className="eyebrow">At a glance</span>
          <h2>Your analysis overview</h2>
        </div>
        <Tag tone={status.running ? "teal" : "neutral"}>
          {liveSession
            ? status.running
              ? "Monitoring live"
              : "Live session stopped"
            : runLabel(engine)}
        </Tag>
      </div>
      <div className="stats-grid">
        <Stat
          icon="network"
          label="Packets analyzed"
          value={count(metrics?.packets)}
          detail="Small pieces of network traffic read in this monitoring session."
        />
        <Stat
          icon="alert"
          label="Alerts in this session"
          value={count(alerts)}
          detail="Suspicious observations to investigate. An alert needs review."
        />
        <Stat
          icon="activity"
          label="Alert processing · p99"
          value={alerts ? `${number(metrics!.latency_ms.p99)} ms` : "—"}
          detail="99% of measured alert processing times are at or below this value."
        />
      </div>
      <div className="overview-panels">
        <section className="panel traffic-panel">
          <div className="panel-heading">
            <div>
              <h2>Traffic through the engine</h2>
              <p>
                {USE_MOCK
                  ? "Illustrative packet rate"
                  : "Recent packet rate reported by the engine"}
              </p>
            </div>
            <span className="rate-value">
              {count(metrics?.packets_per_s)}
              <small>packets / second</small>
            </span>
          </div>
          <TrafficChart engine={engine} />
          <div className="chart-foot">
            <span>
              {engine.history.length > 1
                ? "Recent updates → latest"
                : "Waiting for traffic"}
            </span>
            <span>
              Replay measurements depend on this machine and replay speed.
            </span>
          </div>
        </section>
        <section className="panel next-panel">
          <span className="step-label">Your next step</span>
          <div className="round-icon">
            <Icon name={status.running ? "activity" : "play"} size={26} />
          </div>
          <h2>
            {status.running
              ? liveSession
                ? "Live monitoring is in progress"
                : "A replay is in progress"
              : "Start with a familiar example"}
          </h2>
          <p>
            {status.running
              ? liveSession
                ? "Open Live monitor to see capture quality, concurrent alerts, and the stop control."
                : "Open the demo page to see progress, pause the replay, or stop it."
              : "Try a SYN flood to see how a burst of incomplete connections becomes a traffic-flood alert."}
          </p>
          <a
            className="text-link"
            href={liveSession && status.running ? "#/live" : "#/demo"}
          >
            {status.running
              ? liveSession
                ? "View live monitoring"
                : "View replay"
              : "Choose a scenario"}{" "}
            <Icon name="arrow" size={17} />
          </a>
        </section>
      </div>
      <div className="section-heading">
        <div>
          <span className="eyebrow">What we look for</span>
          <h2>Six ways traffic can look suspicious</h2>
        </div>
        <a className="text-link" href="#/guide">
          Learn the signals <Icon name="arrow" size={16} />
        </a>
      </div>
      <div className="category-grid">
        {CATEGORIES.map((item, index) => (
          <a
            href="#/alerts"
            className={`category-card ${item.color}`}
            key={item.id}
          >
            <div className="category-top">
              <span className="category-number">0{index + 1}</span>
              <span className="category-count">
                {count(engine.counts[item.id] ?? 0)} recent alerts
              </span>
            </div>
            <h3>{item.name}</h3>
            <p>{item.description}</p>
            <span className="category-bottom">
              {item.short}
              <Icon name="arrow" size={16} />
            </span>
          </a>
        ))}
      </div>
      <p className="section-note">
        Category counts cover the latest 400 loaded alerts and can include
        earlier replays. A quiet dashboard does not establish that a network is
        safe.
      </p>
      <div className="learn-banner">
        <span className="round-icon">
          <Icon name="book" size={26} />
        </span>
        <div>
          <h2>New to network security?</h2>
          <p>
            Learn what a flow is, what an alert means, and how to walk someone
            through a demo.
          </p>
        </div>
        <a className="button secondary" href="#/guide">
          Start here <Icon name="arrow" size={16} />
        </a>
      </div>
    </>
  );
}

function Pipeline() {
  const steps = [
    {
      icon: "network",
      name: "Observe traffic",
      detail: "Read packets from a saved capture",
    },
    {
      icon: "activity",
      name: "Find unusual patterns",
      detail: "Analyze metadata with rules + models",
    },
    {
      icon: "shield",
      name: "Explain the alert",
      detail: "Show the signal, score, and evidence",
    },
  ] as const;
  return (
    <ol className="pipeline">
      {steps.map((step, index) => (
        <li key={step.name}>
          <span className={`pipeline-icon step-${index}`}>
            <Icon name={step.icon} size={24} />
          </span>
          <div>
            <h3>{step.name}</h3>
            <p>{step.detail}</p>
          </div>
          <span className="pipeline-index">0{index + 1}</span>
        </li>
      ))}
    </ol>
  );
}
function Stat({
  icon,
  label,
  value,
  detail,
}: {
  icon: IconName;
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <section className="stat-card">
      <div className="stat-label">
        {label}
        <Icon name={icon} size={19} />
      </div>
      <strong className="stat-value">{value}</strong>
      <p>{detail}</p>
    </section>
  );
}
function TrafficChart({ engine }: { engine: Engine }) {
  const values = engine.history.map((point) =>
    Math.max(0, point.packets_per_s),
  );
  if (values.length < 2 || values.every((value) => value === 0))
    return (
      <Empty title="Your traffic story starts here">
        Run a demo to see how quickly the engine reads packets.
      </Empty>
    );
  const max = Math.max(...values, 1);
  const coordinates = values.map(
    (value, index) =>
      `${(index / (values.length - 1)) * 700},${130 - (value / max) * 112}`,
  );
  return (
    <svg
      className="traffic-chart"
      viewBox="0 0 700 150"
      preserveAspectRatio="none"
      role="img"
      aria-label={`Recent packet rate. Latest ${count(values.at(-1))}, peak ${count(max)} packets per second.`}
    >
      <defs>
        <linearGradient id="traffic-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="#168575" stopOpacity=".2" />
          <stop offset="100%" stopColor="#168575" stopOpacity=".015" />
        </linearGradient>
      </defs>
      {[30, 80, 130].map((y) => (
        <line
          key={y}
          x1="0"
          x2="700"
          y1={y}
          y2={y}
          stroke="#e5eeeb"
          strokeDasharray="4 5"
        />
      ))}
      <polygon
        points={`0,150 ${coordinates.join(" ")} 700,150`}
        fill="url(#traffic-fill)"
      />
      <polyline
        points={coordinates.join(" ")}
        fill="none"
        stroke="#147363"
        strokeWidth="2.5"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}

function Demo({ engine }: { engine: Engine }) {
  const [selected, setSelected] = useState("");
  const [pace, setPace] = useState("walkthrough");
  const scenarioId =
    selected ||
    engine.status.scenario ||
    engine.scenarios.find(
      (item) => item.id === "syn_flood" || item.id === "syn-flood",
    )?.id ||
    engine.scenarios[0]?.id ||
    "";
  const scenario = engine.scenarios.find((item) => item.id === scenarioId);
  const current = engine.scenarios.find(
    (item) => item.id === engine.status.scenario,
  );
  const progress = Math.min(100, Math.max(0, engine.status.progress * 100));
  const canRun = engine.apiUp && engine.connected && !engine.busy;
  return (
    <>
      <PageHeading
        eyebrow="Try it yourself"
        title="A real example makes it click."
      >
        Choose a saved traffic sample and watch the engine analyze it. Replays
        read local files without sending attack traffic.
      </PageHeading>
      <div className="demo-layout">
        <section className="scenario-section">
          <div className="section-heading compact">
            <h2>
              <span className="step-circle">1</span>Choose a scenario
            </h2>
            <span className="muted">{engine.scenarios.length} available</span>
          </div>
          {engine.scenarios.length === 0 ? (
            <div className="panel">
              <Empty title="Scenarios load from the engine">
                Connect to the engine or use sample mode to explore the
                controls.
              </Empty>
            </div>
          ) : (
            <fieldset className="scenario-grid">
              <legend className="sr-only">Traffic scenario</legend>
              {engine.scenarios.map((item) => (
                <ScenarioCard
                  key={item.id}
                  item={item}
                  checked={item.id === scenarioId}
                  disabled={engine.status.running || engine.busy}
                  onChange={() => setSelected(item.id)}
                />
              ))}
            </fieldset>
          )}
        </section>
        <aside className="demo-controls panel">
          <h2>
            <span className="step-circle">2</span>Replay & observe
          </h2>
          <div className="chosen-scenario">
            <span className="eyebrow">Selected sample</span>
            <h3>{scenario?.name ?? "Choose a scenario"}</h3>
            <p>
              {scenario
                ? category(scenario.threat_class).signals
                : "Pick a sample to get started."}
            </p>
          </div>
          <label className="field-label" htmlFor="pace">
            Replay pace
          </label>
          <select
            id="pace"
            value={pace}
            disabled={engine.status.running || engine.busy}
            onChange={(event) => setPace(event.target.value)}
          >
            <option value="walkthrough">Walkthrough · original timing</option>
            <option value="quick">Quick replay · as fast as possible</option>
          </select>
          <p className="field-help">
            Walkthrough gives you time to pause and explain. Quick replay
            processes the capture without timing delays.
          </p>
          <button
            className="button primary full-width"
            disabled={!canRun || !scenario || engine.status.running}
            onClick={() =>
              engine.start(
                scenarioId,
                1,
                pace === "quick" ? "virtual" : "realtime",
                "pcap",
              )
            }
          >
            <Icon name="play" size={17} />
            {engine.busy ? "Working…" : "Start replay"}
          </button>
          {engine.status.scenario && (
            <div className="replay-progress">
              <div className="progress-label">
                <strong role="status">{runLabel(engine)}</strong>
                <span>{number(progress)}%</span>
              </div>
              <progress
                max="100"
                value={progress}
                aria-label="Replay progress"
              />
              <p>
                {current?.name ?? engine.status.scenario} ·{" "}
                {count(engine.status.alerts)} alerts raised
              </p>
            </div>
          )}
          {engine.status.running && (
            <div className="button-row replay-actions">
              <button
                className="button secondary"
                disabled={!canRun}
                onClick={engine.status.paused ? engine.resume : engine.pause}
              >
                {engine.status.paused ? "Resume" : "Pause"}
              </button>
              <button
                className="button secondary"
                disabled={!canRun}
                onClick={engine.stop}
              >
                Stop replay
              </button>
            </div>
          )}
          <a className="text-link" href="#/alerts">
            Review the alerts <Icon name="arrow" size={17} />
          </a>
          <div className="explanation-note">
            <Icon name="book" size={18} />
            <p>
              <strong>What should I expect?</strong>
              <br />
              Attack samples are designed to exercise particular detectors. The
              observed result can differ with the active model and settings.
            </p>
          </div>
          <p className="field-help">
            Both dashboards share one engine. Starting, pausing, or stopping a
            real replay affects both views.
          </p>
        </aside>
      </div>
    </>
  );
}
function ScenarioCard({
  item,
  checked,
  disabled,
  onChange,
}: {
  item: Scenario;
  checked: boolean;
  disabled: boolean;
  onChange: () => void;
}) {
  const info = category(item.threat_class);
  return (
    <label
      className={`scenario-card ${checked ? "selected" : ""} ${disabled ? "disabled" : ""}`}
    >
      <div className="scenario-card-top">
        <Tag tone={info.color}>{info.short}</Tag>
        <input
          type="radio"
          name="scenario"
          value={item.id}
          checked={checked}
          disabled={disabled}
          onChange={onChange}
        />
      </div>
      <h3>{item.name}</h3>
      <p>{info.description}</p>
      <span className="scenario-meta">
        {count(item.packets)} packets <span>·</span> {number(item.duration_s)}s
        capture
      </span>
    </label>
  );
}

function Alerts({ engine }: { engine: Engine }) {
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const shown = useMemo(
    () =>
      engine.alerts.filter(
        (alert) =>
          (filter === "all" || alert.x_threat_class === filter) &&
          `${alert.name} ${alert.description} ${flowLabel(alert.x_flow_identifier)}`
            .toLowerCase()
            .includes(search.toLowerCase()),
      ),
    [engine.alerts, filter, search],
  );
  const active = shown.find((alert) => alert.id === selected) ?? shown[0];
  return (
    <>
      <PageHeading
        eyebrow="Explore the evidence"
        title="Every alert has a story."
      >
        See what looked suspicious, which connection was involved, and the
        signals behind the detection. Use the evidence to decide what to
        investigate.
      </PageHeading>
      {!USE_MOCK && (
        <div className="export-banner">
          <p>
            <strong>Alerts are saved automatically.</strong> Export the complete
            stored history, including records beyond the browser’s 400-alert
            window.
          </p>
          <div className="button-row">
            <a
              className="button primary"
              href="/api/alerts/export?format=json"
              download
            >
              Download JSON
            </a>
            <a
              className="button secondary"
              href="/api/alerts/export?format=jsonl"
              download
            >
              Download JSONL
            </a>
          </div>
        </div>
      )}
      <div className="alert-toolbar panel">
        <div>
          <label className="field-label" htmlFor="alert-search">
            Search alerts
          </label>
          <input
            id="alert-search"
            type="search"
            placeholder="Search a name, IP address, or description"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>
        <div>
          <label className="field-label" htmlFor="alert-category">
            Threat category
          </label>
          <select
            id="alert-category"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
          >
            <option value="all">All categories</option>
            {CATEGORIES.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </div>
        <span className="muted">{shown.length} shown</span>
      </div>
      <p className="section-note">
        The latest 400 loaded alerts may include previous replays. Capture
        timestamps describe recorded traffic. Scores express detector confidence
        and need context.
      </p>
      {shown.length === 0 ? (
        <section className="panel">
          <Empty
            title={
              engine.alerts.length
                ? "No alerts match your filters"
                : "No alerts to review yet"
            }
            icon="shield"
          >
            {engine.alerts.length ? (
              "Try a different category or clear the search."
            ) : (
              <>
                Start <a href="#/live">live monitoring</a> or run a sample on
                the <a href="#/demo">demo page</a> to see detections and their
                evidence.
              </>
            )}
          </Empty>
        </section>
      ) : (
        <div className="alert-layout">
          <section className="panel alert-list" aria-label="Alert results">
            {shown.map((alert) => (
              <button
                key={alert.id}
                className={`alert-row ${active?.id === alert.id ? "selected" : ""}`}
                aria-pressed={active?.id === alert.id}
                onClick={() => setSelected(alert.id)}
              >
                <div className="alert-row-top">
                  <Tag tone={alert.x_severity.toLowerCase()}>
                    {alert.x_severity}
                  </Tag>
                  <span>{alert.confidence}/100</span>
                </div>
                <h3>{alert.name}</h3>
                <p>{flowLabel(alert.x_flow_identifier)}</p>
                <div className="alert-row-foot">
                  <span>{category(alert.x_threat_class).short}</span>
                  <time dateTime={alert.created}>{date(alert.created)}</time>
                </div>
              </button>
            ))}
          </section>
          {active && <AlertDetail alert={active} />}
        </div>
      )}
      <section className="ledger-panel panel">
        <div>
          <h2>
            <Icon name="shield" size={20} />
            Alert record integrity
          </h2>
          <p>
            {!engine.ledger
              ? "Verification has not completed."
              : engine.ledger.ok && engine.ledger.anchors_ok
                ? `${count(engine.ledger.records)} stored records checked; the chain and available signatures passed.`
                : "Verification found a record-chain or signature problem. Investigate in the advanced view."}{" "}
            This checks record consistency, not detection correctness.
          </p>
        </div>
        <button
          className="button secondary"
          disabled={engine.ledgerBusy || !engine.apiUp}
          onClick={engine.verifyLedger}
        >
          {engine.ledgerBusy ? "Checking…" : "Check records"}
        </button>
      </section>
    </>
  );
}
function AlertDetail({ alert }: { alert: Alert }) {
  return (
    <article className="panel alert-detail" aria-label="Selected alert details">
      <div className="panel-top">
        <span className="eyebrow">Understanding this alert</span>
        <Tag tone={category(alert.x_threat_class).color}>
          {category(alert.x_threat_class).short}
        </Tag>
      </div>
      <h2>{alert.name}</h2>
      <p className="alert-description">{alert.description}</p>
      <div className="score-box">
        <div>
          <span>Detection score</span>
          <strong>
            {alert.confidence}
            <small>/100</small>
          </strong>
        </div>
        <p>
          {USE_MOCK
            ? "Illustrative sample score, generated in your browser."
            : alert.x_confidence_calibrated
              ? "A calibrated confidence score. Its reliability depends on how closely this traffic matches the calibration data."
              : "A rule or detector confidence score. It is not a calibrated probability."}{" "}
          This is not the model’s accuracy.
        </p>
      </div>
      <dl className="alert-facts">
        <div>
          <dt>Observed connection</dt>
          <dd className="mono">{flowLabel(alert.x_flow_identifier)}</dd>
        </div>
        <div>
          <dt>Protocol & visibility</dt>
          <dd>
            {alert.x_flow_identifier.proto} ·{" "}
            {alert.x_flow_identifier.completeness_flag
              ? "Both directions observed"
              : "Incomplete or one-way visibility"}
          </dd>
        </div>
        <div>
          <dt>Detector</dt>
          <dd>{alert.x_detector}</dd>
        </div>
        <div>
          <dt>Capture time</dt>
          <dd>{date(alert.created)}</dd>
        </div>
      </dl>
      {alert.x_detection_context.novelty && (
        <section className="notice" aria-label="Zero-Day Analysis">
          <Icon name="alert" />
          <div>
            <strong>Zero-Day Analysis — analyst review required</strong>
            <p>
              Decision: {alert.x_detection_context.novelty.decision}. Benign-tail fraction:{" "}
              {alert.x_detection_context.novelty.benign_tail_fraction}. This measures rarity against the approved
              baseline, not the probability of an attack or proof of a zero-day exploit.
            </p>
            <p>
              Evidence quality: {alert.x_detection_context.novelty.direction_coverage};{" "}
              {alert.x_detection_context.novelty.missing_fields.length} fields unavailable;{" "}
              {alert.x_detection_context.novelty.group_windows} related windows.
            </p>
          </div>
        </section>
      )}
      <h3 className="evidence-title">Why it was flagged</h3>
      <p className="field-help">
        These are the recorded signals supporting the alert. A signal on its own
        may also appear in normal traffic.
      </p>
      <div className="evidence-list">
        {alert.x_supporting_evidence.length ? (
          alert.x_supporting_evidence.slice(0, 6).map((item, index) => (
            <div className="evidence-item" key={`${item.feature}-${index}`}>
              <div>
                <strong>{item.feature.replace(/_/g, " ")}</strong>
                <p>{featureGloss(item.feature)}</p>
              </div>
              <span>{number(item.value)}</span>
            </div>
          ))
        ) : (
          <p className="muted">
            No feature evidence was attached to this alert.
          </p>
        )}
      </div>
      <details className="technical-details">
        <summary>Technical record & all evidence</summary>
        <p>
          Model: {alert.x_model_lineage.model_id} · Dataset:{" "}
          {alert.x_model_lineage.dataset_version}
        </p>
        <pre>{JSON.stringify(alert, null, 2)}</pre>
      </details>
      <SimpleCopilot alert={alert} />
    </article>
  );
}

type SimpleCopilotJob = {
  id: string;
  state: "queued" | "running" | "complete" | "failed" | "cancelled";
  result?: { briefing?: string } | null;
  error?: string | null;
};

function SimpleCopilot({ alert }: { alert: Alert }) {
  const [job, setJob] = useState<SimpleCopilotJob | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setJob(null);
    setError("");
  }, [alert.id]);

  useEffect(() => {
    if (!job || !["queued", "running"].includes(job.state)) return;
    const timer = window.setInterval(async () => {
      const response = await fetch(`/api/copilot/jobs/${encodeURIComponent(job.id)}`);
      if (response.ok) setJob((await response.json()) as SimpleCopilotJob);
      else setError("The copilot job could not be read.");
    }, 500);
    return () => window.clearInterval(timer);
  }, [job]);

  const explain = async () => {
    setError("");
    const response = await fetch("/api/copilot/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ intent: "explain_alert", alert_ids: [alert.id] }),
    });
    if (!response.ok) {
      setError("Offline SOC Copilot is unavailable or this role is not authorised.");
      return;
    }
    setJob((await response.json()) as SimpleCopilotJob);
  };

  return (
    <section className="technical-details" aria-label="Offline SOC Copilot">
      <h3>Offline SOC Copilot</h3>
      <p>Creates a bounded, evidence-linked explanation. It cannot change the alert or contact the monitored network.</p>
      <button className="button secondary" onClick={() => void explain()} disabled={job?.state === "queued" || job?.state === "running"}>
        {job?.state === "queued" || job?.state === "running" ? "Preparing explanation…" : "Explain this alert"}
      </button>
      {error && <p className="muted">{error}</p>}
      {job?.error && <p className="muted">{job.error}</p>}
      {job?.result?.briefing && <pre>{job.result.briefing}</pre>}
    </section>
  );
}

function Guide() {
  return (
    <>
      <PageHeading
        eyebrow="A quick field guide"
        title="Network security, in plain language."
      >
        A few concepts are enough to understand this prototype and give a clear,
        honest walkthrough.
      </PageHeading>
      <section className="guide-intro panel">
        <div>
          <Tag tone="teal">The 20-second explanation</Tag>
          <h2>It watches network patterns and explains suspicious activity.</h2>
          <p>
            Network Watch reads saved network traffic, groups related packets
            into flows, and checks their behavior using detection rules and
            machine-learning models. When it finds something suspicious, it
            creates an alert with supporting evidence.
          </p>
          <p>
            The dashboard is a window into that analysis. It helps a person
            investigate; it does not automatically block traffic.
          </p>
        </div>
        <Pipeline />
      </section>
      <div className="section-heading">
        <div>
          <span className="eyebrow">A simple walkthrough</span>
          <h2>Present it in three steps</h2>
        </div>
      </div>
      <div className="walkthrough-grid">
        {[
          {
            title: "Show a normal example",
            text: "On Run a demo, select the benign baseline. Explain that normal traffic is a useful comparison, and that false alarms also matter.",
          },
          {
            title: "Replay suspicious traffic",
            text: "Choose a SYN flood or another attack sample. Start the replay, then open Overview to show packet counts and any alerts.",
          },
          {
            title: "Explain one alert",
            text: "Open Alerts and select a result. Point to the observed connection, detection score, and evidence. Explain that confidence is not accuracy.",
          },
        ].map((step, index) => (
          <section className="panel walkthrough-card" key={step.title}>
            <span className="step-circle">{index + 1}</span>
            <h3>{step.title}</h3>
            <p>{step.text}</p>
          </section>
        ))}
      </div>
      <div className="guide-columns">
        <section>
          <div className="section-heading">
            <h2>The signals, explained</h2>
          </div>
          <div className="faq-list">
            {CATEGORIES.map((item) => (
              <details key={item.id}>
                <summary>{item.name}</summary>
                <p>
                  {item.description} The engine looks at{" "}
                  {item.signals.charAt(0).toLowerCase() + item.signals.slice(1)}
                </p>
              </details>
            ))}
          </div>
        </section>
        <section>
          <div className="section-heading">
            <h2>Words you’ll see</h2>
          </div>
          <dl className="glossary panel">
            {[
              {
                term: "Packet",
                detail: "One small unit of data crossing a network.",
              },
              {
                term: "Flow",
                detail:
                  "Related packets grouped into a conversation between network endpoints.",
              },
              {
                term: "Alert",
                detail:
                  "A suspicious observation worth reviewing. It is not proof of an attack.",
              },
              {
                term: "Detection score",
                detail:
                  "How strongly a detector rates one observation, shown on a 0–100 scale.",
              },
              {
                term: "Throughput",
                detail: "How much traffic the engine processes per second.",
              },
              {
                term: "p99 latency",
                detail:
                  "A processing-time threshold met by 99% of measured alerts. This excludes the full wait needed to collect a pattern.",
              },
            ].map((item) => (
              <div key={item.term}>
                <dt>{item.term}</dt>
                <dd>{item.detail}</dd>
              </div>
            ))}
          </dl>
        </section>
      </div>
      <section className="panel accuracy-explainer">
        <span className="eyebrow">Understanding quality</span>
        <h2>Confidence and accuracy answer different questions.</h2>
        <p>
          A detection score belongs to one alert. Precision, recall, and F1 need
          a labeled test set with known correct answers; replay counters cannot
          calculate them.
        </p>
        <div className="metric-explanations">
          <div>
            <h3>Precision</h3>
            <p>Of everything flagged, how much was actually malicious?</p>
          </div>
          <div>
            <h3>Recall</h3>
            <p>Of all real malicious examples, how many did we catch?</p>
          </div>
          <div>
            <h3>F1 score</h3>
            <p>A combined measure that balances precision and recall.</p>
          </div>
          <div>
            <h3>False-positive rate</h3>
            <p>Of the benign examples, how many were incorrectly flagged?</p>
          </div>
        </div>
        <p className="section-note">
          Use the project’s evaluation reports for measured model quality.
          Synthetic captures demonstrate behavior; they do not establish
          production accuracy. Encrypted traffic is analyzed through visible
          metadata, not decrypted content.
        </p>
      </section>
      <div className="learn-banner">
        <span className="round-icon">
          <Icon name="book" size={26} />
        </span>
        <div>
          <h2>Keep the full walkthrough handy.</h2>
          <p>
            The Markdown guide includes setup, page instructions,
            troubleshooting, and a presentation script.
          </p>
        </div>
        <a className="button primary" href={GUIDE_URL} download>
          Download guide <Icon name="arrow" size={16} />
        </a>
      </div>
    </>
  );
}
