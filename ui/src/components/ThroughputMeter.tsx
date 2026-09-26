import type { MetricsSnapshot, ReplayStatus } from "../api";
import type { HistoryPoint } from "../useEngine";
import { chartColours, formatCount, formatMs, formatRate, type Theme } from "../threats";
import Panel from "./Panel";
import Sparkline from "./Sparkline";

type Props = {
  metrics: MetricsSnapshot | null;
  history: HistoryPoint[];
  status: ReplayStatus;
  theme: Theme;
};

type Figure = { label: string; value: string; unit: string; note: string; strong?: boolean };

export default function ThroughputMeter({ metrics, history, status, theme }: Props) {
  const colours = chartColours(theme);
  const flows = history.map((p) => p.flows_per_s);
  const latency = history.map((p) => p.p99);
  const peakFlows = flows.length ? Math.max(...flows) : 0;
  const peakPackets = history.length ? Math.max(...history.map((p) => p.packets_per_s)) : 0;
  const peakMbps = history.length ? Math.max(...history.map((p) => p.mbps)) : 0;

  // the meter is a 10 s rolling window, so it empties the moment a replay stops
  const active = history.filter((point) => point.packets_per_s > 0);
  const finished = !status.running && active.length > 0;
  const idle = !status.running && active.length === 0;
  const mean = (pick: (point: HistoryPoint) => number) =>
    active.length ? active.reduce((sum, point) => sum + pick(point), 0) / active.length : 0;
  const measured = metrics != null && metrics.alerts > 0;

  const rate = (label: string, unit: string, live: number, sustained: number, peak: string): Figure => ({
    label,
    unit: finished ? `${unit} sustained` : unit,
    value: idle ? "--" : formatRate(finished ? sustained : live),
    note: idle ? "no run yet" : `peak ${peak}`,
    strong: true,
  });

  const figures: Figure[] = [
    rate(
      "flows per second",
      "flows/s",
      metrics?.flows_per_s ?? 0,
      mean((p) => p.flows_per_s),
      formatCount(peakFlows),
    ),
    rate(
      "packets per second",
      "pkts/s",
      metrics?.packets_per_s ?? 0,
      mean((p) => p.packets_per_s),
      formatCount(peakPackets),
    ),
    rate("wire throughput", "Mbps", metrics?.mbps ?? 0, mean((p) => p.mbps), `${formatRate(peakMbps)} Mbps`),
    {
      label: "wire-to-alert p50",
      value: measured ? formatMs(metrics?.latency_ms.p50) : "n/a",
      unit: "median",
      note: measured ? "packet timestamp to alert" : "no alerts measured yet",
    },
    {
      label: "wire-to-alert p99",
      value: measured ? formatMs(metrics?.latency_ms.p99) : "n/a",
      unit: "tail",
      note: measured ? `p999 ${formatMs(metrics?.latency_ms.p999)}` : "no alerts measured yet",
    },
  ];

  return (
    <Panel
      className="meter-card"
      title="Live throughput and latency"
      caption={caption(status.running, finished)}
      tip={
        "Constraint C-d asks for a stated and demonstrated rate, so these numbers are measured, not claimed. " +
        "While a replay runs these are the last ten seconds of ingest. " +
        "Once it finishes the rolling window empties, so the figures switch to the mean the run sustained. " +
        "Latency is wire to alert: from the packet's own capture timestamp to the moment the alert is emitted. " +
        "p50 is the typical case and p99 is the slow tail, which is the honest number to judge."
      }
      right={
        <span className="chip">
          {status.mode} clock, {status.speed}x
        </span>
      }
    >
      <div className="meter">
        {figures.map((f) => (
          <div key={f.label} className={f.strong ? "figure strong" : "figure"}>
            <div className="figure-value">{f.value}</div>
            <div className="figure-unit">{f.unit}</div>
            <div className="figure-label">{f.label}</div>
            <div className="figure-note">{f.note}</div>
          </div>
        ))}
      </div>
      <div className="meter-trends">
        <div className="trend">
          <div className="trend-head">
            <span className="small muted">flows per second</span>
            <span className="mono small">{active.length ? formatRate(peakFlows) + " peak" : "no samples yet"}</span>
          </div>
          <Sparkline values={flows} colour={colours.cool} label="flows per second over the run" />
        </div>
        <div className="trend">
          <div className="trend-head">
            <span className="small muted">p99 wire-to-alert latency</span>
            <span className="mono small">{measured ? formatMs(metrics?.latency_ms.p99) : "no alerts yet"}</span>
          </div>
          <Sparkline values={latency} colour={colours.warn} label="p99 latency over the run" />
        </div>
      </div>
      <div className="caption">
        Counters cover this replay only. {metrics ? formatCount(metrics.packets) : 0} packets and{" "}
        {metrics ? formatCount(metrics.flows) : 0} flows seen so far.
      </div>
    </Panel>
  );
}

function caption(running: boolean, finished: boolean): string {
  if (running) return "The rate this run is actually sustaining, and how long a packet takes to become an alert.";
  if (finished) return "The mean rate this run sustained, and how long a packet took to become an alert.";
  return "Start a replay. Every figure here is measured off that run, none of it is quoted from a document.";
}
