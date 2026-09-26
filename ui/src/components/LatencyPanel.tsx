import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { MetricsSnapshot } from "../api";
import { chartColours, formatCount, formatMs, tooltipStyle, type Theme } from "../threats";
import Panel from "./Panel";
import Stat from "./Stat";

type Props = { metrics: MetricsSnapshot | null; theme: Theme };

export default function LatencyPanel({ metrics, theme }: Props) {
  const colours = chartColours(theme);
  const buckets = metrics?.latency_histogram ?? [];
  const quantiles = metrics?.latency_ms;
  const measured = (metrics?.alerts ?? 0) > 0;
  const histogram = buckets.length > 0;

  // the engine reports a running total, so differentiate it back into per-bucket counts
  const bars = buckets.map((bucket, index) => ({
    label: `<= ${bound(bucket.le_ms)} ms`,
    count: Math.max(0, bucket.count - (index > 0 ? buckets[index - 1].count : 0)),
  }));
  const quantileBars = quantiles
    ? [
        { label: "p50", count: quantiles.p50 },
        { label: "p95", count: quantiles.p95 },
        { label: "p99", count: quantiles.p99 },
        { label: "p999", count: quantiles.p999 },
      ]
    : [];
  const data = !measured ? [] : histogram ? bars : quantileBars;

  return (
    <Panel
      title="Wire-to-alert latency"
      caption={
        histogram
          ? "How long a packet takes to become an alert, counted into buckets."
          : "Quantiles only. This run has not produced a bucketed histogram yet."
      }
      tip={
        "Latency is measured from the packet's own capture timestamp to the moment the alert record is written, " +
        "not from the start of feature extraction. That is the number an operator actually feels. " +
        "Read the tail, not the median: p99 is the promise you can keep, p50 is the one you cannot."
      }
    >
      <div className="stats">
        <Stat label="p50" value={measured ? formatMs(quantiles?.p50) : "n/a"} sub={sub(measured, "typical")} />
        <Stat label="p95" value={measured ? formatMs(quantiles?.p95) : "n/a"} sub={sub(measured, "most alerts")} />
        <Stat label="p99" value={measured ? formatMs(quantiles?.p99) : "n/a"} sub={sub(measured, "slow tail")} />
        <Stat
          label="p999"
          value={measured ? formatMs(quantiles?.p999) : "n/a"}
          sub={sub(measured, "worst thousandth")}
        />
      </div>
      <div className="chart" style={{ height: 200 }}>
        {data.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 12, right: 12, bottom: 0, left: 4 }}>
              <CartesianGrid stroke={colours.grid} vertical={false} />
              <XAxis dataKey="label" stroke={colours.axis} tick={{ fontSize: 11 }} tickLine={false} />
              <YAxis stroke={colours.axis} tick={{ fontSize: 11 }} tickLine={false} width={54} />
              <Tooltip
                cursor={{ fill: colours.grid, opacity: 0.3 }}
                contentStyle={tooltipStyle(colours)}
                labelStyle={{ color: colours.text }}
                itemStyle={{ color: colours.text }}
                formatter={(value) => (histogram ? formatCount(Number(value)) + " alerts" : formatMs(Number(value)))}
              />
              <Bar
                dataKey="count"
                name={histogram ? "alerts" : "latency"}
                fill={colours.cool}
                radius={[4, 4, 0, 0]}
                isAnimationActive={false}
              />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="empty">Start a replay to measure latency.</div>
        )}
      </div>
    </Panel>
  );
}

function bound(ms: number): string {
  return ms < 1 ? ms.toFixed(2) : ms.toFixed(1);
}

function sub(measured: boolean, text: string): string {
  return measured ? text : "no alerts measured yet";
}
