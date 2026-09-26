import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { MetricsSnapshot } from "../api";
import type { HistoryPoint } from "../useEngine";
import { chartColours, formatCount, formatMB, percent, tooltipStyle, type Theme } from "../threats";
import Panel from "./Panel";

const ORDER = ["flow_table", "beacon_table", "sketches", "models"];

const LABELS: Record<string, string> = {
  flow_table: "Flow table",
  beacon_table: "Beacon table",
  sketches: "Sketches (CMS, HLL, entropy)",
  models: "Models",
};

type Props = { metrics: MetricsSnapshot | null; history: HistoryPoint[]; theme: Theme };

export default function MemoryPanel({ metrics, history, theme }: Props) {
  const colours = chartColours(theme);
  const measured = metrics?.memory_bytes ?? {};
  const caps = metrics?.memory_caps_bytes ?? {};
  const keys = [...ORDER.filter((k) => k in measured), ...Object.keys(measured).filter((k) => !ORDER.includes(k))];
  const capTotal = Object.values(caps).reduce((a, b) => a + b, 0);
  const used = Object.values(measured).reduce((a, b) => a + b, 0);

  const data = history.map((point) => {
    const row: Record<string, number> = { t: Number(point.t.toFixed(1)) };
    for (const key of keys) row[key] = (point.memory[key] ?? 0) / (1024 * 1024);
    return row;
  });

  // scaled to what is in use: at 3 percent of the cap the bands read as a flat line
  const capMB = capTotal / (1024 * 1024);
  const peakMB = data.reduce((top, row) => Math.max(top, keys.reduce((sum, key) => sum + row[key], 0)), 0);
  const axisMax = Math.max(1, Math.ceil(Math.max(peakMB * 1.6, capMB * 0.15)));

  return (
    <Panel
      title="Memory per bounded structure"
      caption="Configured state estimates. Process RSS also includes libraries and temporary analysis memory."
      tip={
        "Constraint C-c asks for streaming with bounded state. Each band is one data structure measured in " +
        "megabytes, stacked so the top edge is the total. The axis is scaled to what is in use, and the sum of " +
        "the configured caps is in the header chip and the table below. " +
        "The point of this chart is what does not happen: run the SYN flood and the total stays flat, " +
        "because the flow table is a fixed-size LRU and the sketches never grow with cardinality."
      }
      right={
        <span className="chip">
          <b>{formatMB(used)}</b> of {formatMB(capTotal)} cap
        </span>
      }
    >
      {metrics?.analysis_limits && <p role="status">
        Beacon windows skipped: {metrics.analysis_limits.beacon_windows_skipped}
        {" "}(timing-grid limit: {metrics.analysis_limits.beacon_event_bin_limit} bins).
        {" "}Late rate packets skipped: {metrics.analysis_limits.late_rate_packets_skipped}.
        {" "}Rate baselines evicted: {metrics.analysis_limits.rate_monitors_evicted}.
        {" "}Skipped analysis is not a benign classification.
      </p>}
      {metrics?.analysis_limits && <p>
        Packet-size/timing assessments: {metrics.analysis_limits.encrypted_sequence_updates ?? 0}.
        {" "}UDP/443 assessments: {metrics.analysis_limits.udp443_sequence_updates ?? 0}
        {" "}(possible QUIC; metadata only, malware classification unvalidated).
        {" "}Model predictions withheld for insufficient evidence: {metrics.analysis_limits.model_candidates_without_support ?? 0}.
      </p>}
      <div className="chart" style={{ height: 260 }}>
        {data.length > 1 ? (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: 4 }}>
              <CartesianGrid stroke={colours.grid} vertical={false} />
              <XAxis
                dataKey="t"
                type="number"
                domain={["dataMin", "dataMax"]}
                stroke={colours.axis}
                tick={{ fontSize: 11 }}
                tickLine={false}
                unit="s"
                minTickGap={28}
              />
              <YAxis
                stroke={colours.axis}
                tick={{ fontSize: 11 }}
                tickLine={false}
                width={54}
                unit=" MB"
                domain={[0, axisMax]}
              />
              <Tooltip
                contentStyle={tooltipStyle(colours)}
                labelStyle={{ color: colours.text }}
                itemStyle={{ color: colours.text }}
                formatter={(value) => `${Number(value).toFixed(1)} MB`}
                labelFormatter={(label) => "t plus " + label + " s"}
              />
              {keys.map((key, index) => (
                <Area
                  key={key}
                  type="monotone"
                  dataKey={key}
                  name={LABELS[key] ?? key}
                  stackId="mem"
                  stroke={colours.surface}
                  strokeWidth={1.5}
                  fill={colours.series[index % colours.series.length]}
                  fillOpacity={0.85}
                  isAnimationActive={false}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="empty">Start a replay to watch memory settle.</div>
        )}
      </div>

      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Structure</th>
              <th className="num">Measured</th>
              <th className="num">Configured cap</th>
              <th className="num">Of cap</th>
              <th>Bound by</th>
            </tr>
          </thead>
          <tbody>
            {keys.map((key) => (
              <tr key={key}>
                <td>
                  <span className="row-swatch">
                    <span
                      className="swatch"
                      style={{ background: colours.series[keys.indexOf(key) % colours.series.length] }}
                    />
                    {LABELS[key] ?? key}
                  </span>
                </td>
                <td className="num mono">{formatMB(measured[key] ?? 0)}</td>
                <td className="num mono">{caps[key] ? formatMB(caps[key]) : "n/a"}</td>
                <td className="num mono">{caps[key] ? percent((measured[key] ?? 0) / caps[key], 0) : "n/a"}</td>
                <td className="small muted">{BOUND[key] ?? "fixed allocation"}</td>
              </tr>
            ))}
            <tr>
              <td>
                <b>Total</b>
              </td>
              <td className="num mono">
                <b>{formatMB(used)}</b>
              </td>
              <td className="num mono">{formatMB(capTotal)}</td>
              <td className="num mono">{capTotal ? percent(used / capTotal, 0) : "n/a"}</td>
              <td className="small muted">process RSS {metrics ? metrics.rss_mb.toFixed(0) : "0"} MB</td>
            </tr>
          </tbody>
        </table>
      </div>
      <div className="caption">
        Headroom: {formatMB(used)} of {formatMB(capTotal)} configured, {percent(capTotal ? used / capTotal : 0, 1)}{" "}
        of the bound. Flow table holds {metrics ? formatCount(metrics.flow_table_entries) : 0} live flows. Entries
        beyond the cap evict the least recently used flow rather than growing the table.
      </div>
    </Panel>
  );
}

const BOUND: Record<string, string> = {
  flow_table: "LRU with a hard entry cap and an idle timeout",
  beacon_table: "separate TTL and cap, allocated only for flows passing the pre-filter",
  sketches: "fixed-width count-min and HyperLogLog, size independent of cardinality",
  models: "loaded once at start",
};
