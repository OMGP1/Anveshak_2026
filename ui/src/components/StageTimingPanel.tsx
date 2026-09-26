import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { MetricsSnapshot } from "../api";
import { chartColours, tooltipStyle, type Theme } from "../threats";
import Panel from "./Panel";

const ORDER = ["decode", "flow_table", "features", "tier1", "tier2", "alert"];

const LABELS: Record<string, string> = {
  decode: "Decode headers",
  flow_table: "Flow table update",
  features: "Feature extraction",
  tier1: "Tier 1 model",
  tier2: "Tier 2 model",
  alert: "Alert build and ledger",
};

type Props = { metrics: MetricsSnapshot | null; theme: Theme };

export default function StageTimingPanel({ metrics, theme }: Props) {
  const colours = chartColours(theme);
  const timing = metrics?.stage_timing_us ?? {};
  // the engine reports aggregates that overlap these stages, so summing all double counts
  const stages = ORDER.filter((key) => typeof timing[key] === "number");
  const total = stages.reduce((sum, key) => sum + timing[key], 0);
  const skipped = Object.keys(timing).filter((key) => !(key in LABELS));
  const data = stages.map((key) => ({ stage: LABELS[key], us: timing[key] }));

  return (
    <Panel
      title="Per-stage timing"
      caption="Mean microseconds one packet spends in each stage of the pipeline."
      tip={
        "This is where the latency budget goes. The stages run in order: headers are decoded, the flow table is " +
        "updated, features are computed from sketches, then the models score. " +
        "Payload never enters any of these stages, which is how constraint C-b is enforced structurally."
      }
      right={<span className="chip">{total.toFixed(1)} us per packet</span>}
    >
      <div className="chart" style={{ height: 240 }}>
        {data.length > 0 ? (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ top: 4, right: 16, bottom: 0, left: 4 }}>
              <CartesianGrid stroke={colours.grid} horizontal={false} />
              <XAxis type="number" stroke={colours.axis} tick={{ fontSize: 11 }} tickLine={false} unit=" us" />
              <YAxis
                type="category"
                dataKey="stage"
                stroke={colours.axis}
                tick={{ fontSize: 11 }}
                tickLine={false}
                width={140}
              />
              <Tooltip
                cursor={{ fill: colours.grid, opacity: 0.3 }}
                contentStyle={tooltipStyle(colours)}
                labelStyle={{ color: colours.text }}
                itemStyle={{ color: colours.text }}
                formatter={(value) => `${Number(value).toFixed(2)} us`}
              />
              <Bar
                dataKey="us"
                name="mean time"
                fill={colours.series[2]}
                radius={[0, 4, 4, 0]}
                isAnimationActive={false}
              />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="empty">Start a replay to see the breakdown.</div>
        )}
      </div>
      {skipped.length > 0 && (
        <div className="caption">
          The engine also reports the aggregate counters {skipped.join(", ")}, which span several of these stages.
          They are left out so the per-packet total is a real sum and not a double count.
        </div>
      )}
    </Panel>
  );
}
