import { Area, AreaChart, CartesianGrid, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { MetricsSnapshot } from "../api";
import type { HistoryPoint } from "../useEngine";
import { chartColours, formatCount, percent, tooltipStyle, type Theme } from "../threats";
import Panel from "./Panel";
import Stat from "./Stat";

const TIERS: Record<string, string> = {
  none: "nothing shed, every frame reaches the dashboard",
  "drop-metrics": "oldest metrics frames dropped first, status and alerts still delivered",
  "alerts-only": "notifications may be dropped; alerts remain in storage and the browser resynchronises",
};

type Props = { metrics: MetricsSnapshot | null; history: HistoryPoint[]; theme: Theme };

export default function QueuePanel({ metrics, history, theme }: Props) {
  const colours = chartColours(theme);
  const queue = metrics?.queue;
  const data = history.map((p) => ({ t: Number(p.t.toFixed(1)), depth: p.queue_depth }));
  const fill = queue && queue.capacity ? queue.depth / queue.capacity : 0;
  const tier = queue?.shedding_tier ?? "none";
  const tone = tier === "none" ? undefined : tier === "alerts-only" ? "danger" : "warn";

  return (
    <Panel
      title="Queue depth and load shedding"
      caption="The bounded queue between the engine and the dashboard, and what gets dropped when it fills."
      tip={
        "One fixed-size notification queue sits between the engine and " +
        "the websocket, and when it fills it sheds in a stated order rather than growing memory: the oldest " +
        "metrics frames go first, then status frames, then alert notifications. " +
        "Alert records are stored before notification. The browser refreshes recent history after a delivery gap. " +
        "Anything dropped is counted here and stamped on the alerts raised at the time."
      }
      right={<span className={tier === "none" ? "badge ok" : "badge warn"}>shedding: {tier}</span>}
    >
      <div className="stats">
        <Stat label="Queue depth" value={queue ? String(queue.depth) : "0"} sub={`of ${queue?.capacity ?? 0} slots`} />
        <Stat label="Fill" value={percent(fill, 0)} tone={tone} sub="of capacity" />
        <Stat
          label="Dropped"
          value={queue ? formatCount(queue.dropped) : "0"}
          tone={queue && queue.dropped > 0 ? "warn" : undefined}
          sub="events shed this run"
        />
      </div>
      <div className="chart" style={{ height: 180 }}>
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
                width={48}
                domain={[0, queue?.capacity ?? "auto"]}
              />
              <Tooltip
                contentStyle={tooltipStyle(colours)}
                labelStyle={{ color: colours.text }}
                itemStyle={{ color: colours.text }}
                formatter={(value) => `${Number(value)} queued`}
                labelFormatter={(label) => "t plus " + label + " s"}
              />
              <Area
                type="monotone"
                dataKey="depth"
                name="queue depth"
                stroke={colours.series[1]}
                strokeWidth={2}
                fill={colours.series[1]}
                fillOpacity={0.16}
                isAnimationActive={false}
              />
              {queue && (
                <ReferenceLine
                  y={queue.capacity}
                  stroke={colours.danger}
                  strokeDasharray="4 4"
                  label={{ value: "capacity", position: "insideTopRight", fill: colours.danger, fontSize: 11 }}
                />
              )}
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="empty">Start a replay to watch the queue.</div>
        )}
      </div>
      <div className="caption">
        Current tier: {TIERS[tier] ?? tier}. Drop policy as the engine states it: {queue?.policy ?? "not reported"}.
      </div>
    </Panel>
  );
}
