type Props = { values: number[]; colour: string; height?: number; label?: string };

const W = 300;

export default function Sparkline({ values, colour, height = 44, label }: Props) {
  if (values.length < 2) {
    return <div className="sparkline empty" style={{ height }} aria-hidden="true" />;
  }
  const max = Math.max(...values);
  const min = Math.min(...values);
  const span = max - min || 1;
  const step = W / (values.length - 1);
  const y = (v: number) => height - 4 - ((v - min) / span) * (height - 8);
  const points = values.map((v, i) => `${(i * step).toFixed(2)},${y(v).toFixed(2)}`);
  const area = `M0,${height} L${points.join(" L")} L${W},${height} Z`;

  return (
    <svg
      className="sparkline"
      viewBox={`0 0 ${W} ${height}`}
      preserveAspectRatio="none"
      style={{ height }}
      role="img"
      aria-label={label ?? "trend"}
    >
      <path d={area} fill={colour} opacity="0.14" />
      <polyline
        points={points.join(" ")}
        fill="none"
        stroke={colour}
        strokeWidth="2"
        strokeLinejoin="round"
        strokeLinecap="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  );
}
