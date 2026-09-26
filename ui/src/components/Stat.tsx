import InfoTip from "./InfoTip";

type Props = {
  label: string;
  value: string;
  sub?: string;
  tone?: "ok" | "warn" | "danger";
  tip?: string;
};

export default function Stat({ label, value, sub, tone, tip }: Props) {
  return (
    <div className={tone ? `stat ${tone}` : "stat"}>
      <div className="label" title={label}>
        {label}
        {tip ? <InfoTip title={label} text={tip} /> : null}
      </div>
      <div className="value" title={value}>
        {value}
      </div>
      {sub ? <div className="stat-sub">{sub}</div> : null}
    </div>
  );
}
