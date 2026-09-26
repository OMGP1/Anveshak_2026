import type { ReactNode } from "react";
import InfoTip from "./InfoTip";

type Props = {
  title: string;
  caption: string;
  tip: string;
  right?: ReactNode;
  className?: string;
  children: ReactNode;
};

export default function Panel({ title, caption, tip, right, className, children }: Props) {
  return (
    <section className={className ? `card ${className}` : "card"}>
      <div className="card-title">
        <div className="panel-heading">
          <h2>{title}</h2>
          <InfoTip title={title} text={tip} />
        </div>
        {right ? <div className="panel-actions">{right}</div> : null}
      </div>
      <div className="caption">{caption}</div>
      {children}
    </section>
  );
}
