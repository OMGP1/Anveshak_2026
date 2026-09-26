import { threat, threatColour, type Theme } from "../threats";

type Props = { id: string; theme: Theme; short?: boolean };

export default function ThreatBadge({ id, theme, short }: Props) {
  const info = threat(id);
  return (
    <span className="badge threat" title={info.label}>
      <span className="swatch" style={{ background: threatColour(id, theme) }} />
      {short ? info.short : info.label}
    </span>
  );
}
