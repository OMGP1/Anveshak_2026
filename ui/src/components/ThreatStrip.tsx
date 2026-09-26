import { THREATS, threatColour, activateOnEnter, type Theme } from "../threats";
import Panel from "./Panel";

type Props = {
  counts: Record<string, number>;
  theme: Theme;
  selected: string | null;
  onSelect: (id: string | null) => void;
};

export default function ThreatStrip({ counts, theme, selected, onSelect }: Props) {
  const total = THREATS.reduce((sum, t) => sum + (counts[t.id] ?? 0), 0);

  return (
    <Panel
      title="Threat and novelty alerts this session"
      caption="Six known classes plus unknown/unusual behaviour for analyst review. Click a tile to filter."
      tip={
        "The six known classes retain their existing model contract; unknown/unusual is a separate alert-only taxonomy. " +
        "These are the alert counts for this replay only, not a historic total. " +
        "A tile at zero means nothing crossed threshold for that class, which is the expected result on benign traffic."
      }
      right={
        selected ? (
          <button type="button" className="button small" onClick={() => onSelect(null)}>
            Clear filter
          </button>
        ) : (
          <span className="chip">
            <b>{total}</b> alerts
          </span>
        )
      }
    >
      <div className="threat-strip">
        {THREATS.map((t) => {
          const count = counts[t.id] ?? 0;
          const share = total ? count / total : 0;
          const active = selected === t.id;
          const choose = () => onSelect(active ? null : t.id);
          return (
            <div
              key={t.id}
              className={active ? "threat-tile active" : "threat-tile"}
              role="button"
              tabIndex={0}
              aria-pressed={active}
              onClick={choose}
              onKeyDown={activateOnEnter(choose)}
              title={t.signal}
            >
              <div className="threat-tile-head">
                <span className="swatch" style={{ background: threatColour(t.id, theme) }} />
                <span className="threat-tile-letter mono">{t.letter}</span>
              </div>
              <div className="threat-tile-count">{count}</div>
              <div className="threat-tile-label">{t.label}</div>
              <div className="threat-tile-bar">
                <div style={{ width: `${share * 100}%`, background: threatColour(t.id, theme) }} />
              </div>
              <div className="threat-tile-signal">{t.signal}</div>
            </div>
          );
        })}
      </div>
    </Panel>
  );
}
