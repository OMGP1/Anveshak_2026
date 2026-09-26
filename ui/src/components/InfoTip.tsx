import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";

type Props = { title: string; text: string };

export default function InfoTip({ title, text }: Props) {
  const [open, setOpen] = useState(false);
  const [alignRight, setAlignRight] = useState(false);
  const root = useRef<HTMLSpanElement>(null);
  const popover = useRef<HTMLDivElement>(null);
  const id = useId();

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    const onClick = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("mousedown", onClick);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("mousedown", onClick);
    };
  }, [open]);

  // hang from the right edge when the popover would run off the viewport
  useLayoutEffect(() => {
    if (!open || !popover.current) return;
    const rect = popover.current.getBoundingClientRect();
    setAlignRight(rect.right > window.innerWidth - 8);
  }, [open]);

  return (
    <span className="info-tip" ref={root}>
      <button
        type="button"
        className="info-tip-button"
        aria-label={`About ${title}`}
        aria-expanded={open}
        aria-controls={id}
        onClick={() => setOpen((o) => !o)}
      >
        ?
      </button>
      {open && (
        <div
          id={id}
          ref={popover}
          role="dialog"
          aria-label={title}
          className={alignRight ? "info-tip-popover right" : "info-tip-popover"}
        >
          <div className="info-tip-title">{title}</div>
          <div className="info-tip-text">{text}</div>
        </div>
      )}
    </span>
  );
}
