import type { MouseEvent } from "react";
import { activateOnEnter, formatTime } from "../threats";

export type ToastInput = {
  kind: "alert" | "info";
  title: string;
  body?: string;
  host?: string;
  at?: string;
  alertId?: string;
};

export type Toast = ToastInput & { id: number };

type Props = {
  toasts: Toast[];
  onDismiss: (id: number) => void;
  onInvestigate: (alertId: string) => void;
};

export default function Toasts({ toasts, onDismiss, onInvestigate }: Props) {
  if (toasts.length === 0) return null;
  return (
    <div className="toasts" aria-live="polite">
      {toasts.map((toast) => {
        const target = toast.alertId ?? null;
        const open = () => {
          if (!target) return;
          onInvestigate(target);
          onDismiss(toast.id);
        };
        const close = (e: MouseEvent) => {
          e.stopPropagation();
          onDismiss(toast.id);
        };
        return (
          <div
            key={toast.id}
            className={`toast ${toast.kind}${target ? " clickable" : ""}`}
            role={target ? "button" : undefined}
            tabIndex={target ? 0 : undefined}
            onClick={target ? open : undefined}
            onKeyDown={target ? activateOnEnter(open) : undefined}
          >
            <div className="toast-body">
              <div className="toast-title">{toast.title}</div>
              {toast.body && <div className="toast-text">{toast.body}</div>}
              {toast.host && toast.at && (
                <div className="toast-meta mono">
                  {toast.host} at {formatTime(toast.at)}
                  {target ? ", click to open the evidence" : ""}
                </div>
              )}
            </div>
            <button type="button" className="toast-close" aria-label="Dismiss" onClick={close}>
              x
            </button>
          </div>
        );
      })}
    </div>
  );
}
