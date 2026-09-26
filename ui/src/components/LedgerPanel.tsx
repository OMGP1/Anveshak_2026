import type { LedgerVerdict } from "../api";
import { formatCount } from "../threats";
import Panel from "./Panel";
import Stat from "./Stat";

type Props = { ledger: LedgerVerdict | null; busy: boolean; onVerify: () => void };

const ANCHOR_EVERY = 100;

export default function LedgerPanel({ ledger, busy, onVerify }: Props) {
  const broken = ledger != null && !ledger.ok;
  const anchors = ledger?.anchors ?? [];
  const anchored = anchors.length > 0;

  return (
    <Panel
      className={broken ? "alerting" : undefined}
      title="Alert ledger"
      caption="Every alert is appended to a hash-chained file. Verify walks the chain and names the first break."
      tip={
        "The problem statement's own background asks for a clean chain of custody. " +
        "Each record stores the hash of the record before it, so changing any past alert changes every hash after " +
        "it. Verify recomputes the whole chain and checks the periodic signed anchors. " +
        "Try it: edit one byte in the ledger file, press Verify, and it will name the exact record that broke. " +
        "The chain catches an edit or a reorder anywhere. Only a signed anchor bounds a deletion from the tail, " +
        "so the anchor interval is the granularity of that guarantee."
      }
      right={
        <button type="button" className="button primary" onClick={onVerify} disabled={busy}>
          {busy ? "Verifying..." : "Verify chain"}
        </button>
      }
    >
      <div className="stats">
        <Stat label="Records" value={ledger ? formatCount(ledger.records) : "0"} sub="alerts written" />
        <Stat
          label="Chain"
          value={ledger ? (ledger.ok ? "PASS" : `BROKEN at ${ledger.broken_at}`) : "not checked"}
          tone={ledger ? (ledger.ok ? "ok" : "danger") : undefined}
          sub={ledger?.ok ? "every hash recomputes" : "record index of the first mismatch"}
        />
        <Stat
          label="Signed anchors"
          value={anchorValue(ledger, anchored)}
          tone={ledger && anchored ? (ledger.anchors_ok ? "ok" : "danger") : undefined}
          sub={
            ledger && !anchored
              ? `one anchor per ${ANCHOR_EVERY} records, the chain holds ${ledger.records}`
              : "Ed25519 over the chain head"
          }
        />
      </div>
      <div className="kv">
        <div>
          <span>Chain head</span>
          <b className="mono wrap">{ledger?.head ?? "not checked"}</b>
        </div>
        <div>
          <span>Signing key</span>
          <b>{ledger?.key_source ?? "not checked"}</b>
        </div>
      </div>
    </Panel>
  );
}

function anchorValue(ledger: LedgerVerdict | null, anchored: boolean): string {
  if (!ledger) return "not checked";
  if (!anchored) return "none written yet";
  return ledger.anchors_ok ? `${ledger.anchors?.length ?? 0} valid` : "invalid";
}
