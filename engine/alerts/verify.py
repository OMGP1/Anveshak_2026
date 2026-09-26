from __future__ import annotations

import json
import os
import sys

from engine.alerts.ledger import anchor_paths, chain_hash, verify_anchor
from engine.alerts.schema import GENESIS_HASH

USAGE = "usage: python -m engine.alerts.verify <alerts.jsonl>"


def load_pubkey(pub_path: str) -> str | None:
    if not os.path.exists(pub_path):
        return None
    with open(pub_path, "r", encoding="ascii") as handle:
        text = handle.read().strip()
    return text or None


def _walk_records(path: str) -> tuple[int, int | None, str, str, dict[int, str]]:
    prev, index, broken_at, reason = GENESIS_HASH, 0, None, ""
    heads: dict[int, str] = {}
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            if not line.endswith("\n"):
                return index, index + 1, "unterminated ledger record", prev, heads
            try:
                entry = json.loads(line)
            except ValueError as exc:
                return index, index + 1, "line is not valid JSON (%s)" % exc, prev, heads
            problem = _check_entry(entry, prev)
            if problem:
                return index, index + 1, problem, prev, heads
            prev = entry["hash"]
            index += 1
            heads[index] = prev
    return index, broken_at, reason, prev, heads


def _check_entry(entry: object, prev: str) -> str:
    if not isinstance(entry, dict):
        return "line is not a ledger entry"
    for field in ("record", "prev_hash", "hash"):
        if field not in entry:
            return "line is missing %r" % field
    if entry["prev_hash"] != prev:
        return "prev_hash does not match the previous line"
    record = entry["record"]
    if not isinstance(record, dict):
        return "record is not an object"
    if record.get("x_prev_hash", prev) != prev:
        return "record x_prev_hash does not match the chain"
    if chain_hash(record, entry["prev_hash"]) != entry["hash"]:
        return "record content does not match its hash"
    return ""


def _check_anchors(anchors_path: str, pubkey: str | None, heads: dict[int, str]) -> tuple[list[dict], bool]:
    results: list[dict] = []
    if not os.path.exists(anchors_path):
        return results, True
    ok = True
    with open(anchors_path, "r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                anchor = json.loads(line)
            except ValueError:
                results.append({"count": None, "signature_ok": False, "head_ok": False})
                ok = False
                continue
            signature_ok = verify_anchor(anchor, pubkey)
            head_ok = heads.get(anchor.get("count")) == anchor.get("chain_head")
            results.append({"count": anchor.get("count"), "signature_ok": signature_ok, "head_ok": head_ok})
            ok = ok and signature_ok and head_ok
    return results, ok


def verify_chain(path: str) -> dict:
    anchors_path, _key_path, pub_path = anchor_paths(path)
    if not os.path.exists(path):
        return {"ok": False, "records": 0, "broken_at": None, "anchors_ok": False, "anchors": [],
                "head": GENESIS_HASH, "reason": "ledger file not found", "path": path, "key_source": "none"}
    records, broken_at, reason, head, heads = _walk_records(path)
    pubkey = load_pubkey(pub_path)
    anchors, anchors_ok = _check_anchors(anchors_path, pubkey, heads)
    return {
        "ok": broken_at is None,
        "records": records,
        "records_in_file": _count_lines(path),
        "broken_at": broken_at,
        "anchors_ok": anchors_ok,
        "anchors": anchors,
        "head": head,
        "reason": reason,
        "path": path,
        "key_source": "sidecar" if pubkey else ("embedded" if anchors else "none"),
    }


def _count_lines(path: str) -> int:
    with open(path, "r", encoding="utf-8") as handle:
        return sum(1 for line in handle if line.strip())


def report(result: dict) -> str:
    verified = sum(1 for a in result["anchors"] if a["signature_ok"] and a["head_ok"])
    total = len(result["anchors"])
    if result["ok"] and result["anchors_ok"]:
        return "PASS  %d records, %d/%d anchors verified, head %s" % (
            result["records"], verified, total, result["head"])
    lines = []
    if not result["ok"] and result["broken_at"] is None:
        return "FAIL  %s: %s" % (result["reason"] or "the chain could not be read", result["path"])
    if not result["ok"]:
        lines.append("FAIL  chain breaks at record %s of %s: %s"
                     % (result["broken_at"], result.get("records_in_file", result["records"]),
                        result["reason"]))
    else:
        lines.append("FAIL  chain hashes are intact but an anchor signature does not check out")
    lines.append("      %d records verified before the break, %d/%d anchors verified"
                 % (result["records"], verified, total))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 1:
        print(USAGE)
        return 2
    result = verify_chain(args[0])
    print(report(result))
    return 0 if result["ok"] and result["anchors_ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
