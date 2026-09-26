from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Any

import duckdb

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB = os.path.join(ROOT, "data", "alerts.duckdb")
DEFAULT_LEDGER = os.path.join(ROOT, "data", "alerts.jsonl")

GENESIS = "sha256:" + "0" * 64
ANCHOR_EVERY = 100

SCHEMA = """
create table if not exists alerts (
    seq bigint,
    id varchar,
    created varchar,
    created_ts double,
    threat_class varchar,
    subtype varchar,
    severity varchar,
    confidence integer,
    detector varchar,
    src_ip varchar,
    dst_ip varchar,
    dst_port integer,
    latency_ms double,
    doc varchar
)
"""

COLUMNS = (
    "seq, id, created, created_ts, threat_class, subtype, severity, confidence, "
    "detector, src_ip, dst_ip, dst_port, latency_ms, doc"
)


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def chain_hash(record: dict, prev_hash: str) -> str:
    digest = hashlib.sha256(canonical_json(record).encode("utf-8") + prev_hash.encode("utf-8"))
    return "sha256:" + digest.hexdigest()


class FileLedger:
    def __init__(self, path: str = DEFAULT_LEDGER, anchor_every: int = ANCHOR_EVERY) -> None:
        self.path = path
        self.anchor_every = int(anchor_every)
        self.head = GENESIS
        self.count = 0
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        self._signer = _load_signer(path)
        self._resume()

    def append(self, alert: dict) -> dict:
        with self._lock:
            record = {"record": alert, "prev_hash": self.head}
            record["hash"] = chain_hash(alert, self.head)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(canonical_json(record) + "\n")
            self.head = record["hash"]
            self.count += 1
            if self.anchor_every and self.count % self.anchor_every == 0:
                self._write_anchor()
            return record

    def anchor(self) -> dict:
        with self._lock:
            return self._write_anchor()

    def verify(self) -> dict:
        return verify_chain(self.path)

    def _resume(self) -> None:
        if not os.path.exists(self.path):
            return
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    break
                self.head = record.get("hash", self.head)
                self.count += 1

    def _write_anchor(self) -> dict:
        body = {"chain_head": self.head, "count": self.count, "ts": time.time()}
        signature, public = self._signer(canonical_json(body).encode("utf-8"))
        body["sig"] = signature
        body["pubkey"] = public
        with open(anchor_path(self.path), "a", encoding="utf-8") as fh:
            fh.write(canonical_json(body) + "\n")
        return body


def anchor_path(ledger: str) -> str:
    return ledger + ".anchors"


def key_path(ledger: str) -> str:
    return ledger + ".ed25519"


def _load_signer(ledger: str):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    path = key_path(ledger)
    if os.path.exists(path):
        with open(path, "rb") as fh:
            private = ed25519.Ed25519PrivateKey.from_private_bytes(fh.read())
    else:
        private = ed25519.Ed25519PrivateKey.generate()
        with open(path, "wb") as fh:
            fh.write(
                private.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    public_hex = public.hex()

    def sign(payload: bytes) -> tuple[str, str]:
        return private.sign(payload).hex(), public_hex

    return sign


def verify_chain(path: str) -> dict:
    if not os.path.exists(path):
        return {"ok": True, "records": 0, "broken_at": None, "anchors_ok": True, "head": GENESIS}
    prev = GENESIS
    records = 0
    broken_at = None
    heads: dict[int, str] = {0: GENESIS}
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                record = entry["record"]
                stated_prev = entry["prev_hash"]
                stated_hash = entry["hash"]
            except (ValueError, KeyError, TypeError):
                broken_at = records + 1
                break
            if stated_prev != prev or stated_hash != chain_hash(record, stated_prev):
                broken_at = records + 1
                break
            prev = stated_hash
            records += 1
            heads[records] = prev
    anchors_ok = _verify_anchors(anchor_path(path), heads)
    ok = broken_at is None and anchors_ok
    return {"ok": ok, "records": records, "broken_at": broken_at, "anchors_ok": anchors_ok, "head": prev}


def _verify_anchors(path: str, heads: dict[int, str]) -> bool:
    if not os.path.exists(path):
        return True
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519

    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                anchor = json.loads(line)
                body = {"chain_head": anchor["chain_head"], "count": anchor["count"], "ts": anchor["ts"]}
                public = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(anchor["pubkey"]))
                public.verify(bytes.fromhex(anchor["sig"]), canonical_json(body).encode("utf-8"))
            except (ValueError, KeyError, TypeError, InvalidSignature):
                return False
            if heads.get(anchor["count"]) != anchor["chain_head"]:
                return False
    return True


def resolve_ledger(path: str) -> Any:
    try:
        from engine.alerts.ledger import Ledger
    except ImportError:
        return FileLedger(path)
    return Ledger(path)


def resolve_verifier():
    try:
        from engine.alerts.verify import verify_chain as engine_verify
    except ImportError:
        return verify_chain
    return engine_verify


class AlertStore:
    def __init__(self, db_path: str = DEFAULT_DB, ledger_path: str = DEFAULT_LEDGER) -> None:
        self.db_path = db_path
        self.ledger_path = ledger_path
        if db_path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._conn = duckdb.connect(db_path)
        self._conn.execute(SCHEMA)
        self._verify = resolve_verifier()
        try:
            self._conn.execute("create index if not exists alerts_id_lookup on alerts(id)")
            self._conn.execute("create index if not exists alerts_seq_lookup on alerts(seq)")
            if os.path.exists(ledger_path):
                result = self._verify(ledger_path)
                if not result.get("ok") or not result.get("anchors_ok", True):
                    raise ValueError("Ledger integrity failed; preserve evidence and restore a verified backup")
            self._reconcile()
            self.ledger = resolve_ledger(ledger_path)
        except Exception:
            self._conn.close()
            raise
        self._seq = self._max_seq()
        self.duplicates = 0
        self._failed = False

    def _reconcile(self) -> None:
        """Ledger is authoritative. Repair missing index rows, never overwrite a conflict."""
        self._conn.execute("begin transaction")
        count = 0
        try:
            if os.path.exists(self.ledger_path):
                with open(self.ledger_path, encoding="utf-8") as source:
                    for line in source:
                        if not line.strip():
                            continue
                        count += 1
                        record = json.loads(line)["record"]
                        existing = self._conn.execute("select seq, doc from alerts where id = ?", [record["id"]]).fetchall()
                        if existing:
                            if len(existing) != 1 or existing[0][0] != count or json.loads(existing[0][1]) != record:
                                raise ValueError("Database conflicts with verified ledger; restore into a new database")
                        else:
                            self._conn.execute(f"insert into alerts ({COLUMNS}) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", _row(count, record))
            if self._conn.execute("select count(*) from alerts").fetchone()[0] != count:
                raise ValueError("Database contains records absent from ledger")
            self._conn.execute("commit")
        except Exception:
            self._conn.execute("rollback")
            raise

    def append(self, alert: dict) -> dict:
        with self._lock:
            if self._failed:
                raise RuntimeError("Persistence failed; restart to reconcile the verified ledger")
            head = getattr(self.ledger, "head", GENESIS)
            alert_id = str(alert.get("id", ""))
            if alert_id and self._exists(alert_id):
                self.duplicates += 1
                saved = self._conn.execute("select doc from alerts where id = ? limit 1", [alert_id]).fetchone()
                return {"record": json.loads(saved[0]), "hash": head, "duplicate": True}
            if not alert.get("x_prev_hash"):
                alert["x_prev_hash"] = head
            try:
                entry = self.ledger.append(alert)
                alert = entry.get("record", alert) if isinstance(entry, dict) else alert
                self._conn.execute(
                    f"insert into alerts ({COLUMNS}) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    _row(self._seq + 1, alert),
                )
                self._seq += 1
            except Exception:
                self._failed = True
                raise
            return entry if isinstance(entry, dict) else {"record": alert, "hash": head}

    def _exists(self, alert_id: str) -> bool:
        row = self._conn.execute("select 1 from alerts where id = ? limit 1", [alert_id]).fetchone()
        return row is not None

    def recent(self, since: str | None = None, limit: int = 200, threat_class: str | None = None) -> list[dict]:
        clauses = []
        params: list[Any] = []
        cutoff = parse_since(since)
        if cutoff is not None:
            clauses.append("created_ts > ?")
            params.append(cutoff)
        if threat_class:
            clauses.append("threat_class = ?")
            params.append(threat_class)
        where = (" where " + " and ".join(clauses)) if clauses else ""
        params.append(max(1, min(int(limit), 1000)))
        with self._lock:
            rows = self._conn.execute(
                f"select doc from alerts{where} order by seq desc limit ?", params
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def get(self, alert_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("select doc from alerts where id = ? limit 1", [alert_id]).fetchone()
        return json.loads(row[0]) if row else None

    def evidence_snapshot(self, *, alert_ids: list[str] | None = None, since: str | None = None,
                          until: str | None = None, threat_class: str | None = None,
                          limit: int = 20) -> dict:
        """Freeze bounded rows and bind them to ledger hashes at one insertion boundary."""
        limit = max(1, min(int(limit), 20))
        clauses = ["seq <= ?"]
        params: list[Any] = []
        with self._lock:
            upper = self._max_seq()
            params.append(upper)
            if alert_ids:
                clean = list(dict.fromkeys(str(value) for value in alert_ids))[:20]
                clauses.append("id in (" + ",".join("?" for _ in clean) + ")")
                params.extend(clean)
            start = parse_since(since)
            end = parse_since(until)
            if start is not None:
                clauses.append("created_ts >= ?")
                params.append(start)
            if end is not None:
                clauses.append("created_ts <= ?")
                params.append(end)
            if threat_class:
                clauses.append("threat_class = ?")
                params.append(threat_class)
            where = " and ".join(clauses)
            total = int(self._conn.execute(f"select count(*) from alerts where {where}", params).fetchone()[0])
            rows = self._conn.execute(
                f"select seq,doc from alerts where {where} order by seq desc limit ?", [*params, limit]
            ).fetchall()
        selected = {int(seq): json.loads(doc) for seq, doc in rows}
        ledger_rows: dict[int, dict] = {}
        if os.path.exists(self.ledger_path):
            with open(self.ledger_path, encoding="utf-8") as source:
                for sequence, line in enumerate((line for line in source if line.strip()), start=1):
                    if sequence > upper:
                        break
                    if sequence in selected:
                        ledger_rows[sequence] = json.loads(line)
        verdict = self.verify_ledger()
        pinned = _trusted_ledger_key(self.ledger_path)
        trusted_anchor = 0
        if pinned:
            trusted_anchor = max((int(row.get("count") or 0) for row in verdict.get("anchors", [])
                                  if row.get("signature_ok") and row.get("head_ok")), default=0)
        records = []
        for sequence, alert in sorted(selected.items(), reverse=True):
            entry = ledger_rows.get(sequence)
            exact = bool(entry and entry.get("record") == alert)
            if not verdict.get("ok") or not verdict.get("anchors_ok", False) or not exact:
                state = "failed"
            elif pinned and sequence <= trusted_anchor:
                state = "verified_trusted_checkpoint"
            elif pinned:
                state = "unanchored_tail"
            else:
                state = "untrusted_key"
            records.append({"sequence": sequence, "alert": alert,
                            "record_hash": entry.get("hash") if entry else None,
                            "integrity_state": state})
        return {
            "schema_version": "evidence-snapshot-v1",
            "ledger_generation": os.path.abspath(self.ledger_path),
            "sequence_boundary": upper,
            "query_template_version": "alerts-bounded-v1",
            "total_matching": total,
            "shown": len(records),
            "records": records,
            "ledger": {key: verdict.get(key) for key in
                       ("ok", "anchors_ok", "head", "records", "key_source", "reason")},
        }

    def after(self, cursor: int = 0, limit: int = 200) -> dict:
        """Stable insertion cursor, including alerts sharing the same capture timestamp."""
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            rows = self._conn.execute(
                "select seq, doc from alerts where seq > ? order by seq limit ?", [cursor, limit + 1]
            ).fetchall()
        page = rows[:limit]
        return {"alerts": [json.loads(row[1]) for row in page],
                "cursor": int(page[-1][0]) if page else cursor, "has_more": len(rows) > limit}

    def count(self, threat_class: str | None = None) -> int:
        with self._lock:
            if threat_class:
                row = self._conn.execute(
                    "select count(*) from alerts where threat_class = ?", [threat_class]
                ).fetchone()
            else:
                row = self._conn.execute("select count(*) from alerts").fetchone()
        return int(row[0]) if row else 0

    def class_counts(self) -> dict[str, int]:
        with self._lock:
            rows = self._conn.execute(
                "select threat_class, count(*) from alerts group by threat_class"
            ).fetchall()
        return {str(row[0]): int(row[1]) for row in rows}

    def export_records(self, format: str = "json", threat_class: str | None = None):
        """Export a fixed insertion boundary in bounded pages, including >1000 records."""
        if format not in {"json", "jsonl"}:
            raise ValueError("format must be json or jsonl")
        with self._lock:
            upper = self._max_seq()

        def generate():
            cursor = 0
            first = True
            if format == "json":
                yield "[\n"
            while cursor < upper:
                with self._lock:
                    clauses = "seq > ? and seq <= ?"
                    params = [cursor, upper]
                    if threat_class:
                        clauses += " and threat_class = ?"
                        params.append(threat_class)
                    rows = self._conn.execute(
                        f"select seq, doc from alerts where {clauses} order by seq limit 100", params
                    ).fetchall()
                if not rows:
                    break
                for seq, doc in rows:
                    if format == "json":
                        yield ("" if first else ",\n") + doc
                    else:
                        yield doc + "\n"
                    first = False
                    cursor = seq
            if format == "json":
                yield "\n]\n"

        return generate()

    def verify_ledger(self) -> dict:
        result = dict(self._verify(self.ledger_path))
        result.setdefault("head", getattr(self.ledger, "head", GENESIS))
        result.setdefault("anchors_ok", True)
        result.setdefault("broken_at", None)
        return result

    def clear(self) -> None:
        with self._lock:
            self._conn.execute("delete from alerts")
            self._seq = 0
            self.duplicates = 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()
            close = getattr(self.ledger, "close", None)
            if close is not None:
                close()

    def _max_seq(self) -> int:
        row = self._conn.execute("select coalesce(max(seq), 0) from alerts").fetchone()
        return int(row[0]) if row else 0


def parse_since(since: str | None) -> float | None:
    if not since:
        return None
    text = since.strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        pass
    from datetime import datetime, timezone

    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp.timestamp()


def _row(seq: int, alert: dict) -> list[Any]:
    flow = alert.get("x_flow_identifier") or {}
    created = str(alert.get("created", ""))
    return [
        seq,
        str(alert.get("id", "")),
        created,
        parse_since(created) or 0.0,
        str(alert.get("x_threat_class", "")),
        str(alert.get("x_subtype", "")),
        str(alert.get("x_severity", "")),
        int(alert.get("confidence", 0)),
        str(alert.get("x_detector", "")),
        str(flow.get("src_ip", "")),
        str(flow.get("dst_ip", "")),
        int(flow.get("dst_port", 0) or 0),
        float(alert.get("x_latency_ms", 0.0)),
        canonical_json(alert),
    ]


def _trusted_ledger_key(ledger_path: str) -> bool:
    """A generated sidecar becomes trusted only when independently pinned."""
    configured = os.environ.get("SIH_LEDGER_PUBLIC_KEY")
    if not configured or not os.path.exists(configured):
        return False
    try:
        from engine.alerts.ledger import anchor_paths
        pub_path = anchor_paths(ledger_path)[2]
        return (os.path.exists(pub_path)
                and open(configured, encoding="ascii").read().strip()
                == open(pub_path, encoding="ascii").read().strip())
    except (ImportError, OSError):
        return False
