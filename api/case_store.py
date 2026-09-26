"""Transactional single-node collaboration state, separate from immutable alerts."""
from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class CaseConflict(ValueError):
    pass


class CollaborationStore:
    """One writer with optimistic versions, idempotency, audit events and an outbox cursor."""

    def __init__(self, path: str) -> None:
        self.path = path
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = duckdb.connect(path)
        self._conn.execute("""
            create table if not exists cases (
                case_id varchar primary key, alert_id varchar unique, owner varchar,
                status varchar, version bigint, review_label varchar,
                created varchar, updated varchar, doc varchar
            )
        """)
        self._conn.execute("""
            create table if not exists case_events (
                event_sequence bigint primary key, event_id varchar unique, case_id varchar,
                case_version bigint, actor varchar, action varchar, created varchar, doc varchar
            )
        """)
        self._conn.execute("""
            create table if not exists command_results (
                actor varchar, idempotency_key varchar, command_digest varchar, result varchar,
                primary key(actor, idempotency_key)
            )
        """)
        self._conn.execute("alter table command_results add column if not exists command_digest varchar")
        self._conn.execute("""
            create table if not exists report_drafts (
                report_id varchar primary key, version bigint, status varchar, actor varchar,
                created varchar, updated varchar, document varchar, markdown varchar
            )
        """)
        row = self._conn.execute("select coalesce(max(event_sequence), 0) from case_events").fetchone()
        self._event_sequence = int(row[0]) if row else 0

    def get_case(self, alert_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute("select doc from cases where alert_id = ?", [alert_id]).fetchone()
        return json.loads(row[0]) if row else None

    def list_cases(self, *, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self._conn.execute("select doc from cases order by updated desc limit ?",
                                      [max(1, min(int(limit), 1000))]).fetchall()
        return [json.loads(row[0]) for row in rows]

    def command(self, *, alert_id: str, actor: str, role: str, action: str,
                expected_version: int, idempotency_key: str, payload: dict) -> dict:
        if not idempotency_key or len(idempotency_key) > 128:
            raise ValueError("idempotency_key must contain 1 to 128 characters")
        if action not in {"claim", "release", "annotate", "set_status", "review"}:
            raise ValueError("unsupported case action")
        command_digest = str(uuid.uuid5(uuid.NAMESPACE_URL, _json({
            "alert_id": alert_id, "action": action, "expected_version": int(expected_version), "payload": payload,
        })))
        with self._lock:
            cached = self._conn.execute(
                "select command_digest,result from command_results where actor = ? and idempotency_key = ?",
                [actor, idempotency_key],
            ).fetchone()
            if cached:
                if cached[0] and cached[0] != command_digest:
                    raise CaseConflict("idempotency key was already used for a different command")
                result = json.loads(cached[1])
                result["idempotent_replay"] = True
                return result
            self._conn.execute("begin transaction")
            try:
                row = self._conn.execute("select doc from cases where alert_id = ?", [alert_id]).fetchone()
                now = _now()
                if row:
                    case = json.loads(row[0])
                else:
                    case = {
                        "case_id": "case--" + str(uuid.uuid4()),
                        "alert_id": alert_id,
                        "owner": None,
                        "status": "open",
                        "version": 0,
                        "review_label": None,
                        "annotations": [],
                        "created": now,
                        "updated": now,
                    }
                if int(expected_version) != int(case["version"]):
                    raise CaseConflict(f"case version conflict; current version is {case['version']}")
                changed: dict[str, Any] = {}
                if action == "claim":
                    if case["owner"] not in (None, actor):
                        raise CaseConflict("case is already claimed")
                    case["owner"] = actor
                    changed["owner"] = actor
                elif action == "release":
                    if case["owner"] not in (None, actor) and role != "admin":
                        raise CaseConflict("only the owner or an administrator can release this case")
                    case["owner"] = None
                    changed["owner"] = None
                elif action == "annotate":
                    note = str(payload.get("note", "")).strip()
                    if not note or len(note) > 4000:
                        raise ValueError("annotation must contain 1 to 4000 characters")
                    annotation = {"id": "note--" + str(uuid.uuid4()), "actor": actor,
                                  "created": now, "text": note}
                    case["annotations"] = [*(case.get("annotations") or []), annotation]
                    changed["annotation"] = annotation
                elif action == "set_status":
                    status = str(payload.get("status", ""))
                    if status not in {"open", "investigating", "escalated", "closed"}:
                        raise ValueError("invalid case status")
                    case["status"] = status
                    changed["status"] = status
                else:
                    label = str(payload.get("label", ""))
                    if label not in {"confirmed-benign", "suspicious-needs-investigation",
                                     "confirmed-malicious", "inconclusive"}:
                        raise ValueError("invalid review label")
                    reason = str(payload.get("reason", "")).strip()
                    if not reason or len(reason) > 4000:
                        raise ValueError("review reason must contain 1 to 4000 characters")
                    case["review_label"] = label
                    changed.update({"review_label": label, "review_reason": reason})
                case["version"] = int(case["version"]) + 1
                case["updated"] = now
                self._event_sequence += 1
                event = {
                    "event_id": "event--" + str(uuid.uuid4()),
                    "event_sequence": self._event_sequence,
                    "case_id": case["case_id"],
                    "case_version": case["version"],
                    "alert_id": alert_id,
                    "actor": actor,
                    "action": action,
                    "changed": changed,
                    "created": now,
                }
                doc = _json(case)
                self._conn.execute("delete from cases where alert_id = ?", [alert_id])
                self._conn.execute(
                    "insert into cases values (?,?,?,?,?,?,?,?,?)",
                    [case["case_id"], alert_id, case["owner"], case["status"], case["version"],
                     case["review_label"], case["created"], case["updated"], doc],
                )
                self._conn.execute("insert into case_events values (?,?,?,?,?,?,?,?)",
                                   [event["event_sequence"], event["event_id"], event["case_id"],
                                    event["case_version"], actor, action, now, _json(event)])
                result = {"case": case, "event": event, "idempotent_replay": False}
                self._conn.execute(
                    "insert into command_results (actor,idempotency_key,command_digest,result) values (?,?,?,?)",
                    [actor, idempotency_key, command_digest, _json(result)])
                self._conn.execute("commit")
                return result
            except Exception:
                self._conn.execute("rollback")
                raise

    def events_after(self, after: int = 0, limit: int = 200) -> dict:
        limit = max(1, min(int(limit), 1000))
        with self._lock:
            rows = self._conn.execute(
                "select event_sequence, doc from case_events where event_sequence > ? order by event_sequence limit ?",
                [int(after), limit + 1],
            ).fetchall()
        page = rows[:limit]
        return {"events": [json.loads(row[1]) for row in page],
                "cursor": int(page[-1][0]) if page else int(after), "has_more": len(rows) > limit}

    @property
    def latest_event_sequence(self) -> int:
        with self._lock:
            return self._event_sequence

    def save_report(self, document: dict, markdown: str, actor: str) -> dict:
        now = _now()
        report_id = "report--" + str(uuid.uuid4())
        record = {"report_id": report_id, "version": 1, "status": "draft", "actor": actor,
                  "created": now, "updated": now, "document": document, "markdown": markdown}
        with self._lock:
            self._conn.execute("insert into report_drafts values (?,?,?,?,?,?,?,?)",
                               [report_id, 1, "draft", actor, now, now, _json(document), markdown])
        return record

    def get_report(self, report_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "select version,status,actor,created,updated,document,markdown from report_drafts where report_id = ?",
                [report_id],
            ).fetchone()
        if not row:
            return None
        return {"report_id": report_id, "version": int(row[0]), "status": row[1], "actor": row[2],
                "created": row[3], "updated": row[4], "document": json.loads(row[5]), "markdown": row[6]}

    def review_report(self, report_id: str, expected_version: int, actor: str, status: str) -> dict:
        if status not in {"human_reviewed", "exported", "submission_recorded"}:
            raise ValueError("invalid report lifecycle status")
        with self._lock:
            current = self.get_report_unlocked(report_id)
            if current is None:
                raise KeyError(report_id)
            if current["version"] != int(expected_version):
                raise CaseConflict(f"report version conflict; current version is {current['version']}")
            version = current["version"] + 1
            now = _now()
            self._conn.execute("update report_drafts set version=?, status=?, actor=?, updated=? where report_id=?",
                               [version, status, actor, now, report_id])
        return self.get_report(report_id) or {}

    def get_report_unlocked(self, report_id: str) -> dict | None:
        row = self._conn.execute(
            "select version,status,actor,created,updated,document,markdown from report_drafts where report_id = ?",
            [report_id],
        ).fetchone()
        if not row:
            return None
        return {"report_id": report_id, "version": int(row[0]), "status": row[1], "actor": row[2],
                "created": row[3], "updated": row[4], "document": json.loads(row[5]), "markdown": row[6]}

    def close(self) -> None:
        with self._lock:
            self._conn.close()
