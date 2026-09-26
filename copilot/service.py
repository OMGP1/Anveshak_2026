"""Bounded deterministic copilot baseline; optional model selection plugs in after evaluation."""
from __future__ import annotations

import json
import threading
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SUPPORTED_INTENTS = {
    "explain_alert", "summarise_window", "compare_alerts", "explain_term", "draft_incident_report"
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class CopilotService:
    """One active worker, four queued jobs, bounded contexts, and deterministic fallback."""

    def __init__(self, alert_store, collaboration_store, *, queue_capacity: int = 4) -> None:
        self.alert_store = alert_store
        self.collaboration_store = collaboration_store
        self.queue_capacity = max(1, int(queue_capacity))
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="offline-copilot")
        self._lock = threading.Lock()
        self._jobs: dict[str, dict] = {}
        self._futures: dict[str, Future] = {}
        glossary_path = Path(__file__).resolve().parents[1] / "data" / "reference" / "copilot_glossary.json"
        self.glossary = json.loads(glossary_path.read_text(encoding="utf-8")) if glossary_path.exists() else {}

    def submit(self, request: dict, *, actor: str, scope: str) -> dict:
        intent = str(request.get("intent", ""))
        if intent not in SUPPORTED_INTENTS:
            return {"state": "unsupported_intent", "supported_intents": sorted(SUPPORTED_INTENTS)}
        with self._lock:
            active = sum(1 for job in self._jobs.values() if job["state"] in {"queued", "running"})
            if active >= self.queue_capacity + 1:
                return {"state": "runtime_unavailable", "detail": "copilot queue is full; use a narrower request"}
            job_id = "copilot-job--" + str(uuid.uuid4())
            job = {"id": job_id, "state": "queued", "intent": intent, "actor": actor,
                   "scope": scope, "created": _now(), "updated": _now(), "result": None, "error": None}
            self._jobs[job_id] = job
            future = self._executor.submit(self._run, job_id, dict(request), actor)
            self._futures[job_id] = future
            return self._public(job)

    def get(self, job_id: str, *, actor: str, scope: str) -> dict | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or (job["actor"] != actor and scope != "admin"):
                return None
            return self._public(job)

    def cancel(self, job_id: str, *, actor: str, scope: str) -> dict | None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or (job["actor"] != actor and scope != "admin"):
                return None
            future = self._futures.get(job_id)
            if job["state"] == "queued" and future is not None and future.cancel():
                job["state"] = "cancelled"
                job["updated"] = _now()
            elif job["state"] == "running":
                job["cancel_requested"] = True
            return self._public(job)

    @staticmethod
    def _public(job: dict) -> dict:
        return {key: value for key, value in job.items() if key not in {"actor", "scope"}}

    def _run(self, job_id: str, request: dict, actor: str) -> None:
        with self._lock:
            job = self._jobs[job_id]
            if job["state"] == "cancelled":
                return
            job["state"] = "running"
            job["updated"] = _now()
        try:
            result = self._answer(request, actor)
            with self._lock:
                job = self._jobs[job_id]
                if job.get("cancel_requested"):
                    job["state"] = "cancelled"
                    job["result"] = None
                else:
                    job["state"] = "complete"
                    job["result"] = result
                job["updated"] = _now()
        except Exception as exc:
            with self._lock:
                job = self._jobs[job_id]
                job["state"] = "failed"
                job["error"] = f"{type(exc).__name__}: {exc}"
                job["updated"] = _now()

    def _answer(self, request: dict, actor: str) -> dict:
        intent = request["intent"]
        if intent == "explain_term":
            term = str(request.get("term", "")).strip().lower()
            row = self.glossary.get(term)
            if row is None:
                return {"state": "no_matching_records", "intent": intent,
                        "detail": "The approved local glossary has no matching term."}
            return {"state": "complete", "intent": intent, "mode": "deterministic",
                    "briefing": row["definition"],
                    "claims": [{"id": "G1", "text": row["definition"], "origin": "approved_reference",
                                "citation": {"source": "copilot_glossary", "term": term}}],
                    "limitations": row.get("limitations", [])}
        alert_ids = [str(value) for value in request.get("alert_ids") or []]
        if intent == "explain_alert" and len(alert_ids) != 1:
            return {"state": "clarification_required", "detail": "Select exactly one alert."}
        if intent == "compare_alerts" and not 2 <= len(alert_ids) <= 20:
            return {"state": "clarification_required", "detail": "Select between two and twenty alerts."}
        if intent in {"summarise_window", "draft_incident_report"} and not alert_ids:
            if not request.get("since") or not request.get("until"):
                return {"state": "clarification_required",
                        "detail": "Provide selected alerts or an absolute start and end time."}
        snapshot = self.alert_store.evidence_snapshot(
            alert_ids=alert_ids or None, since=request.get("since"), until=request.get("until"),
            threat_class=request.get("threat_class"), limit=20,
        )
        if not snapshot["records"]:
            return {"state": "no_matching_records", "intent": intent,
                    "detail": "No matching authorised records were found; this is not proof that the network is safe.",
                    "snapshot": snapshot}
        claims, limitations = _claims(snapshot)
        briefing = _render(intent, claims, snapshot, limitations)
        result = {"state": "complete", "intent": intent, "mode": "deterministic",
                  "briefing": briefing, "claims": claims, "limitations": limitations,
                  "snapshot": snapshot,
                  "scope_note": f"{snapshot['shown']} shown from {snapshot['total_matching']} matching records"}
        if intent == "draft_incident_report":
            document, markdown = _report(snapshot, claims, request.get("human_fields") or {})
            saved = self.collaboration_store.save_report(document, markdown, actor)
            result["report"] = saved
        return result

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


def _claims(snapshot: dict) -> tuple[list[dict], list[str]]:
    claims: list[dict] = []
    limitations: list[str] = []
    for index, row in enumerate(snapshot["records"], start=1):
        alert = row["alert"]
        prefix = f"A{index}"
        citation = {"alert_id": alert["id"], "record_hash": row["record_hash"]}
        claims.extend([
            {"id": prefix + "-class", "text": f"The detector labelled this observation as {alert['x_threat_class']}.",
             "origin": "observed_record", "integrity": row["integrity_state"],
             "citation": {**citation, "field": "x_threat_class"}},
            {"id": prefix + "-confidence",
             "text": (f"The recorded review score is {alert['confidence']} out of 100; "
                      f"it is {'calibrated' if alert['x_confidence_calibrated'] else 'not calibrated as an attack probability'}."),
             "origin": "observed_record", "integrity": row["integrity_state"],
             "citation": {**citation, "field": "confidence"}},
        ])
        flow = alert["x_flow_identifier"]
        if not flow.get("completeness_flag"):
            limitations.append(f"{alert['id']}: reverse-direction traffic was not observed in this capture.")
        novelty = (alert.get("x_detection_context") or {}).get("novelty")
        if novelty:
            claims.append({"id": prefix + "-novelty",
                           "text": (f"The benign-tail fraction is {novelty.get('benign_tail_fraction')}; this is rarity "
                                    "against the approved reference, not proof of an exploit."),
                           "origin": "computed_aggregate", "integrity": row["integrity_state"],
                           "citation": {**citation, "field": "x_detection_context.novelty"}})
        if row["integrity_state"] != "verified_trusted_checkpoint":
            limitations.append(f"{alert['id']}: evidence integrity state is {row['integrity_state']}.")
    limitations = list(dict.fromkeys(limitations))
    return claims, limitations


def _render(intent: str, claims: list[dict], snapshot: dict, limitations: list[str]) -> str:
    title = {
        "explain_alert": "Alert explanation", "compare_alerts": "Alert comparison",
        "summarise_window": "Shift-window summary", "draft_incident_report": "Incident-report evidence summary",
    }[intent]
    lines = [f"## {title}", "", f"Scope: {snapshot['shown']} shown from {snapshot['total_matching']} matching records.", ""]
    lines.extend(f"- {claim['text']} [{claim['id']}]" for claim in claims)
    lines.extend(["", "### Limitations"])
    lines.extend(f"- {item}" for item in (limitations or ["No additional capture limitation was recorded."]))
    return "\n".join(lines)


def _report(snapshot: dict, claims: list[dict], human_fields: dict) -> tuple[dict, str]:
    allowed_human = {key: human_fields.get(key) for key in
                     ("reporter_name", "reporter_contact", "organisation", "asset_description",
                      "awareness_time", "impact", "actions_taken") if human_fields.get(key)}
    missing = [key for key in ("reporter_name", "reporter_contact", "organisation", "awareness_time")
               if key not in allowed_human]
    alerts = [row["alert"] for row in snapshot["records"]]
    document = {
        "schema_version": "soc-report-draft-v1",
        "document_type": "incident_report_draft",
        "review_status": "draft",
        "reportability": "undecided",
        "submission_status": "not_submitted",
        "alert_ids": [alert["id"] for alert in alerts],
        "observed_times": [alert["created"] for alert in alerts],
        "recorded_classes": [alert["x_threat_class"] for alert in alerts],
        "human_attested": allowed_human,
        "awareness": {"value": allowed_human.get("awareness_time"),
                      "status": "recorded" if allowed_human.get("awareness_time") else "needs_human_input",
                      "source_refs": ["human_attested"] if allowed_human.get("awareness_time") else []},
        "retention": {"configured_days": None, "verified_coverage_days": None,
                      "verification_status": "not_checked"},
        "missing_fields": missing,
        "evidence_snapshot": {"sequence_boundary": snapshot["sequence_boundary"],
                              "ledger_head": snapshot["ledger"].get("head"),
                              "record_hashes": [row["record_hash"] for row in snapshot["records"]]},
        "claim_ids": [claim["id"] for claim in claims],
    }
    lines = ["# CERT-In reporting assistance draft", "", "Status: Draft; human review required; not submitted.", "",
             "## Recorded observations"]
    lines.extend(f"- {claim['text']} [{claim['id']}]" for claim in claims)
    lines.extend(["", "## Information still needed"])
    lines.extend(f"- {field.replace('_', ' ')}" for field in (missing or ["None in the minimum checklist"]))
    return document, "\n".join(lines)
