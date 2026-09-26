from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

import stix2
from stix2.v21 import Indicator

from engine.explain import MAX_EVIDENCE, evidence_rows, explain, headline, host_text, proto_text
from engine.types import ALERT_CLASSES, ATTACK_TECHNIQUE, Detection

SPEC_VERSION = "2.1"
GENESIS_HASH = "sha256:" + "0" * 64
HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
DIRECTIONALITY = ("FWD_ONLY", "REV_ONLY", "BIDIRECTIONAL", "UNKNOWN")
SPOOFED_SRC = "spoofed - low attribution confidence"
ALERT_NAMESPACE = uuid.UUID("1e4a6f60-1c5f-4a0c-9a37-2b5f0e26145a")
INDICATOR_TYPES = ["anomalous-activity"]
DEFAULT_LABELS = ["cii-relevant"]

REQUIRED_PS_FIELDS = ("created", "x_flow_identifier", "x_threat_class", "confidence", "x_supporting_evidence")
REQUIRED_TOP_FIELDS = (
    "type", "spec_version", "id", "created", "modified", "name", "description", "indicator_types",
    "pattern", "pattern_type", "valid_from", "confidence", "labels",
    "x_flow_identifier", "x_threat_class", "x_subtype", "x_severity", "x_confidence_calibrated",
    "x_detector", "x_latency_ms", "x_model_lineage", "x_supporting_evidence", "x_detection_context",
    "x_prev_hash", "external_references",
)
FLOW_FIELDS = (
    "flow_id", "proto", "src_ip", "dst_ip", "src_port", "dst_port",
    "directionality", "completeness_flag", "window_start", "window_end",
)
LINEAGE_FIELDS = ("model_id", "model_hash", "dataset_version")


class AlertSchemaError(ValueError):
    pass


def iso_ts(ts_ns: int) -> str:
    sec, rem = divmod(int(ts_ns), 1_000_000_000)
    stamp = datetime.fromtimestamp(sec, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return "%s.%03dZ" % (stamp, rem // 1_000_000)


def _window(flow: dict, side: str, fallback_ns: int) -> str:
    exact = flow.get("window_%s_ns" % side)
    if isinstance(exact, (int, float)) and not isinstance(exact, bool):
        return iso_ts(int(exact))
    value = flow.get("window_" + side)
    if isinstance(value, str) and value:
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return iso_ts(int(float(value) * 1e9))
    return iso_ts(fallback_ns)


def _port(value: object) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _host_field(value: object) -> str:
    return "unknown" if value is None else host_text(value)


def flow_identifier(detection: Detection) -> dict:
    flow = detection.flow or {}
    spoofed = flow.get("src_attribution") == "spoofed"
    src = SPOOFED_SRC if spoofed else _host_field(flow.get("src_ip"))
    dst = _host_field(flow.get("dst_ip"))
    proto = proto_text(flow.get("proto"))
    src_port, dst_port = _port(flow.get("src_port")), _port(flow.get("dst_port"))
    direction = str(flow.get("directionality", "UNKNOWN")).upper()
    if direction not in DIRECTIONALITY:
        direction = "UNKNOWN"
    return {
        "flow_id": "%s %s:%d>%s:%d" % (proto, "spoofed" if spoofed else src, src_port, dst, dst_port),
        "proto": proto,
        "src_ip": src,
        "dst_ip": dst,
        "src_port": src_port,
        "dst_port": dst_port,
        "directionality": direction,
        "completeness_flag": bool(flow.get("completeness_flag", False)),
        "window_start": _window(flow, "start", detection.ts_ns),
        "window_end": _window(flow, "end", detection.ts_ns),
    }


def stix_pattern(flow: dict) -> str:
    terms = ["network-traffic:protocols[*] = '%s'" % flow["proto"].lower()]
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", flow["dst_ip"]):
        terms.append("network-traffic:dst_ref.value = '%s'" % flow["dst_ip"])
    if flow["dst_port"]:
        terms.append("network-traffic:dst_port = %d" % flow["dst_port"])
    return "[" + " AND ".join(terms) + "]"


def confidence_score(value: float) -> int:
    score = float(value)
    if score <= 1.0:
        score *= 100.0
    return max(0, min(100, int(round(score))))


def severity_for(detection: Detection, score: int) -> str:
    given = str(detection.severity or "").upper()
    if given in SEVERITIES:
        return given
    if score >= 90:
        return "CRITICAL"
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def alert_id(detection: Detection, flow: dict) -> str:
    seed = "|".join([detection.threat_class, detection.subtype or "", str(detection.ts_ns),
                     flow["flow_id"], detection.source or ""])
    return "indicator--" + str(uuid.uuid5(ALERT_NAMESPACE, seed))


def external_refs(threat_class: str) -> list[dict]:
    technique = ATTACK_TECHNIQUE.get(threat_class)
    if technique is None:
        return []
    return [{"source_name": "mitre-attack", "external_id": technique[0], "description": technique[1]}]


def build_alert(detection: Detection, lineage: dict) -> dict:
    if detection.threat_class not in ALERT_CLASSES:
        raise AlertSchemaError("unknown threat class %r" % detection.threat_class)
    ctx = detection.context or {}
    flow = flow_identifier(detection)
    score = confidence_score(detection.confidence)
    created = iso_ts(detection.ts_ns)
    latency_ns = float(lineage.get("latency_ns", ctx.get("latency_ns", 0.0)) or 0.0)
    context = {
        **ctx,
        "sampling_active": bool(ctx.get("sampling_active", False)),
        "sampling_ratio": float(ctx.get("sampling_ratio", 1.0)),
        "shedding_tier": str(ctx.get("shedding_tier", "none") or "none"),
    }
    indicator = Indicator(
        id=alert_id(detection, flow),
        created=created,
        modified=created,
        name=headline(detection),
        description=detection.summary or explain(detection),
        indicator_types=list(INDICATOR_TYPES),
        pattern=stix_pattern(flow),
        pattern_type="stix",
        valid_from=created,
        confidence=score,
        labels=list(lineage.get("labels", DEFAULT_LABELS)),
        external_references=external_refs(detection.threat_class),
        allow_custom=True,
        x_flow_identifier=flow,
        x_threat_class=detection.threat_class,
        x_subtype=detection.subtype or "",
        x_severity=severity_for(detection, score),
        x_confidence_calibrated=bool(lineage.get("calibrated", False)),
        x_detector=detection.source or "unknown",
        x_latency_ms=round(latency_ns / 1e6, 3),
        x_model_lineage={key: str(lineage.get(key, "none")) for key in LINEAGE_FIELDS},
        x_supporting_evidence=evidence_rows(detection),
        x_detection_context=context,
        x_prev_hash=str(lineage.get("prev_hash", GENESIS_HASH)),
    )
    result = json.loads(indicator.serialize())
    # stix2 omits an explicitly empty optional list, but the application contract
    # requires the field so unknown observations cannot inherit a fake technique.
    result.setdefault("external_references", [])
    return result


def _require(alert: dict, field: str) -> object:
    if field not in alert:
        raise AlertSchemaError("missing required field %r" % field)
    return alert[field]


def _require_map(alert: dict, field: str, keys: tuple[str, ...]) -> dict:
    value = _require(alert, field)
    if not isinstance(value, dict):
        raise AlertSchemaError("%s must be an object" % field)
    for key in keys:
        if key not in value:
            raise AlertSchemaError("%s is missing %r" % (field, key))
    return value


def validate_alert(alert: dict) -> None:
    if not isinstance(alert, dict):
        raise AlertSchemaError("alert must be a JSON object")
    for field in REQUIRED_TOP_FIELDS:
        _require(alert, field)
    if alert["type"] != "indicator" or alert["spec_version"] != SPEC_VERSION:
        raise AlertSchemaError("alert must be a STIX 2.1 indicator")
    if not str(alert["id"]).startswith("indicator--"):
        raise AlertSchemaError("id must be an indicator identifier")
    if not isinstance(alert["confidence"], int) or isinstance(alert["confidence"], bool):
        raise AlertSchemaError("confidence must be an integer")
    if not 0 <= alert["confidence"] <= 100:
        raise AlertSchemaError("confidence must be between 0 and 100")
    if alert["x_threat_class"] not in ALERT_CLASSES:
        raise AlertSchemaError("unknown threat class %r" % alert["x_threat_class"])
    if alert["x_severity"] not in SEVERITIES:
        raise AlertSchemaError("severity must be one of %s" % (SEVERITIES,))
    if not isinstance(alert["x_confidence_calibrated"], bool):
        raise AlertSchemaError("x_confidence_calibrated must be a boolean")
    if not isinstance(alert["x_latency_ms"], (int, float)) or alert["x_latency_ms"] < 0:
        raise AlertSchemaError("x_latency_ms must be a non-negative number")
    flow = _require_map(alert, "x_flow_identifier", FLOW_FIELDS)
    if not isinstance(flow["src_port"], int) or not isinstance(flow["dst_port"], int):
        raise AlertSchemaError("flow ports must be integers")
    if not isinstance(flow["completeness_flag"], bool):
        raise AlertSchemaError("completeness_flag must be a boolean")
    if flow["directionality"] not in DIRECTIONALITY:
        raise AlertSchemaError("directionality must be one of %s" % (DIRECTIONALITY,))
    lineage = _require_map(alert, "x_model_lineage", LINEAGE_FIELDS)
    for key in LINEAGE_FIELDS:
        if not isinstance(lineage[key], str) or not lineage[key]:
            raise AlertSchemaError("model lineage %r must be a non-empty string" % key)
    context = _require_map(alert, "x_detection_context", ("sampling_active", "sampling_ratio", "shedding_tier"))
    if not isinstance(context["sampling_active"], bool):
        raise AlertSchemaError("sampling_active must be a boolean")
    _validate_evidence(alert["x_supporting_evidence"])
    if not HASH_RE.match(str(alert["x_prev_hash"])):
        raise AlertSchemaError("x_prev_hash must look like sha256:<64 hex chars>")
    _validate_refs(alert)
    try:
        stix2.parse(alert, allow_custom=True, version=SPEC_VERSION)
    except Exception as exc:
        raise AlertSchemaError("STIX 2.1 validation failed: %s" % exc) from exc


def _validate_evidence(evidence: object) -> None:
    if not isinstance(evidence, list) or not evidence:
        raise AlertSchemaError("x_supporting_evidence must be a non-empty list")
    if len(evidence) > MAX_EVIDENCE:
        raise AlertSchemaError("x_supporting_evidence holds at most %d rows" % MAX_EVIDENCE)
    for row in evidence:
        if not isinstance(row, dict):
            raise AlertSchemaError("each evidence row must be an object")
        if not isinstance(row.get("feature"), str) or not row["feature"]:
            raise AlertSchemaError("each evidence row needs a feature name")
        if not isinstance(row.get("value"), (int, float)) or isinstance(row.get("value"), bool):
            raise AlertSchemaError("evidence %r needs a numeric value" % row["feature"])
        weight = row.get("shap", row.get("contribution"))
        if not isinstance(weight, (int, float)) or isinstance(weight, bool):
            raise AlertSchemaError("evidence %r needs a numeric contribution" % row["feature"])


def _validate_refs(alert: dict) -> None:
    technique = ATTACK_TECHNIQUE.get(alert["x_threat_class"])
    refs = alert["external_references"]
    if not isinstance(refs, list):
        raise AlertSchemaError("external_references must be a list")
    mitre = [ref for ref in refs if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack"]
    if technique is None:
        return
    if not mitre:
        raise AlertSchemaError("alert must carry a mitre-attack external reference")
    if mitre[0].get("external_id") != technique[0]:
        raise AlertSchemaError("mitre technique must be %s for %s" % (technique[0], alert["x_threat_class"]))
