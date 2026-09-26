from __future__ import annotations

from engine.types import Detection, Evidence

MAX_EVIDENCE = 5
MAX_IN_SENTENCE = 3

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

CLASS_HEADLINE = {
    "benign": "Normal traffic {src} to {dst}",
    "volumetric-ddos": "Suspected volumetric flood against {dst}",
    "c2-beaconing": "Suspected C2 beaconing from {src} to {dst}",
    "dga-dns-tunnelling": "Suspected algorithmic domain lookups from {src}",
    "encrypted-malware": "Suspicious encrypted session from {src} to {dst}",
    "recon-scanning": "Suspected reconnaissance from {src}",
    "data-exfiltration": "Suspected data exfiltration from {src} to {dst}",
}

SUBTYPE_HEADLINE = {
    ("volumetric-ddos", "tcp-rate-anomaly"): "TCP packet-rate anomaly against {dst}",
    ("volumetric-ddos", "udp-rate-anomaly"): "UDP packet-rate anomaly against {dst}",
    ("volumetric-ddos", "icmp-rate-anomaly"): "ICMP packet-rate anomaly against {dst}",
    ("volumetric-ddos", "tcp-syn-rate-anomaly"): "TCP SYN-attempt rate anomaly against {dst}",
    ("volumetric-ddos", "syn-flood"): "Suspected spoofed-source SYN flood against {dst}",
    ("volumetric-ddos", "reflection"): "Suspected UDP reflection and amplification aimed at {dst}",
    ("volumetric-ddos", "amplification"): "Suspected UDP reflection and amplification aimed at {dst}",
    ("volumetric-ddos", "slowloris"): "Suspected slow HTTP connection exhaustion against {dst}",
    ("volumetric-ddos", "protocol-exhaustion"): "Suspected connection-table exhaustion against {dst}",
    ("c2-beaconing", "jittered"): "Suspected jittered C2 beaconing from {src} to {dst}",
    ("c2-beaconing", "regular"): "Suspected C2 beaconing from {src} to {dst}",
    ("dga-dns-tunnelling", "dga"): "Suspected DGA domain lookups from {src}",
    ("dga-dns-tunnelling", "dictionary-dga"): "Suspected dictionary-DGA domain lookups from {src}",
    ("dga-dns-tunnelling", "tunnel"): "Suspected DNS tunnelling from {src}",
    ("dga-dns-tunnelling", "dns-tunnel"): "Suspected DNS tunnelling from {src}",
    ("encrypted-malware", "fingerprint-mismatch"): "TLS fingerprint disagrees with the OS fingerprint on {src}",
    ("encrypted-malware", "ja4-spoof"): "TLS fingerprint disagrees with the OS fingerprint on {src}",
    ("encrypted-malware", "splt-anomaly"): "Unusual packet size and timing pattern in an encrypted session from {src}",
    ("recon-scanning", "vertical"): "Suspected vertical port scan from {src} against {dst}",
    ("recon-scanning", "horizontal"): "Suspected horizontal sweep from {src} across many hosts",
    ("recon-scanning", "strobe"): "Suspected strobe scan from {src}, few ports across many hosts",
    ("data-exfiltration", "slow-drip"): "Suspected slow-drip data exfiltration from {src} to {dst}",
    ("data-exfiltration", "bulk"): "Suspected bulk data transfer out from {src} to {dst}",
}

FEATURE_PHRASE = {
    "syn_attempts_per_second": "{v:.0f} observed SYN attempts per second, including possible retransmissions",
    "syn_attempts_ewma_dev": "SYN-attempt rate {v:.1f} sigma above its observed baseline",
    "syn_synack_ratio_1s": "{v:.1f} SYNs for every SYN-ACK in the last second",
    "pps_to_dst_ewma_dev": "packet rate to this destination {v:.1f} sigma above its own baseline",
    "src_entropy_1s": "source-IP entropy {v:.2f} of maximum over one second",
    "src_entropy_5s": "source-IP entropy {v:.2f} of maximum over five seconds",
    "src_entropy_60s": "source-IP entropy {v:.2f} of maximum over the last minute",
    "entropy_explosion_score": "source diversity {a:.1f} sigma above normal, the spoofed-flood signature",
    "entropy_collapse_score": "source diversity {a:.1f} sigma below normal, the reflection signature",
    "src_cardinality_per_dst": "around {v:,.0f} distinct sources aimed at one destination",
    "amplification_ratio": "replies {v:.1f} times larger than the queries that drew them",
    "iat_mean": "check-ins roughly every {v:.0f} seconds",
    "iat_std": "an inter-arrival spread of {v:.1f} seconds",
    "iat_cv": "inter-arrival variation of only {v:.2f}",
    "iat_skew": "inter-arrival skew {v:.2f}",
    "iat_kurtosis": "inter-arrival kurtosis {v:.2f}",
    "ls_peak_power": "a periodogram peak of normalised power {v:.1f}",
    "ls_peak_period_s": "a repeating {v:.0f} second period",
    "ls_fap": "false-alarm probability {v:.1e} for that period",
    "dst_stability": "destination stability {v:.2f}, the same host almost every time",
    "qname_char_entropy": "query-name entropy {v:.2f} bits per character",
    "qname_bigram_ll": "mean bigram log-likelihood {v:.2f} against ordinary domain names",
    "qname_len": "query names averaging {v:.0f} characters",
    "label_count": "{v:.0f} labels in the query name",
    "max_label_len": "a longest label of {v:.0f} characters",
    "digit_ratio": "{v:.0%} of the name is digits",
    "consonant_run_max": "a run of {v:.0f} consonants",
    "qtype_txt_null_ratio": "{v:.0%} of queries asking for TXT or NULL records",
    "subdomain_cardinality": "around {v:,.0f} distinct subdomains under one registered domain",
    "fingerprint_consistency_score": "JA4 and TCP fingerprint agreement of only {v:.2f}",
    "tls_version": "TLS version code {v:.0f}",
    "ext_count": "{v:.0f} TLS extensions offered",
    "vertical_fanout": "{v:,.0f} distinct ports touched on one host",
    "horizontal_fanout": "{v:,.0f} distinct hosts touched on one port",
    "strobe_score": "strobe score {v:.2f}, few ports across many hosts",
    "rst_response_ratio": "{v:.0%} of probes answered with RST",
    "mean_bytes_per_flow": "only {v:.0f} bytes per flow",
    "out_in_byte_ratio": "{v:.1f} bytes leaving for every byte arriving",
    "out_in_ratio_ewma_7d": "an outbound ratio of {v:.1f} against this pair's own long-run baseline",
    "dst_novelty_score": "destination novelty {v:.2f}, this pair has barely been seen before",
    "upload_burst_score": "upload burst score {v:.2f}",
    "sustained_asymmetry_duration": "asymmetry sustained for {v:.0f} seconds",
    "duration": "a flow lasting {v:.1f} seconds",
    "pkts_fwd": "{v:,.0f} packets outbound",
    "pkts_rev": "{v:,.0f} packets inbound",
    "bytes_fwd": "{v:,.0f} bytes outbound",
    "bytes_rev": "{v:,.0f} bytes inbound",
    "bytes_per_pkt_fwd": "{v:.0f} bytes per outbound packet",
    "bytes_per_pkt_rev": "{v:.0f} bytes per inbound packet",
    "flags_seen_bitmap": "a TCP flag set of 0x{i:02x}",
    "orientation_confidence": "orientation confidence {v:.2f}",
    "mean_bytes": "{v:.0f} bytes per packet on average",
}

BOOLEAN_PHRASE = {
    "completeness_flag": ("not one of these flows was answered", "both directions of the flow were seen"),
}

SHEDDING_NOTE = "Raised while the engine was shedding at tier {tier}, so evidence depth is reduced."
SAMPLING_NOTE = "Raised while sampling was active at {ratio:.2f}, so counts are estimates."


def host_text(value: object) -> str:
    if value is None:
        return "an unknown host"
    if isinstance(value, str):
        return value or "an unknown host"
    if isinstance(value, int):
        return "%d.%d.%d.%d" % ((value >> 24) & 0xFF, (value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF)
    return str(value)


def endpoint_text(flow: dict, side: str) -> str:
    host = host_text(flow.get(side + "_ip"))
    port = flow.get(side + "_port")
    if isinstance(port, int) and port > 0:
        return "%s:%d" % (host, port)
    return host


def proto_text(proto: object) -> str:
    if isinstance(proto, str):
        return proto.upper()
    if isinstance(proto, int):
        return PROTO_NAMES.get(proto, "IP-%d" % proto)
    return "IP"


def normalise_subtype(subtype: str) -> str:
    out = []
    for ch in (subtype or "").strip().lower():
        out.append(ch if ch.isalnum() else "-")
    return "-".join(part for part in "".join(out).split("-") if part)


def headline(detection: Detection) -> str:
    flow = detection.flow or {}
    fields = {"src": endpoint_text(flow, "src"), "dst": endpoint_text(flow, "dst")}
    key = (detection.threat_class, normalise_subtype(detection.subtype))
    template = SUBTYPE_HEADLINE.get(key)
    if template is None:
        template = CLASS_HEADLINE.get(detection.threat_class, "Suspicious activity from {src}")
    return template.format(**fields)


def top_evidence(evidence: list[Evidence] | None, limit: int = MAX_EVIDENCE) -> list[Evidence]:
    items = list(evidence or [])
    items.sort(key=lambda e: (-abs(float(e.contribution)), e.feature))
    return items[:limit]


def feature_phrase(item: Evidence) -> str:
    value = float(item.value)
    pair = BOOLEAN_PHRASE.get(item.feature)
    if pair is not None:
        return pair[1] if value else pair[0]
    template = FEATURE_PHRASE.get(item.feature)
    if template is None:
        return "%s at %g" % (item.feature.replace("_", " "), value)
    return template.format(v=value, i=int(value), a=abs(value))


def join_clauses(clauses: list[str]) -> str:
    if not clauses:
        return ""
    if len(clauses) == 1:
        return clauses[0]
    return ", ".join(clauses[:-1]) + " and " + clauses[-1]


def context_notes(detection: Detection) -> list[str]:
    ctx = detection.context or {}
    notes = []
    ja4_claims = ctx.get("ja4_claims")
    tcpfp_claims = ctx.get("tcpfp_claims")
    if ja4_claims and tcpfp_claims:
        notes.append("The TLS fingerprint claims %s while the TCP fingerprint looks like %s."
                     % (ja4_claims, tcpfp_claims))
    tier = str(ctx.get("shedding_tier", "none") or "none")
    if tier not in ("none", "0"):
        notes.append(SHEDDING_NOTE.format(tier=tier))
    if ctx.get("sampling_active"):
        notes.append(SAMPLING_NOTE.format(ratio=float(ctx.get("sampling_ratio", 1.0))))
    return notes


def explain(detection: Detection) -> str:
    ranked = top_evidence(detection.evidence, MAX_IN_SENTENCE)
    body = join_clauses([feature_phrase(item) for item in ranked])
    sentence = headline(detection) + (": " + body + "." if body else ".")
    notes = context_notes(detection)
    return " ".join([sentence] + notes)


def evidence_rows(detection: Detection, limit: int = MAX_EVIDENCE) -> list[dict]:
    rows = []
    for item in top_evidence(detection.evidence, limit):
        rows.append({"feature": item.feature, "value": float(item.value), "shap": float(item.contribution)})
    return rows
