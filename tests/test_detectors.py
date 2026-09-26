from __future__ import annotations

import json
import os

import pytest

from engine.decode.packet import format_ip
from engine.detect.base import Context, Reference, flow_features
from engine.detect.beaconing import BeaconDetector
from engine.detect.ddos import DdosDetector
from engine.detect.dga import DgaDetector
from engine.detect.encrypted import EncryptedDetector
from engine.detect.exfil import ExfilDetector
from engine.detect.scan import ScanDetector
from engine.features import registry
from engine.sources.pcap_source import PcapSource
from engine.state.flow_table import FlowTable
from engine.types import ACK, SYN, TCP, THREAT_CLASSES, UDP, DNSMeta, PacketMeta, TLSMeta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCENARIO_DIR = os.path.join(ROOT, "data", "scenarios")

ATTACK_SCENARIOS = {
    "syn_flood": "volumetric-ddos",
    "udp_reflection": "volumetric-ddos",
    "slowloris": "volumetric-ddos",
    "beacon_jitter": "c2-beaconing",
    "dga_burst": "dga-dns-tunnelling",
    "dns_tunnel": "dga-dns-tunnelling",
    "ja4_spoof": "encrypted-malware",
    "port_scan": "recon-scanning",
    "exfil_drip": "data-exfiltration",
    "exfil_bulk": "data-exfiltration",
}

ALL_SCENARIOS = ["benign"] + sorted(ATTACK_SCENARIOS)

_CACHE: dict[str, dict] = {}


def build_detectors() -> list:
    return [
        DdosDetector(),
        BeaconDetector(),
        DgaDetector(),
        EncryptedDetector(),
        ScanDetector(),
        ExfilDetector(),
    ]


def replay(scenario: str, tick_s: float = 30.0) -> dict:
    if scenario in _CACHE:
        return _CACHE[scenario]
    ctx = Context()
    flows = FlowTable()
    detectors = build_detectors()
    detections = []
    last_tick = 0
    for meta in PcapSource(os.path.join(SCENARIO_DIR, scenario + ".pcap")):
        flow = flows.observe(meta)
        ctx.begin_packet(meta, flow)
        for detector in detectors:
            detections.extend(detector.observe(meta, flow, ctx))
        if meta.ts_ns - last_tick >= tick_s * 1e9:
            last_tick = meta.ts_ns
            for detector in detectors:
                detections.extend(detector.tick(meta.ts_ns, ctx))
    for detector in detectors:
        detections.extend(detector.tick(ctx.now_ns, ctx))
    result = {
        "detections": detections,
        "detectors": detectors,
        "ctx": ctx,
        "flows": flows,
        "labels": load_labels(scenario),
    }
    _CACHE[scenario] = result
    return result


def load_labels(scenario: str) -> dict:
    with open(os.path.join(SCENARIO_DIR, scenario + ".labels.json"), "r", encoding="utf-8") as fh:
        return json.load(fh)


def windows(labels: dict) -> list[tuple[float, float]]:
    return [(a["start_ts"], a["end_ts"]) for a in labels.get("attacks", [])]


def inside(detection, spans: list[tuple[float, float]]) -> bool:
    ts = detection.ts_ns / 1e9
    return any(start <= ts <= end for start, end in spans)


def syn(ts_ns: int, src: int, dst: int, port: int, length: int = 44) -> PacketMeta:
    return PacketMeta(
        ts_ns=ts_ns, proto=TCP, src_ip=src, dst_ip=dst, src_port=40000 + (port % 20000),
        dst_port=port, length=length, tcp_flags=SYN, ttl=64, tcp_window=65535, tcp_mss=1460,
        tcp_opts=(2, 4, 8, 1, 3),
    )


def query(ts_ns: int, src: int, name: str, qtype: int = 1) -> PacketMeta:
    return PacketMeta(
        ts_ns=ts_ns, proto=UDP, src_ip=src, dst_ip=53, src_port=40000, dst_port=53, length=80,
        dns=DNSMeta(qname=name, qtype=qtype, qname_len=len(name), is_response=False, answer_count=0),
    )


def feed(detector, metas, ctx: Context, flows: FlowTable) -> list:
    out = []
    for meta in metas:
        flow = flows.observe(meta)
        ctx.begin_packet(meta, flow)
        out.extend(detector.observe(meta, flow, ctx))
    return out


@pytest.mark.parametrize("scenario", sorted(ATTACK_SCENARIOS))
def test_expected_threat_class_fires_inside_the_labelled_window(scenario: str) -> None:
    result = replay(scenario)
    expected = ATTACK_SCENARIOS[scenario]
    spans = windows(result["labels"])
    hits = [d for d in result["detections"] if d.threat_class == expected and inside(d, spans)]
    assert hits, "{0}: no {1} detection inside {2}".format(scenario, expected, spans)


def test_benign_scenario_raises_no_alert_at_all() -> None:
    result = replay("benign")
    assert result["detections"] == [], [
        (d.threat_class, d.subtype, d.summary) for d in result["detections"]
    ]


@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_no_detection_falls_outside_a_labelled_attack_window(scenario: str) -> None:
    result = replay(scenario)
    spans = windows(result["labels"])
    stray = [(d.threat_class, d.subtype, d.ts_ns / 1e9) for d in result["detections"]
             if not inside(d, spans)]
    assert stray == []


@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_no_detection_names_a_threat_class_the_labels_do_not(scenario: str) -> None:
    result = replay(scenario)
    declared = {a["threat_class"] for a in result["labels"]["attacks"]}
    seen = {d.threat_class for d in result["detections"]}
    assert seen <= declared, sorted(seen - declared)


def test_a_client_hello_without_its_syn_is_not_a_disagreement() -> None:
    ctx = Context()
    flows = FlowTable()
    detector = EncryptedDetector()
    base = 1_700_000_000_000_000_000
    client, server = 0x0A140213, 0x5DB8D803
    hello = TLSMeta(ja4="t13d1516h2_8daaf6152771_e5627efa2ab1", version=0x0303, alpn="h2",
                    sni_present=True, ext_count=16, is_client_hello=True)
    meta = PacketMeta(ts_ns=base, proto=TCP, src_ip=client, dst_ip=server, src_port=51000,
                      dst_port=443, length=571, tcp_flags=ACK, ttl=64, tls=hello)
    assert feed(detector, [meta], ctx, flows) == []
    assert detector.no_syn == 1
    assert any(row["reason"] == "no-syn-observed" for row in ctx.suppression_summary())


def test_beacon_decoy_pollers_do_not_alert() -> None:
    result = replay("beacon_jitter")
    decoys = set(result["labels"]["attacks"][0]["benign_decoys"]["hosts"])
    sources = {d.flow["src_ip"] for d in result["detections"] if d.threat_class == "c2-beaconing"}
    assert not (sources & decoys), sources & decoys


def test_ddos_reports_the_spoofed_flood_sub_type_with_growing_source_cardinality() -> None:
    hits = [d for d in replay("syn_flood")["detections"] if d.threat_class == "volumetric-ddos"]
    assert hits
    assert all(d.subtype == "syn-flood-spoofed-source" for d in hits)
    values = {e.feature: e.value for e in hits[0].evidence}
    assert values["entropy_explosion_score"] >= 0.5
    assert values["src_cardinality_growth"] > 4.0
    assert values["syn_synack_ratio_1s"] > 4.0
    assert hits[0].context["attribution_confidence"] == 0.0


def test_ddos_reports_the_reflection_sub_type_with_a_saturated_source_set() -> None:
    hits = [d for d in replay("udp_reflection")["detections"]
            if d.threat_class == "volumetric-ddos"]
    assert hits
    assert all(d.subtype == "udp-reflection-amplification" for d in hits)
    values = {e.feature: e.value for e in hits[0].evidence}
    assert values["entropy_collapse_score"] >= 0.5
    assert values["src_cardinality_growth"] < 3.0
    assert values["amplification_ratio"] > 5.0


@pytest.mark.parametrize("pps", [400, 2000, 8000, 30000])
def test_the_spoofed_flood_score_does_not_fade_as_the_flood_gets_bigger(pps: int) -> None:
    ctx = Context()
    flows = FlowTable()
    detector = DdosDetector()
    base = 1_700_000_000_000_000_000
    victim = 0x0A140411
    found = []
    for second in range(6):
        for i in range(pps):
            src = 0x2D000000 + second * pps + i
            meta = syn(base + int(second * 1e9) + int(i * 1e9 / pps), src, victim, 443)
            flow = flows.observe(meta)
            ctx.begin_packet(meta, flow)
            found.extend(detector.observe(meta, flow, ctx))
    values = detector.features()
    assert values["entropy_explosion_score"] >= 0.5, (pps, values["src_entropy_ratio_1s"])
    assert found, pps


def test_the_two_ddos_sub_types_are_distinguishable_and_carry_opposite_advice() -> None:
    flood = [d for d in replay("syn_flood")["detections"] if d.threat_class == "volumetric-ddos"][0]
    reflection = [d for d in replay("udp_reflection")["detections"]
                  if d.threat_class == "volumetric-ddos"][0]
    assert flood.subtype != reflection.subtype
    assert flood.context["response_note"] != reflection.context["response_note"]
    assert flood.context["sub_type_basis"] != reflection.context["sub_type_basis"]


def test_slowloris_is_reported_as_connection_exhaustion_not_as_a_volumetric_flood() -> None:
    hits = [d for d in replay("slowloris")["detections"] if d.threat_class == "volumetric-ddos"]
    assert hits
    assert all(d.subtype == "connection-exhaustion" for d in hits)
    values = {e.feature: e.value for e in hits[0].evidence}
    assert values["pps_to_dst"] < 60.0
    assert values["teardown_ratio_60s"] <= 0.1


def test_beacon_alert_states_its_maximum_detectable_period() -> None:
    hits = [d for d in replay("beacon_jitter")["detections"] if d.threat_class == "c2-beaconing"]
    assert hits
    cover = hits[0].context["coverage"]
    assert cover["max_period_s"] == 21600.0
    assert cover["min_samples"] == 12.0
    assert "21600" in hits[0].context["coverage_note"]
    detector = [d for d in replay("beacon_jitter")["detectors"] if d.name == "beaconing"][0]
    assert detector.coverage["max_period_s"] == 21600.0


def test_beacon_recovers_the_scenario_period_and_names_the_clause_that_carried_it() -> None:
    hits = [d for d in replay("beacon_jitter")["detections"] if d.threat_class == "c2-beaconing"]
    period = replay("beacon_jitter")["labels"]["attacks"][0]["period_s"]
    assert hits
    for hit in hits:
        values = {e.feature: e.value for e in hit.evidence}
        assert abs(values["ls_peak_period_s"] - period) / period < 0.15
        clauses = hit.context["clauses"]
        assert clauses["periodogram"]["passed"] or clauses["regularity"]["passed"]
        if hit.context["carried_by"] == "periodogram significance":
            assert values["ls_fap"] < 1e-3
        else:
            assert values["iat_cv"] <= 0.35
            assert values["beacon_sample_count"] >= 20


def test_the_jittered_beacon_reaches_every_infected_host_in_the_scenario() -> None:
    result = replay("beacon_jitter")
    infected = set(result["labels"]["attacks"][0]["attackers"])
    seen = {d.flow["src_ip"] for d in result["detections"] if d.threat_class == "c2-beaconing"}
    missed = infected - seen
    assert len(missed) <= 1, missed


def test_a_udp_beacon_is_not_reported_as_tcp() -> None:
    ctx = Context()
    flows = FlowTable()
    detector = BeaconDetector()
    base = 1_700_000_000_000_000_000
    client, server = 0x0A140213, 0x2E1A0F04
    metas = []
    for i in range(40):
        port = 41000 + i
        metas.append(PacketMeta(
            ts_ns=base + int(i * 45.0 * 1e9), proto=UDP, src_ip=client, dst_ip=server,
            src_port=port, dst_port=8053, length=300,
        ))
        metas.append(PacketMeta(
            ts_ns=base + int(i * 45.0 * 1e9) + 20_000_000, proto=UDP, src_ip=server,
            dst_ip=client, src_port=8053, dst_port=port, length=200,
        ))
    feed(detector, metas, ctx, flows)
    hits = detector.tick(metas[-1].ts_ns, ctx)
    assert hits, "a 45 s udp beacon must be assessable"
    assert hits[0].flow["proto"] == "UDP"
    assert hits[0].flow["dst_port"] == 8053


def test_the_first_tunnel_alert_does_not_quote_an_unlearned_baseline() -> None:
    hits = [d for d in replay("dns_tunnel")["detections"] if d.subtype == "dns-tunnel-txt-null"]
    assert hits
    first = hits[0]
    assert first.context["subdomain_baseline"] == "none learned yet"
    assert first.context["baseline_windows"] == 0
    assert "no baseline learned" in first.summary
    assert {e.feature: e.value for e in first.evidence}["subdomain_excess"] == 1.0


def test_a_zone_learns_its_baseline_from_traffic_that_never_alerts() -> None:
    ctx = Context()
    flows = FlowTable()
    detector = DgaDetector()
    base = 1_700_000_000_000_000_000
    src = 0x0A140213
    metas = []
    for window in range(3):
        for i in range(40):
            name = "chunk{0}-{1}.files.example.net".format(window, i)
            metas.append(query(base + int((window * 320 + i) * 1e9), src, name))
    assert feed(detector, metas, ctx, flows) == []
    zone = detector.zones.peek((src, "example.net"))
    assert zone is not None
    assert zone.ewma.n >= 2
    assert zone.ewma.mean > 0.0


def test_dga_catches_both_families_and_names_the_dictionary_one_separately() -> None:
    hits = [d for d in replay("dga_burst")["detections"]
            if d.threat_class == "dga-dns-tunnelling"]
    subtypes = {d.subtype for d in hits}
    assert "dga-high-entropy" in subtypes
    assert "dga-dictionary" in subtypes


def test_the_dictionary_alert_is_honest_that_the_per_name_score_does_not_separate_it() -> None:
    hits = [d for d in replay("dga_burst")["detections"] if d.subtype == "dga-dictionary"]
    assert hits
    values = {e.feature: e.value for e in hits[0].evidence}
    assert values["dga_mean_name_score"] < 0.55
    assert values["nx_response_ratio"] >= 0.5
    assert values["distinct_regdom_300s"] >= 20.0
    assert "campaign" in hits[0].context["separation"]


def test_the_bigram_model_separates_algorithmic_names_but_not_dictionary_names() -> None:
    model = Reference().bigrams
    assert model is not None
    benign = ["northwind", "contoso", "fabrikam", "woodgrove", "relecloud", "southridge"]
    algorithmic = ["kulwjb5w4qe8439", "e45vyy3ah2zc8vnjt7", "wvngwfox8g102g", "4s1isgybdninzqwhm"]
    dictionary = ["anchorhollow", "hollowcopper", "mandrelprairie", "harbornotch"]
    mean = lambda xs: sum(model.score(x) for x in xs) / len(xs)
    assert mean(algorithmic) < mean(benign) - 1.0
    assert abs(mean(dictionary) - mean(benign)) < 0.5


def test_dns_tunnelling_fires_on_subdomain_cardinality_and_query_type() -> None:
    hits = [d for d in replay("dns_tunnel")["detections"] if d.subtype == "dns-tunnel-txt-null"]
    assert hits
    values = {e.feature: e.value for e in hits[0].evidence}
    assert values["subdomain_cardinality"] >= 50.0
    assert values["qtype_txt_null_ratio"] >= 0.3
    assert "encoding" in hits[0].context["evasion_note"]


def test_the_cdn_allowlist_suppresses_and_logs_rather_than_dropping_silently() -> None:
    ctx = Context()
    flows = FlowTable()
    detector = DgaDetector()
    base = 1_700_000_000_000_000_000
    metas = []
    for i in range(400):
        name = "n{0:08x}.edge.akamaiedge.net".format(i)
        metas.append(query(base + i * 10_000_000, 0x0A140101, name, qtype=16))
    detections = feed(detector, metas, ctx, flows)
    assert not [d for d in detections if d.subtype == "dns-tunnel-txt-null"]
    assert detector.suppressed > 0
    summary = ctx.suppression_summary()
    assert any(row["reason"] == "cdn-wildcard-allowlist" and row["count"] > 0 for row in summary)
    assert any(row["detector"] == "dga" for row in ctx.suppression_log)


def test_encrypted_alert_carries_both_claims_side_by_side() -> None:
    hits = [d for d in replay("ja4_spoof")["detections"]
            if d.threat_class == "encrypted-malware"]
    assert hits
    hit = hits[0]
    assert hit.subtype == "ja4-tcp-fingerprint-disagreement"
    ja4 = hit.context["ja4_claims"]
    tcp = hit.context["tcpfp_claims"]
    assert ja4["expected_tcp_families"] == ["windows"]
    assert tcp["family"] == "linux"
    assert "user space" in ja4["chosen_by"]
    assert "kernel" in tcp["chosen_by"]
    assert "reputation" in hit.context["why_this_matters"]


def test_every_spoofing_host_in_the_scenario_is_reported() -> None:
    labels = replay("ja4_spoof")["labels"]
    expected = set(labels["attacks"][0]["attackers"])
    seen = {d.flow["src_ip"] for d in replay("ja4_spoof")["detections"]
            if d.threat_class == "encrypted-malware"}
    assert expected <= seen


def test_scan_reports_which_pattern_fired() -> None:
    hits = [d for d in replay("port_scan")["detections"] if d.threat_class == "recon-scanning"]
    patterns = {d.context["pattern"] for d in hits}
    assert "vertical" in patterns
    assert "horizontal" in patterns
    subtypes = {d.subtype for d in hits}
    assert {"vertical-scan-fast", "vertical-scan-slow", "horizontal-sweep"} <= subtypes


def test_fast_and_slow_vertical_scans_are_separated_by_the_one_second_scale() -> None:
    hits = [d for d in replay("port_scan")["detections"] if d.context.get("pattern") == "vertical"]
    fast = [d for d in hits if d.subtype == "vertical-scan-fast"]
    slow = [d for d in hits if d.subtype == "vertical-scan-slow"]
    assert fast and slow
    fast_values = {e.feature: e.value for e in fast[0].evidence}
    slow_values = {e.feature: e.value for e in slow[0].evidence}
    assert fast_values["vertical_fanout_1s"] >= 10.0
    assert slow_values["vertical_fanout_1s"] < 10.0


def test_strobe_pattern_fires_on_a_synthetic_few_ports_many_hosts_sweep() -> None:
    ctx = Context()
    flows = FlowTable()
    detector = ScanDetector()
    base = 1_700_000_000_000_000_000
    metas = []
    step = 20_000_000
    index = 0
    for host in range(80):
        for port in (139, 445, 3389):
            metas.append(syn(base + index * step, 0x05BC3E8C, 0x0A140000 + host, port))
            index += 1
    detections = feed(detector, metas, ctx, flows)
    strobes = [d for d in detections if d.subtype == "strobe-scan"]
    assert strobes
    assert strobes[0].context["pattern"] == "strobe"
    assert "no committed scenario" in strobes[0].context["corpus_note"]


def test_exfiltration_beats_a_single_window_threshold() -> None:
    hits = [d for d in replay("exfil_drip")["detections"]
            if d.threat_class == "data-exfiltration"]
    assert hits
    values = {e.feature: e.value for e in hits[-1].evidence}
    assert values["out_in_ratio_ewma"] > 3.0
    assert values["sustained_asymmetry_s"] >= 300.0
    assert values["upload_burst_score"] < 0.25
    assert "single window" in hits[-1].context["why_ewma"]


def test_bulk_exfiltration_is_reported_as_a_burst_not_a_drip() -> None:
    hits = [d for d in replay("exfil_bulk")["detections"]
            if d.threat_class == "data-exfiltration" and d.source == "rule"]
    assert hits
    assert all(d.subtype == "upload-burst" for d in hits), [d.subtype for d in hits]
    values = {e.feature: e.value for e in hits[0].evidence}
    assert values["peak_window_out_bytes"] >= 5_000_000.0
    assert values["upload_burst_score"] > 0.5
    assert hits[0].context["pattern"] == "burst"
    assert hits[0].context["orientation"]["guessed"] is False


def test_the_two_exfiltration_shapes_carry_opposite_burst_scores() -> None:
    drip = [d for d in replay("exfil_drip")["detections"] if d.subtype == "slow-drip-upload"]
    burst = [d for d in replay("exfil_bulk")["detections"] if d.subtype == "upload-burst"]
    assert drip and burst
    drip_score = {e.feature: e.value for e in drip[0].evidence}["upload_burst_score"]
    burst_score = {e.feature: e.value for e in burst[0].evidence}["upload_burst_score"]
    assert drip_score < 0.25 < burst_score


def test_exfil_ignores_a_flow_whose_direction_was_never_established() -> None:
    ctx = Context()
    flows = FlowTable()
    detector = ExfilDetector()
    base = 1_700_000_000_000_000_000
    client, server = 0x0A140213, 0x2E1A0F04
    metas = []
    for i in range(400):
        metas.append(PacketMeta(
            ts_ns=base + i * 1_000_000_000, proto=TCP, src_ip=client, dst_ip=server,
            src_port=51000, dst_port=51001, length=1400, tcp_flags=ACK,
        ))
    assert feed(detector, metas, ctx, flows) == []
    assert detector.unoriented == len(metas)


def test_the_exfil_allowlist_suppresses_and_logs_rather_than_dropping_silently() -> None:
    ctx = Context()
    flows = FlowTable()
    detector = ExfilDetector()
    base = 1_700_000_000_000_000_000
    client, server = 0x0A140213, 0x0A140050
    metas = [syn(base, client, server, 445)]
    for i in range(1, 2000):
        metas.append(PacketMeta(
            ts_ns=base + i * 1_000_000_000, proto=TCP, src_ip=client, dst_ip=server,
            src_port=40000, dst_port=445, length=1400, tcp_flags=ACK,
        ))
        if i % 20 == 0:
            metas.append(PacketMeta(
                ts_ns=base + i * 1_000_000_000 + 1000, proto=TCP, src_ip=server, dst_ip=client,
                src_port=445, dst_port=40000, length=60, tcp_flags=ACK,
            ))
    detections = feed(detector, metas, ctx, flows)
    assert detections == []
    assert detector.suppressed > 0
    assert any(row["reason"] == "exfil-allowlist" for row in ctx.suppression_summary())


def test_every_detection_carries_a_usable_alert_payload() -> None:
    required = {"proto", "src_ip", "dst_ip", "src_port", "dst_port", "directionality",
                "completeness_flag", "window_start", "window_end"}
    for scenario in ALL_SCENARIOS:
        for detection in replay(scenario)["detections"]:
            assert detection.threat_class in THREAT_CLASSES
            assert 0.0 <= detection.confidence <= 1.0
            assert detection.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
            assert detection.subtype
            assert len(detection.summary) > 40
            assert detection.evidence
            assert required <= set(detection.flow)
            assert detection.flow["window_end"] >= detection.flow["window_start"]
            assert "confidence_basis" in detection.context


def test_confidence_is_derived_from_the_margin_past_the_threshold() -> None:
    for scenario in sorted(ATTACK_SCENARIOS):
        for detection in replay(scenario)["detections"]:
            margins = detection.context["rule_margins"]
            assert margins, detection.summary
            assert all(0.0 <= m <= 1.0 for m in margins)
            expected = round(0.5 + 0.5 * (sum(margins) / len(margins)), 4)
            assert abs(detection.confidence - expected) < 1e-3
            assert 0.5 <= detection.confidence <= 1.0


def test_severity_follows_confidence() -> None:
    bands = {"LOW": (0.0, 0.60), "MEDIUM": (0.60, 0.75), "HIGH": (0.75, 0.90),
             "CRITICAL": (0.90, 1.01)}
    for scenario in sorted(ATTACK_SCENARIOS):
        for detection in replay(scenario)["detections"]:
            low, high = bands[detection.severity]
            assert low <= detection.confidence < high


def test_every_feature_a_detector_emits_is_documented_in_the_registry() -> None:
    emitted: set[str] = set()
    for scenario in sorted(ATTACK_SCENARIOS):
        result = replay(scenario)
        for detector in result["detectors"]:
            emitted.update(detector.features())
        for detection in result["detections"]:
            emitted.update(e.feature for e in detection.evidence)
    assert registry.unregistered({name: 0.0 for name in emitted}) == []


def test_flow_structural_features_are_documented_too() -> None:
    result = replay("benign")
    flow = next(iter(result["flows"]))
    assert registry.unregistered(flow_features(flow)) == []


def test_the_registry_reads_as_a_feature_dictionary() -> None:
    names = registry.names()
    assert len(names) == len(set(names))
    assert registry.COUNT >= 90
    for row in registry.FEATURES:
        assert row["group"] in registry.GROUPS
        assert row["dtype"] in ("int", "float", "bool")
        assert len(row["definition"]) >= 30
        assert len(row["rationale"]) >= 40
        assert row["threat_class"] == "all" or row["threat_class"] in THREAT_CLASSES
    for group in registry.GROUPS:
        assert registry.FEATURES_BY_GROUP[group]


def test_detector_state_stays_bounded_under_a_hostile_key_space() -> None:
    ctx = Context({"dst_hot_capacity": 4, "scan_hll_capacity": 64, "dns_hll_capacity": 64})
    flows = FlowTable(capacity=256)
    detectors = [
        DdosDetector({"monitor_capacity": 64}),
        ScanDetector({"source_capacity": 64}),
        ExfilDetector({"peer_capacity": 64, "fanout_capacity": 64}),
        DgaDetector({"source_capacity": 64, "zone_capacity": 64}),
        EncryptedDetector({"host_capacity": 64, "flow_capacity": 64}),
    ]
    base = 1_700_000_000_000_000_000
    metas = []
    for i in range(6000):
        metas.append(syn(base + i * 1_000_000, 0x01000000 + i, 0x02000000 + i, 1 + (i % 60000)))
    for meta in metas:
        flow = flows.observe(meta)
        ctx.begin_packet(meta, flow)
        for detector in detectors:
            detector.observe(meta, flow, ctx)
    assert len(flows) <= 256
    assert len(detectors[0].table) <= 64
    assert len(detectors[1].sources) <= 64
    assert len(detectors[2].peers) <= 64
    assert len(detectors[3].sources) <= 64
    assert len(detectors[4].hosts) <= 64
    for detector in detectors:
        assert detector.nbytes < 40_000_000
    assert ctx.nbytes <= sum(ctx.memory_caps_bytes().values())


def test_the_detection_path_opens_no_socket() -> None:
    banned = ("import socket", "requests", "urllib", "http.client", "aiohttp", "subprocess",
              "socket.socket")
    directory = os.path.join(ROOT, "engine", "detect")
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(directory, name), "r", encoding="ascii") as fh:
            text = fh.read()
        for word in banned:
            assert word not in text, "{0} references {1}".format(name, word)


def test_reference_data_is_present_and_states_where_it_came_from() -> None:
    reference = Reference()
    assert reference.bigrams is not None
    assert reference.bigrams.corpus["english_words"]["count"] >= 2000
    assert "no network" in reference.bigrams.corpus["english_words"]["origin"]
    assert len(reference.ja4_families) >= 3
    assert "unknown_policy" in reference.ja4_notes
    assert reference.wildcard_reason("edge.akamaiedge.net")
    assert not reference.wildcard_reason("dnsc2-relay.net")
    assert reference.exfil_reason(0x0A140050, 443)
    assert not reference.exfil_reason(0xB9F4193D, 443)


def test_registrable_domain_handles_two_level_public_suffixes() -> None:
    reference = Reference()
    assert reference.registrable("www.northwind.co.in") == "northwind.co.in"
    assert reference.registrable("a.b.t.dnsc2-relay.net") == "dnsc2-relay.net"
    assert reference.registrable("kulwjb5w4qe8439.top") == "kulwjb5w4qe8439.top"


def test_detector_names_and_classes_cover_the_six_mandated_threats() -> None:
    covered = set()
    for detector in build_detectors():
        assert detector.name
        assert detector.classes
        covered.update(detector.classes)
    assert covered == set(THREAT_CLASSES) - {"benign"}


def test_alert_source_ip_is_honest_about_spoofing() -> None:
    hits = [d for d in replay("syn_flood")["detections"] if d.threat_class == "volumetric-ddos"]
    assert "spoofed" in hits[0].flow["src_ip"]
    assert format_ip(0) == "0.0.0.0"
