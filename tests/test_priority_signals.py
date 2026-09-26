from dataclasses import replace

import pytest

from bench.traffic_cases import BASE, CLIENT, SERVER, dns_query, dns_cross_zone, download, regular_encrypted_session
from engine.detect.base import Context
from engine.detect.ddos import DdosDetector
from engine.detect.dga import DgaDetector
from engine.detect.encrypted import EncryptedDetector
from engine.pipeline import Engine
from engine.state.flow_table import FlowTable
from engine.types import SYN, TCP, UDP, PacketMeta


def feed(detector, packets):
    ctx, flows, hits = Context(), FlowTable(), []
    for packet in packets:
        flow = flows.observe(packet)
        ctx.begin_packet(packet, flow)
        hits.extend(detector.observe(packet, flow, ctx))
    return hits, ctx, flows


@pytest.mark.parametrize("proto,port", [(TCP, 443), (TCP, 53), (UDP, 443), (UDP, 5004)])
def test_large_benign_download_is_not_udp_reflection(proto, port):
    detector = DdosDetector()
    hits, ctx, _ = feed(detector, download(proto=proto, service=port))
    hits.extend(detector.tick(BASE + 12 * 10**9, ctx))
    assert hits == []


def test_reflection_closes_at_eof_and_does_not_dilute_after_silence():
    detector = DdosDetector()
    packets = list(download(proto=UDP, service=123, count=800))
    _, ctx, _ = feed(detector, packets)
    hits = detector.tick(BASE + 90 * 10**9, ctx)
    assert len(hits) == 1
    assert hits[0].subtype == "udp-reflection-amplification"
    assert hits[0].ts_ns == BASE + 2 * 10**9
    assert hits[0].context["feature_snapshot"]["pps_to_dst"] == 400
    assert hits[0].context["udp_egress_observed"] is False
    assert detector.tick(BASE + 91 * 10**9, ctx) == []


@pytest.mark.parametrize("proto", [TCP, UDP])
def test_growing_random_source_flood_has_transport_specific_evidence(proto):
    detector = DdosDetector()
    packets = (PacketMeta(BASE + i * 2_500_000, proto, 0x2D000000 + i, CLIENT,
                          30000 + i % 20000, 443, 60, tcp_flags=SYN if proto == TCP else 0)
               for i in range(2400))
    hits, _, _ = feed(detector, packets)
    assert hits
    assert hits[0].flow["proto"] == ("TCP" if proto == TCP else "UDP")
    assert hits[0].context["attribution_confidence"] == 0
    if proto == UDP:
        assert hits[0].context["extended_detection"]
        assert "syn_synack_ratio_1s" not in {e.feature for e in hits[0].evidence}
        # Context margins are serialized to four decimal places.
        assert [e.contribution for e in hits[0].evidence[:3]] == pytest.approx(
            hits[0].context["rule_margins"], abs=5e-5)


def test_completed_bucket_rejects_late_packets():
    detector = DdosDetector()
    _, ctx, flows = feed(detector, download(count=4))
    detector.tick(BASE + 2 * 10**9, ctx)
    late = next(download())
    assert detector.observe(late, flows.observe(late), ctx) == []
    assert not detector.pending


def test_record_types_are_scoped_to_source_and_domain():
    detector = DgaDetector()
    hits, _, _ = feed(detector, dns_cross_zone())
    assert hits == []
    assert detector.features()["qtype_txt_null_ratio"] == 0


@pytest.mark.parametrize("qtype", [1, 28, 15, 65])
def test_query_length_is_measured_without_treating_length_alone_as_attack(qtype):
    name = "a" * 60 + "." + "b" * 55 + ".example.com"
    detector = DgaDetector()
    hits, _, _ = feed(detector, [dns_query(i, name, qtype) for i in range(100)])
    assert hits == []
    assert detector.features()["qname_len"] == len(name)
    assert detector.features()["max_label_len"] == 60


@pytest.mark.parametrize("qtype", [10, 16])
def test_high_cardinality_txt_null_tunnel_still_alerts(qtype):
    detector = DgaDetector()
    hits, _, _ = feed(detector, (dns_query(i, f"encoded{i:050d}.tunnel.example.com", qtype)
                               for i in range(200)))
    assert any(hit.subtype == "dns-tunnel-txt-null" for hit in hits)


@pytest.mark.parametrize("proto", [TCP, UDP])
def test_sequence_features_refresh_after_handshake_then_stop_at_bounded_prefix(proto):
    detector = EncryptedDetector()
    hits, _, flows = feed(detector, regular_encrypted_session(proto=proto))
    assert hits == []
    features = detector.features()
    assert features["splt_len"] == 20
    assert features["splt_iat_mean"] == pytest.approx(0.1)
    assert features["splt_iat_cv"] == pytest.approx(0)
    assert features["splt_mean_abs_len"] == pytest.approx(300)
    assert features["splt_direction_changes"] == 19
    assert detector.sequence_updates == 2
    assert len(next(iter(flows)).splt) == 20
    if proto == UDP:
        assert "fingerprint_consistency_score" not in features
        assert "tls_version" not in features


def test_aggregate_records_never_fabricate_packet_timing():
    detector = EncryptedDetector()
    hits, _, flows = feed(detector, (replace(p, from_flow_record=True, packets=50)
                                     for p in regular_encrypted_session(proto=UDP)))
    assert hits == [] and detector.features() == {}
    assert next(iter(flows)).splt == []


def test_udp443_sequences_cannot_invent_a_tcp_trained_model_verdict():
    engine = Engine({"model_enabled": False, "anomaly_enabled": False})
    class RejectScoring:
        def score(self, values):
            if "splt_len" in values:
                pytest.fail("Unsupported UDP/443 sequence reached a TCP-trained model")
            return None
    engine.tier1 = RejectScoring()
    rows = []
    engine.on_vector = rows.append
    # Stay within one bucket so unrelated DDoS snapshots do not invoke scoring.
    for i, packet in enumerate(regular_encrypted_session(proto=UDP, count=20)):
        assert engine.feed(replace(packet, ts_ns=BASE + i * 1_000_000)) == []
    assert [row["values"]["splt_len"] for row in rows if "splt_len" in row["values"]] == [8, 20]


def test_many_interleaved_sequences_cannot_exceed_total_sample_budget():
    flows = FlowTable(capacity=100, splt_capacity=2)
    for i in range(20):
        for port in range(40000, 40020):
            flows.observe(PacketMeta(BASE + i * 10**6, UDP, CLIENT, SERVER, port, 443, 100))
    assert sum(len(flow.splt) for flow in flows) == 40
    assert flows.nbytes <= flows.capacity_bytes
