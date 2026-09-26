from __future__ import annotations

from dataclasses import dataclass
import sys

from engine.decode.packet import format_ip
from engine.decode.tcp_fingerprint import fingerprint_family, tcp_fingerprint
from engine.detect.base import (
    Context,
    Detector,
    LruMap,
    evidence,
    flow_identifier_of,
    margin,
)
from engine.state.cms import CountMinSketch
from engine.state.welford import Moments
from engine.types import ACK, SYN, TCP, UDP, TLSMeta, Detection, FlowState, PacketMeta

THREAT = "encrypted-malware"

SUB_DISAGREE = "ja4-tcp-fingerprint-disagreement"
SUB_RARE_PAIR = "ja4-tcp-pairing-outlier"

REFERENCE_NOTE = (
    "data/reference/ja4_tcp_reference.json, learned from the spoof-free benign baseline capture. it "
    "covers three tls stacks and makes no claim about a ja4 it has not seen"
)

DEFAULTS = {
    "cooldown_s": 300.0,
    "min_pair_support": 20.0,
    "minority_share": 0.15,
    "host_capacity": 20000,
    "flow_capacity": 50000,
    "cms_width": 4093,
    "cms_depth": 4,
}


@dataclass(slots=True)
class SequenceState:
    first_ts_ns: int = -1
    samples: int = 0
    tls: TLSMeta | None = None
    consistency: float | None = None
    share: float = 0.0
    ja4_seen: float = 0.0


class EncryptedDetector(Detector):
    name = "encrypted"
    classes = [THREAT]

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        cfg = dict(DEFAULTS)
        cfg.update(self.config)
        self.config = cfg
        self.hellos = 0
        self.unknown_ja4 = 0
        self.no_syn = 0
        self.agreements = 0
        self.hosts = LruMap(int(cfg["host_capacity"]), lambda: ("", 0), 160)
        self.flow_fp = LruMap(int(cfg["flow_capacity"]), lambda: "", 160)
        self.last_alert = LruMap(4096, lambda: -1, 120)
        self.pair_counts = CountMinSketch(int(cfg["cms_width"]), int(cfg["cms_depth"]), seed=71)
        self.ja4_counts = CountMinSketch(int(cfg["cms_width"]), int(cfg["cms_depth"]), seed=72)
        self.sequences = LruMap(int(cfg["flow_capacity"]), SequenceState,
                                sys.getsizeof(SequenceState()) + 256)
        self.sequence_updates = 0
        self.udp443_sequence_updates = 0

    def observe(self, meta: PacketMeta, flow: FlowState, ctx: Context) -> list[Detection]:
        if meta.from_flow_record:
            return []  # Aggregated records cannot reconstruct per-packet sequences.
        if meta.proto == UDP:
            if 443 in (meta.src_port, meta.dst_port):
                self._sequence(meta, flow)
            return []
        if meta.proto != TCP:
            return []
        if (meta.tcp_flags & SYN) and not (meta.tcp_flags & ACK):
            fp = tcp_fingerprint(meta)
            if fp:
                self.flow_fp.put(flow.key, fp)
                seen, count = self.hosts.get(meta.src_ip)
                self.hosts.put(meta.src_ip, (fp, count + 1 if seen == fp else 1))
        tls = meta.tls
        if tls is None or not tls.is_client_hello or not tls.ja4:
            if flow.ja4:
                self._sequence(meta, flow)
            return []
        self.hellos += 1
        state = self._sequence_state(flow)
        state.tls = tls
        return self._assess(meta, flow, tls.ja4, ctx)

    def _sequence_state(self, flow: FlowState) -> SequenceState:
        state = self.sequences.get(flow.key)
        if state.first_ts_ns != flow.first_ts_ns:
            state = self.sequences.put(flow.key, SequenceState(first_ts_ns=flow.first_ts_ns))
        return state

    def _sequence(self, meta: PacketMeta, flow: FlowState) -> None:
        state = self._sequence_state(flow)
        count = len(flow.splt)
        # Score at two bounded milestones, once per milestone. Never rescore the
        # same frozen prefix on every subsequent packet of a long transfer.
        if count not in (8, 20) or count <= state.samples:
            return
        state.samples = count
        self._features = self._features_for(flow, state.consistency, state.share,
                                             state.ja4_seen, meta, state.tls)
        self.sequence_updates += 1
        if meta.proto == UDP:
            self.udp443_sequence_updates += 1

    def _assess(self, meta: PacketMeta, flow: FlowState, ja4: str, ctx: Context) -> list[Detection]:
        fp = self.flow_fp.peek(flow.key) or ""
        host_fp, host_count = self.hosts.peek(meta.src_ip) or ("", 0)
        if not fp:
            fp = host_fp
        if not fp:
            self.no_syn += 1
            ctx.suppress(self.name, "no-syn-observed", format_ip(meta.src_ip))
            return []
        family = fingerprint_family(fp)
        row = ctx.reference.ja4_families.get(ja4, {})
        expected = tuple(row.get("expected_tcp_families", ()))
        label = row.get("label", "")
        key = ja4.encode("ascii", "replace")
        self.ja4_counts.add(key)
        self.pair_counts.add(key + b"|" + family.encode("ascii"))
        pair_seen = float(self.pair_counts.estimate(key + b"|" + family.encode("ascii")))
        ja4_seen = float(self.ja4_counts.estimate(key))
        share = pair_seen / ja4_seen if ja4_seen > 0 else 1.0
        if expected:
            consistency = 1.0 if family in expected else 0.0
        else:
            consistency = 0.5
            self.unknown_ja4 += 1
        feats = self._features_for(flow, consistency, share, ja4_seen, meta)
        self._features = feats
        state = self._sequence_state(flow)
        state.consistency, state.share, state.ja4_seen = consistency, share, ja4_seen
        state.samples = len(flow.splt)
        if consistency == 1.0:
            self.agreements += 1
            return []
        now_ns = meta.ts_ns
        last = int(self.last_alert.get(meta.src_ip))
        if last >= 0 and now_ns - last < float(self.config["cooldown_s"]) * 1e9:
            return []
        det = None
        if consistency == 0.0:
            det = self._disagreement(meta, flow, ja4, label, expected, family, fp, host_count, row, feats)
        elif ja4_seen >= float(self.config["min_pair_support"]) \
                and share <= float(self.config["minority_share"]):
            det = self._outlier(meta, flow, ja4, family, fp, share, ja4_seen, feats)
        if det is None:
            return []
        self.last_alert.put(meta.src_ip, now_ns)
        return [det]

    def _features_for(
        self, flow: FlowState, consistency: float | None, share: float, ja4_seen: float,
        meta: PacketMeta, saved_tls: TLSMeta | None = None,
    ) -> dict[str, float]:
        splt = flow.splt
        gaps = Moments()
        lengths = Moments()
        ups = 0.0
        downs = 0.0
        changes = 0
        previous = 0
        for index, (length, gap_us) in enumerate(splt):
            if index:  # The first packet has no preceding inter-arrival interval.
                gaps.add(float(gap_us) / 1e6)
            lengths.add(abs(float(length)))
            if length >= 0:
                ups += float(length)
            else:
                downs += float(-length)
            sign = 1 if length >= 0 else -1
            if previous and sign != previous:
                changes += 1
            previous = sign
        tls = saved_tls or meta.tls
        values = {
            "splt_len": float(len(splt)),
            "splt_mean_abs_len": float(lengths.mean),
            "splt_len_cv": float(lengths.cv),
            "splt_iat_mean": float(gaps.mean),
            "splt_iat_cv": float(gaps.cv),
            "splt_up_down_ratio": ups / downs if downs > 0.0 else ups,
            "splt_direction_changes": float(changes),
        }
        if consistency is not None:
            values.update(fingerprint_consistency_score=float(consistency),
                          ja4_tcp_pair_share=float(share), ja4_observation_count=float(ja4_seen))
        if tls is not None:
            values.update(tls_version=float(tls.version), tls_ext_count=float(tls.ext_count),
                          tls_alpn_is_h2=float(tls.alpn == "h2"))
        return values

    def _disagreement(
        self, meta: PacketMeta, flow: FlowState, ja4: str, label: str, expected: tuple,
        family: str, fp: str, host_count: int, row: dict, f: dict
    ) -> Detection:
        support = float(row.get("support_hosts", 0))
        margins = [
            margin(float(row.get("confidence", 0.0)), 0.5, 0.5),
            margin(support, 3.0, 12.0),
            margin(float(host_count), 2.0, 10.0),
        ]
        end = meta.ts_ns / 1e9
        flow_id = flow_identifier_of(flow, flow.first_ts_ns / 1e9, end)
        claims = "; ".join(expected) if expected else "unknown"
        return self._emit(
            meta.ts_ns, THREAT, SUB_DISAGREE, margins, flow_id,
            evidence([
                ("fingerprint_consistency_score", f["fingerprint_consistency_score"], margins[0]),
                ("ja4_reference_support_hosts", support, margins[1]),
                ("host_fingerprint_repeats", float(host_count), margins[2]),
                ("splt_up_down_ratio", f["splt_up_down_ratio"], 0.0),
                ("splt_iat_cv", f["splt_iat_cv"], 0.0),
            ]),
            "cross-layer disagreement from {0}: the tls library says {1} (ja4 {2}, expected tcp stack "
            "{3}) while the kernel says {4} (tcp fingerprint {5}). the application and the operating "
            "system differ from the learned reference. Ported TLS libraries, proxies and custom "
            "clients can also produce this mismatch; it is a suspicion signal".format(
                format_ip(meta.src_ip), label or "an unlabelled stack", ja4, claims, family, fp),
            {
                "ja4_claims": {"ja4": ja4, "label": label, "expected_tcp_families": list(expected),
                               "chosen_by": "the tls library in user space"},
                "tcpfp_claims": {"fingerprint": fp, "family": family,
                                 "chosen_by": "the operating system kernel"},
                "why_this_matters": "this needs no destination reputation data, which is the point. a "
                                    "reputation lookup would be an outbound request and would break "
                                    "the read-only ingest constraint",
                "reference": REFERENCE_NOTE,
            },
        )

    def _outlier(
        self, meta: PacketMeta, flow: FlowState, ja4: str, family: str, fp: str,
        share: float, ja4_seen: float, f: dict
    ) -> Detection:
        cfg = self.config
        margins = [
            margin(float(cfg["minority_share"]) - share, 0.0, float(cfg["minority_share"])),
            margin(ja4_seen, float(cfg["min_pair_support"]), 200.0),
            margin(0.5, 0.5, 1.0),
        ]
        end = meta.ts_ns / 1e9
        flow_id = flow_identifier_of(flow, flow.first_ts_ns / 1e9, end)
        return self._emit(
            meta.ts_ns, THREAT, SUB_RARE_PAIR, margins, flow_id,
            evidence([
                ("ja4_tcp_pair_share", share, margins[0]),
                ("ja4_observation_count", ja4_seen, margins[1]),
                ("fingerprint_consistency_score", f["fingerprint_consistency_score"], 0.0),
                ("splt_up_down_ratio", f["splt_up_down_ratio"], 0.0),
                ("splt_direction_changes", f["splt_direction_changes"], 0.0),
            ]),
            "rare cross-layer pairing from {0}: this ja4 ({1}) has been seen about {2:.0f} times on "
            "this link and only {3:.0f} percent of those sat on a {4} tcp stack ({5}). the reference "
            "table has no entry for this ja4, so this is learned from the link itself and is reported "
            "at lower confidence".format(
                format_ip(meta.src_ip), ja4, ja4_seen, 100.0 * share, family, fp),
            {
                "ja4_claims": {"ja4": ja4, "label": "not in the reference table",
                               "chosen_by": "the tls library in user space"},
                "tcpfp_claims": {"fingerprint": fp, "family": family,
                                 "chosen_by": "the operating system kernel"},
                "basis": "online co-occurrence learned from this link only, with no reference data. "
                         "counts come from a count-min sketch so they are upper bounds",
            },
        )

    def stats(self) -> dict:
        return {
            "name": self.name,
            "alerts": self.alerts,
            "client_hellos": self.hellos,
            "agreements": self.agreements,
            "unknown_ja4": self.unknown_ja4,
            "no_syn_observed": self.no_syn,
            "hosts": len(self.hosts),
            "sequence_updates": self.sequence_updates,
            "udp443_sequence_updates": self.udp443_sequence_updates,
            "sequence_limit_packets": 20,
            "udp443_note": "UDP/443 is a port heuristic, not verified QUIC or validated malware coverage",
        }

    @property
    def nbytes(self) -> int:
        return int(self.hosts.nbytes + self.flow_fp.nbytes + self.last_alert.nbytes
                   + self.pair_counts.nbytes + self.ja4_counts.nbytes + self.sequences.nbytes)
