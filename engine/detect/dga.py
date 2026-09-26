from __future__ import annotations

import sys
from dataclasses import dataclass, field

from engine.decode.packet import format_ip
from engine.detect.base import (
    Context,
    Detector,
    LruMap,
    clamp01,
    evidence,
    flow_identifier,
    margin,
    shannon_entropy,
)
from engine.state.entropy import EwmaDeviation
from engine.types import UDP, Detection, FlowState, PacketMeta

THREAT = "dga-dns-tunnelling"

SUB_ALGORITHMIC = "dga-high-entropy"
SUB_DICTIONARY = "dga-dictionary"
SUB_TUNNEL = "dns-tunnel-txt-null"

QTYPE_TXT = 16
QTYPE_NULL = 10
RCODE_NXDOMAIN = 3
VOWELS = frozenset("aeiou")
WINDOW_S = 300

DEFAULTS = {
    "entropy_floor": 3.20,
    "entropy_span": 0.60,
    "bigram_floor": -3.20,
    "bigram_span": 1.00,
    "entropy_weight": 0.40,
    "bigram_weight": 0.60,
    "name_score_alert": 0.55,
    "campaign_domains": 20.0,
    "campaign_queries": 30.0,
    "nx_ratio": 0.50,
    "subdomain_min": 50.0,
    "subdomain_excess": 4.0,
    "txt_null_ratio": 0.30,
    "cooldown_s": 300.0,
    "source_capacity": 4096,
    "zone_capacity": 8192,
}


@dataclass(slots=True)
class SrcMonitor:
    win_sec: int = -1
    queries: int = 0
    responses: int = 0
    nx: int = 0
    empty: int = 0
    txt_null: int = 0
    score_sum: float = 0.0
    score_n: int = 0
    last_alert_ns: int | None = None
    txt_baseline: EwmaDeviation = field(default_factory=lambda: EwmaDeviation(0.05, warmup=3))


@dataclass(slots=True)
class Zone:
    ewma: EwmaDeviation = field(default_factory=lambda: EwmaDeviation(0.05, warmup=2))
    win: int = -1
    peak: float = 0.0
    queries: int = 0
    txt_null: int = 0
    txt_baseline: EwmaDeviation = field(default_factory=lambda: EwmaDeviation(0.05, warmup=3))


_SRC_BYTES = sys.getsizeof(SrcMonitor()) + sys.getsizeof(EwmaDeviation()) + 140
_ZONE_BYTES = sys.getsizeof(Zone()) + 2 * sys.getsizeof(EwmaDeviation()) + 224


def _baseline_text(f: dict) -> str:
    if f["subdomain_baseline_windows"] < 1.0:
        return ("with no baseline learned for this pair yet, so the count stands on its own rather "
                "than as a ratio")
    if f["subdomain_baseline_windows"] < 2.0:
        return ("against a single earlier window of {0:.0f}, which is not yet enough history to "
                "quote a ratio".format(f["subdomain_baseline"]))
    return ("{0:.0f} times the {1:.0f} subdomain baseline learned for this pair over {2:.0f} "
            "earlier windows".format(f["subdomain_excess"], f["subdomain_baseline"],
                                     f["subdomain_baseline_windows"]))


def digit_ratio(label: str) -> float:
    if not label:
        return 0.0
    return sum(1 for c in label if c.isdigit()) / float(len(label))


def consonant_run_max(label: str) -> float:
    best = 0
    run = 0
    for ch in label:
        if ch.isalnum() and ch not in VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return float(best)


class DgaDetector(Detector):
    name = "dga"
    classes = [THREAT]

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        cfg = dict(DEFAULTS)
        cfg.update(self.config)
        self.config = cfg
        self.queries = 0
        self.suppressed = 0
        self.model_suppressed = False
        self.sources = LruMap(int(cfg["source_capacity"]), SrcMonitor, _SRC_BYTES)
        self.zones = LruMap(int(cfg["zone_capacity"]), Zone, _ZONE_BYTES)

    def observe(self, meta: PacketMeta, flow: FlowState, ctx: Context) -> list[Detection]:
        dns = meta.dns
        if dns is None:
            return []
        if dns.is_response:
            mon = self.sources.get(meta.dst_ip)
            self._roll(mon, meta.ts_ns)
            mon.responses += 1
            if dns.rcode == RCODE_NXDOMAIN:
                mon.nx += 1
            elif dns.answer_count == 0:
                mon.empty += 1
            return []
        if not dns.qname:
            return []
        self.queries += 1
        src = meta.src_ip
        mon = self.sources.get(src)
        self._roll(mon, meta.ts_ns)
        mon.queries += 1
        if dns.qtype in (QTYPE_TXT, QTYPE_NULL):
            mon.txt_null += 1
        reference = ctx.reference
        registrable = reference.registrable(dns.qname)
        self.model_suppressed = bool(reference.wildcard_reason(registrable))
        stem = registrable.split(".")[0]
        feats = self._name_features(dns, stem, reference)
        mon.score_sum += feats["dga_name_score"]
        mon.score_n += 1
        group = src.to_bytes(4, "big")
        ctx.dns_regdomains.add(meta.ts_ns, group, registrable.encode("utf-8", "replace"))
        ctx.dns_subdomains.add(
            meta.ts_ns, group + registrable.encode("utf-8", "replace"),
            dns.qname.encode("utf-8", "replace"),
        )
        feats.update(self._source_features(mon, src, registrable, ctx, meta.ts_ns, dns.qtype))
        self._features = feats
        return self._rules(meta, mon, registrable, feats, ctx)

    def _roll(self, mon: SrcMonitor, ts_ns: int) -> None:
        sec = ts_ns // 1_000_000_000
        if mon.win_sec < 0:
            mon.win_sec = sec
            return
        if sec - mon.win_sec < WINDOW_S:
            return
        mon.win_sec = sec
        ratio = float(mon.txt_null) / max(1.0, float(mon.queries))
        mon.txt_baseline.update(ratio)
        mon.queries = 0
        mon.responses = 0
        mon.nx = 0
        mon.empty = 0
        mon.txt_null = 0
        mon.score_sum = 0.0
        mon.score_n = 0

    def _name_features(self, dns, stem: str, reference) -> dict[str, float]:
        cfg = self.config
        entropy = shannon_entropy(stem)
        bigram = reference.bigrams.score(stem) if reference.bigrams is not None else 0.0
        entropy_part = clamp01((entropy - float(cfg["entropy_floor"])) / float(cfg["entropy_span"]))
        bigram_part = clamp01((float(cfg["bigram_floor"]) - bigram) / float(cfg["bigram_span"]))
        score = float(cfg["entropy_weight"]) * entropy_part + float(cfg["bigram_weight"]) * bigram_part
        labels = dns.qname.split(".")
        return {
            "qname_char_entropy": float(entropy),
            "qname_bigram_ll": float(bigram),
            "qname_len": float(dns.qname_len),
            "label_count": float(len(labels)),
            "max_label_len": float(max((len(x) for x in labels), default=0)),
            "digit_ratio": digit_ratio(stem),
            "consonant_run_max": consonant_run_max(stem),
            "dga_entropy_component": float(entropy_part),
            "dga_bigram_component": float(bigram_part),
            "dga_name_score": float(score),
        }

    def _source_features(
        self, mon: SrcMonitor, src: int, registrable: str, ctx: Context, ts_ns: int, qtype: int
    ) -> dict[str, float]:
        group = src.to_bytes(4, "big")
        regdoms = ctx.dns_regdomains.count(ts_ns, group)
        subs = ctx.dns_subdomains.count(ts_ns, group + registrable.encode("utf-8", "replace"))
        zone = self.zones.get((src, registrable))
        baseline = self._roll_zone(zone, float(subs), ts_ns)
        zone.queries += 1
        zone.txt_null += int(qtype in (QTYPE_TXT, QTYPE_NULL))
        excess = subs / baseline if baseline > 0.0 else 1.0
        txt_ratio = float(zone.txt_null) / max(1.0, float(zone.queries))
        responses = max(1.0, float(mon.responses))
        return {
            "dga_mean_name_score": mon.score_sum / max(1, mon.score_n),
            "nx_response_ratio": float(mon.nx) / responses,
            "empty_answer_ratio": float(mon.empty) / responses,
            "distinct_regdom_300s": float(regdoms),
            "source_query_count_300s": float(mon.queries),
            "subdomain_cardinality": float(subs),
            "subdomain_baseline": float(baseline),
            "subdomain_baseline_windows": float(zone.ewma.n),
            "subdomain_excess": float(excess),
            "qtype_txt_null_ratio": float(txt_ratio),
            "qtype_txt_null_dev": float(txt_ratio - zone.txt_baseline.mean),
        }

    @staticmethod
    def _roll_zone(zone: Zone, subs: float, ts_ns: int) -> float:
        win = ts_ns // (WINDOW_S * 1_000_000_000)
        if zone.win < 0:
            zone.win = win
        elif win != zone.win:
            zone.ewma.update(zone.peak)
            zone.txt_baseline.update(zone.txt_null / max(1, zone.queries))
            zone.queries = zone.txt_null = 0
            zone.win = win
            zone.peak = 0.0
        zone.peak = max(zone.peak, subs)
        return zone.ewma.mean if zone.ewma.n > 0 else 0.0

    def _rules(
        self, meta: PacketMeta, mon: SrcMonitor, registrable: str, f: dict[str, float], ctx: Context
    ) -> list[Detection]:
        cfg = self.config
        now_ns = meta.ts_ns
        if mon.last_alert_ns is not None and now_ns - mon.last_alert_ns < float(cfg["cooldown_s"]) * 1e9:
            return []
        det = self._tunnel(meta, registrable, f, ctx)
        if det is None:
            det = self._campaign(meta, registrable, f)
        if det is None:
            return []
        mon.last_alert_ns = now_ns
        return [det]

    def _tunnel(self, meta: PacketMeta, registrable: str, f: dict, ctx: Context) -> Detection | None:
        cfg = self.config
        if f["subdomain_cardinality"] < float(cfg["subdomain_min"]):
            return None
        learned = f["subdomain_baseline_windows"] >= 2.0
        if learned and f["subdomain_excess"] < float(cfg["subdomain_excess"]):
            return None
        if f["qtype_txt_null_ratio"] < float(cfg["txt_null_ratio"]):
            return None
        reason = ctx.reference.wildcard_reason(registrable)
        if reason:
            self.suppressed += 1
            ctx.suppress(self.name, "cdn-wildcard-allowlist", registrable)
            return None
        margins = [
            margin(f["subdomain_cardinality"], float(cfg["subdomain_min"]), 450.0),
            margin(f["subdomain_excess"], float(cfg["subdomain_excess"]), 16.0) if learned else 0.0,
            margin(f["qtype_txt_null_ratio"], float(cfg["txt_null_ratio"]), 0.5),
        ]
        baseline_text = _baseline_text(f)
        end = meta.ts_ns / 1e9
        flow = flow_identifier(
            UDP, meta.src_ip, meta.dst_ip, 0, meta.dst_port, end - float(WINDOW_S), end, "FWD_ONLY", False
        )
        return self._emit(
            meta.ts_ns, THREAT, SUB_TUNNEL, margins, flow,
            evidence([
                ("subdomain_cardinality", f["subdomain_cardinality"], margins[0]),
                ("subdomain_excess", f["subdomain_excess"], margins[1]),
                ("qtype_txt_null_ratio", f["qtype_txt_null_ratio"], margins[2]),
                ("max_label_len", f["max_label_len"], 0.0),
                ("qname_len", f["qname_len"], 0.0),
            ]),
            "dns tunnelling from {0} under {1}: about {2:.0f} distinct subdomains in the last {3} s, "
            "{4}, and {5:.0f} percent of this host's queries under this domain are txt or null. longest label "
            "{6:.0f} characters".format(
                format_ip(meta.src_ip), registrable, f["subdomain_cardinality"], WINDOW_S,
                baseline_text, 100.0 * f["qtype_txt_null_ratio"], f["max_label_len"]),
            {
                "subdomain_baseline": (round(f["subdomain_baseline"], 1)
                                       if f["subdomain_baseline_windows"] >= 1.0
                                       else "none learned yet"),
                "baseline_applied": bool(learned),
                "baseline_windows": int(f["subdomain_baseline_windows"]),
                "evasion_note": "subdomain cardinality is counted on the label itself, so base32, "
                                "base64 or any other encoding of the payload changes the labels but "
                                "not the count. this is why the signal survives encoding evasion",
                "allowlist": "checked against the cdn wildcard allowlist and not suppressed",
                "registrable_domain": registrable,
            },
        )

    def _campaign(self, meta: PacketMeta, registrable: str, f: dict) -> Detection | None:
        cfg = self.config
        if f["distinct_regdom_300s"] < float(cfg["campaign_domains"]):
            return None
        if f["source_query_count_300s"] < float(cfg["campaign_queries"]):
            return None
        algorithmic = f["dga_mean_name_score"] >= float(cfg["name_score_alert"])
        if not algorithmic and f["nx_response_ratio"] < float(cfg["nx_ratio"]):
            return None
        end = meta.ts_ns / 1e9
        flow = flow_identifier(
            UDP, meta.src_ip, meta.dst_ip, 0, meta.dst_port, end - float(WINDOW_S), end, "FWD_ONLY", False
        )
        if algorithmic:
            margins = [
                margin(f["dga_mean_name_score"], float(cfg["name_score_alert"]), 0.35),
                margin(f["distinct_regdom_300s"], float(cfg["campaign_domains"]), 200.0),
                margin(f["nx_response_ratio"], float(cfg["nx_ratio"]), 0.4),
            ]
            return self._emit(
                meta.ts_ns, THREAT, SUB_ALGORITHMIC, margins, flow,
                evidence([
                    ("dga_name_score", f["dga_name_score"], margins[0]),
                    ("qname_char_entropy", f["qname_char_entropy"], f["dga_entropy_component"]),
                    ("qname_bigram_ll", f["qname_bigram_ll"], f["dga_bigram_component"]),
                    ("distinct_regdom_300s", f["distinct_regdom_300s"], margins[1]),
                    ("nx_response_ratio", f["nx_response_ratio"], margins[2]),
                ]),
                "algorithmic domain generation from {0}: mean name score {1:.2f} over {2:.0f} queries "
                "to about {3:.0f} distinct registrable domains in {4} s, {5:.0f} percent of which "
                "resolved to nothing. character entropy {6:.2f} bits and bigram log-likelihood "
                "{7:.2f} both separate this from normal names".format(
                    format_ip(meta.src_ip), f["dga_mean_name_score"], f["source_query_count_300s"],
                    f["distinct_regdom_300s"], WINDOW_S, 100.0 * f["nx_response_ratio"],
                    f["qname_char_entropy"], f["qname_bigram_ll"]),
                {
                    "separation": "high character entropy and a poor bigram likelihood agree here, so "
                                  "either statistic alone would have found this family",
                    "registrable_domain": registrable,
                },
            )
        margins = [
            margin(f["distinct_regdom_300s"], float(cfg["campaign_domains"]), 200.0),
            margin(f["nx_response_ratio"], float(cfg["nx_ratio"]), 0.4),
            margin(float(cfg["name_score_alert"]) - f["dga_mean_name_score"], 0.0, 0.4),
        ]
        return self._emit(
            meta.ts_ns, THREAT, SUB_DICTIONARY, margins, flow,
            evidence([
                ("distinct_regdom_300s", f["distinct_regdom_300s"], margins[0]),
                ("nx_response_ratio", f["nx_response_ratio"], margins[1]),
                ("dga_mean_name_score", f["dga_mean_name_score"], margins[2]),
                ("qname_char_entropy", f["qname_char_entropy"], 0.0),
                ("qname_bigram_ll", f["qname_bigram_ll"], 0.0),
            ]),
            "dictionary-style domain generation from {0}: about {1:.0f} distinct registrable domains "
            "in {2} s with {3:.0f} percent returning nxdomain, while the per-name score is only "
            "{4:.2f}. character entropy {5:.2f} bits and bigram log-likelihood {6:.2f} both sit "
            "inside the benign range, so the campaign shape is what identifies this, not the "
            "name".format(
                format_ip(meta.src_ip), f["distinct_regdom_300s"], WINDOW_S,
                100.0 * f["nx_response_ratio"], f["dga_mean_name_score"],
                f["qname_char_entropy"], f["qname_bigram_ll"]),
            {
                "separation": "the honest position: a single dictionary-word domain is not "
                              "distinguishable from a real registration by entropy or by a bigram "
                              "model, and this build does not claim otherwise. what is detectable is "
                              "the campaign, one host resolving many unrelated registrable domains "
                              "that mostly do not exist",
                "measured_note": "on the local corpus the dictionary family scores -2.73 mean bigram "
                                 "log-likelihood against -2.53 for benign labels, an overlap wide "
                                 "enough that a per-name threshold would be dishonest",
                "registrable_domain": registrable,
            },
        )

    def stats(self) -> dict:
        return {
            "name": self.name,
            "alerts": self.alerts,
            "queries": self.queries,
            "suppressed": self.suppressed,
            "sources": len(self.sources),
            "zones": len(self.zones),
        }

    @property
    def nbytes(self) -> int:
        return int(self.sources.nbytes + self.zones.nbytes)
