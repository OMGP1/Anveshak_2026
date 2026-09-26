"""Optional metadata-only rate alarms; these cannot identify an attack tool or HTTP method."""
from __future__ import annotations

import math
from collections import OrderedDict
from dataclasses import dataclass

from engine.detect.base import Detector, LruMap, evidence, flow_identifier, margin
from engine.types import ACK, SYN, TCP, UDP, ICMP, PacketMeta

NS = 1_000_000_000


@dataclass(slots=True)
class Bucket:
    second: int = -1
    packets: int = 0
    bytes: int = 0
    syns: int = 0
    observations: int = 0
    mean: float = 0.0
    variance: float = 0.0
    syn_mean: float = 0.0
    syn_variance: float = 0.0
    last_alert: int | None = None


class ProtocolFloodMonitor(Detector):
    name = "protocol_flood"

    def __init__(self, config: dict | None = None) -> None:
        super().__init__(config)
        self.enabled = bool(self.config.get("enabled", False))
        self.floor = float(self.config.get("minimum_pps", 2500))
        self.absolute = float(self.config.get("absolute_pps", 0))
        self.syn_floor = float(self.config.get("minimum_syn_pps", 0))
        self.syn_absolute = float(self.config.get("absolute_syn_pps", 0))
        self.sigma = float(self.config.get("sigma", 6))
        self.warmup = int(self.config.get("warmup_windows", 10))
        cooldown = float(self.config.get("cooldown_s", 60))
        if (not all(math.isfinite(value) for value in (
                self.floor, self.absolute, self.syn_floor, self.syn_absolute, self.sigma, cooldown))
                or self.floor <= 0 or self.sigma <= 0 or self.warmup < 2 or cooldown < 0
                or self.absolute < 0 or 0 < self.absolute < self.floor or self.syn_floor < 0
                or self.syn_absolute < 0
                or self.syn_absolute and (not self.syn_floor or self.syn_absolute < self.syn_floor)):
            raise ValueError("Invalid protocol flood thresholds")
        self.cooldown = int(cooldown * NS)
        self.pending: OrderedDict[tuple[int, int], None] = OrderedDict()
        self.buckets = LruMap(int(self.config.get("capacity", 4096)), Bucket, 448,
                              on_evict=lambda key, _bucket: self.pending.pop(key, None))
        self.watermark_second = -1
        self.late_packets_skipped = 0

    def observe_packet(self, meta: PacketMeta) -> list:
        if not self.enabled or meta.proto not in (TCP, UDP, ICMP):
            return []
        # Exporter records lack per-packet timing; do not claim instantaneous rates.
        if meta.from_flow_record:
            return []
        key = (meta.proto, meta.dst_ip)
        second = meta.ts_ns // NS
        previous = self.buckets.peek(key)
        if second < self.watermark_second or previous is not None and second < previous.second:
            self.late_packets_skipped += meta.packets
            return []
        bucket = self.buckets.get(key)
        output = []
        if bucket.second >= 0 and second > bucket.second:
            output = self._finish(key, bucket, meta.ts_ns)
        bucket.second = second
        bucket.packets += meta.packets
        bucket.bytes += meta.length
        if meta.proto == TCP and meta.tcp_flags & SYN and not meta.tcp_flags & ACK:
            bucket.syns += meta.packets
        self.pending[key] = None
        self.pending.move_to_end(key)  # same relative alert order as the baseline LRU
        return output

    def tick(self, now_ns: int, ctx=None) -> list:
        if not self.enabled:
            return []
        self.watermark_second = max(self.watermark_second, now_ns // NS)
        output = []
        for key in list(self.pending):
            bucket = self.buckets.peek(key)
            if bucket.second < self.watermark_second:
                output.extend(self._finish(key, bucket, now_ns))
        return output

    def _trigger(self, rate, mean, variance, observations, floor, absolute):
        deviation = (rate - mean) / math.sqrt(max(1.0, mean, variance))
        if absolute and rate >= absolute:
            return "absolute-limit", deviation, [margin(rate, absolute, absolute)]
        if floor and observations >= self.warmup and rate >= floor and deviation >= self.sigma:
            return "baseline-deviation", deviation, [margin(rate, floor, floor),
                                                      margin(deviation, self.sigma, self.sigma)]
        return None

    def _learn(self, rate, mean, variance, observations):
        # Empty seconds are not invented. Clip upward learning after observed warmup windows.
        value = rate if observations < self.warmup else min(
            rate, mean + 3 * math.sqrt(max(1.0, mean, variance)))
        if not observations:
            return value, 0.0
        delta = value - mean
        return mean + 0.1 * delta, 0.9 * (variance + 0.1 * delta * delta)

    def _finish(self, key, bucket, now_ns):
        self.pending.pop(key, None)
        if not bucket.packets:
            return []
        # Exactly one occupied one-second bucket, regardless of when closure is observed.
        pps = float(bucket.packets)
        trigger = self._trigger(pps, bucket.mean, bucket.variance,
                                bucket.observations, self.floor, self.absolute)
        syn_trigger = self._trigger(bucket.syns, bucket.syn_mean, bucket.syn_variance,
                                    bucket.observations, self.syn_floor, self.syn_absolute) if key[0] == TCP else None
        output = []
        if (trigger or syn_trigger) and (bucket.last_alert is None or now_ns - bucket.last_alert >= self.cooldown):
            protocol = {TCP: "tcp", UDP: "udp", ICMP: "icmp"}[key[0]]
            basis, deviation, weights = trigger or syn_trigger
            syn_only = trigger is None
            feature = "syn_attempts_per_second" if syn_only else "pps_to_dst"
            rate = bucket.syns if syn_only else pps
            subtype = "tcp-syn-rate-anomaly" if syn_only else protocol + "-rate-anomaly"
            limitation = ("Encrypted application methods and legitimate flash crowds are not distinguishable. "
                          "SYN attempts can include retransmissions; they are not counts of completed connections.")
            output.append(self._emit(
                now_ns, "volumetric-ddos", subtype, weights,
                flow_identifier(key[0], "multiple-or-unattributed", key[1], 0, 0,
                                float(bucket.second), float(bucket.second + 1)),
                evidence([(feature, rate, weights[0]),
                          ("syn_attempts_ewma_dev" if syn_only else "pps_to_dst_ewma_dev", deviation,
                           weights[1] if len(weights) > 1 else 0),
                          ("mean_pkt_bytes_1s", bucket.bytes / bucket.packets, 0)]),
                f"Suspected {protocol.upper()} rate anomaly: {rate:.0f} "
                f"{'SYN attempts/s' if syn_only else 'packets/s'} crossed the {basis} threshold. "
                "This is a rate anomaly, not proof of malicious intent or a specific attack tool.",
                {"extended_detection": True, "protocol": protocol, "trigger_basis": basis,
                 "baseline_windows": bucket.observations, "window_seconds": 1,
                 "limitation": limitation},
            ))
            bucket.last_alert = now_ns
        bucket.mean, bucket.variance = self._learn(pps, bucket.mean, bucket.variance, bucket.observations)
        bucket.syn_mean, bucket.syn_variance = self._learn(
            bucket.syns, bucket.syn_mean, bucket.syn_variance, bucket.observations)
        bucket.observations += 1
        bucket.packets = bucket.bytes = bucket.syns = 0
        return output

    def stats(self) -> dict:
        return {"name": self.name, "enabled": self.enabled, "alerts": self.alerts,
                "monitors": len(self.buckets), "monitors_evicted": self.buckets.evicted,
                "pending_windows": len(self.pending),
                "late_packets_skipped": self.late_packets_skipped}

    @property
    def nbytes(self) -> int:
        return self.buckets.nbytes + len(self.pending) * 128
