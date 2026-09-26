from __future__ import annotations

import asyncio
import os
import threading
import time
import uuid
from collections import OrderedDict, deque
from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from engine.decode.packet import format_ip
from engine.sources.pcap_source import PcapSource
from engine.sources.flowrecord_source import FlowRecordSource
from engine.sources.rust_source import RustPcapSource
from engine.sources.replay_clock import MODES, ReplayClock
from engine.state.entropy import SlidingEntropy
from engine.state.flow_table import FlowTable
from engine.state.hll import HLLFamily
from engine.types import ACK, ATTACK_TECHNIQUE, SYN, TCP, UDP, Detection, Evidence, PacketMeta
from training import scenarios as catalogue

QUEUE_CAPACITY = 1024
METRICS_INTERVAL_S = 0.5
DROP_POLICY = "bounded notifications: metrics, then status, then alert notifications; durable alerts remain in the store"

MAX_SPEED = 1000.0
LATENCY_BUCKETS_MS = (0.5, 1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 256.0)

SYN_BURST_MIN = 60
SYN_RATIO_MIN = 5.0
SRC_ENTROPY_MIN = 0.7
FANOUT_MIN = 60
SCAN_WINDOW_NS = 60_000_000_000
COOLDOWN_NS = 5_000_000_000
TLS_PORTS = (443, 8443, 993, 995)

FALLBACK_LINEAGE = {
    "model_id": "rules-v0",
    "model_hash": "sha256:" + "0" * 64,
    "dataset_version": "2026-09-07-synthetic-v1",
    "calibrated": False,
}


def iso(ts_ns: int) -> str:
    stamp = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc)
    return stamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")


class FrameQueue:
    def __init__(self, capacity: int = QUEUE_CAPACITY) -> None:
        self.capacity = int(capacity)
        if self.capacity < 1:
            raise ValueError("queue capacity must be positive")
        self.dropped = 0
        self.dropped_metrics = 0
        self.dropped_status = 0
        self.alert_overflow = 0
        self.dropped_alerts = 0
        self.offered = 0
        self._frames: deque[dict] = deque()
        self._waiter: asyncio.Event | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.RLock()
        self._notification_pending = False
        self._resync = False

    def bind(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop
        self._waiter = asyncio.Event()

    def unbind(self) -> None:
        self._loop = None

    def offer(self, kind: str, payload: Any) -> None:
        frame = {"type": kind, "payload": payload}
        with self._lock:
            self._put(frame)
            loop = self._loop
            if loop is not None and not self._notification_pending:
                self._notification_pending = True
                try:
                    loop.call_soon_threadsafe(self._notify)
                except RuntimeError:
                    self._notification_pending = False

    def _notify(self) -> None:
        with self._lock:
            self._notification_pending = False
            if self._waiter is not None:
                self._waiter.set()

    def _put(self, frame: dict) -> None:
        self.offered += 1
        if len(self._frames) >= self.capacity and not self._evict(frame):
            self._count_drop(frame["type"])
            return
        self._frames.append(frame)

    def _evict(self, incoming: dict) -> bool:
        victim = self._oldest("metrics")
        if victim is None:
            victim = self._oldest("status")
        if victim is None:
            if incoming["type"] != "alert":
                return False
            self.alert_overflow += 1
            self._resync = True
            victim = self._frames.popleft()
            self._count_drop(victim["type"])
            return True
        self._frames.remove(victim)
        self._count_drop(victim["type"])
        return True

    def _oldest(self, kind: str) -> dict | None:
        for frame in self._frames:
            if frame["type"] == kind:
                return frame
        return None

    def _count_drop(self, kind: str) -> None:
        self.dropped += 1
        if kind == "metrics":
            self.dropped_metrics += 1
        elif kind == "status":
            self.dropped_status += 1
        elif kind == "alert":
            self.dropped_alerts += 1

    async def drain(self, timeout: float = 1.0) -> list[dict]:
        with self._lock:
            wait = not self._frames and not self._resync and self._waiter is not None
            if wait:
                self._waiter.clear()
        if wait:
            try:
                await asyncio.wait_for(self._waiter.wait(), timeout)
            except asyncio.TimeoutError:
                return []
        with self._lock:
            out = list(self._frames)
            self._frames.clear()
            if self._resync:
                out.append({"type": "resync", "payload": {"reason": "notification_overflow"}})
                self._resync = False
        return out

    def frames(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(self._frames)

    @property
    def depth(self) -> int:
        return len(self._frames)

    @property
    def shedding_tier(self) -> str:
        depth = len(self._frames)
        if depth >= self.capacity:
            return "alerts-only"
        if depth >= self.capacity * 0.75:
            return "drop-metrics"
        return "none"

    def stats(self) -> dict:
        return {
            "depth": self.depth,
            "capacity": self.capacity,
            "dropped": self.dropped,
            "dropped_metrics": self.dropped_metrics,
            "dropped_status": self.dropped_status,
            "alert_overflow": self.alert_overflow,
            "dropped_alerts": self.dropped_alerts,
            "offered": self.offered,
            "shedding_tier": self.shedding_tier,
            "policy": DROP_POLICY,
        }


class Meter:
    def __init__(self, reservoir: int = 4096) -> None:
        self.packets = 0
        self.flows = 0
        self.alerts = 0
        self.bytes = 0
        self.started = 0.0
        self._latency_ms: deque[float] = deque(maxlen=reservoir)
        self._histogram = [0] * (len(LATENCY_BUCKETS_MS) + 1)
        self._lock = threading.Lock()

    def start(self) -> None:
        with self._lock:
            self.started = time.perf_counter()

    def observe_packet(self, n_bytes: int) -> None:
        self.packets += 1
        self.bytes += int(n_bytes)

    def observe_flow(self) -> None:
        self.flows += 1

    def observe_alert(self, latency_ns: int) -> None:
        ms = max(0.0, latency_ns / 1e6)
        with self._lock:
            self.alerts += 1
            self._latency_ms.append(ms)
            self._histogram[_bucket_index(ms)] += 1

    def snapshot(self) -> dict:
        with self._lock:
            samples = sorted(self._latency_ms)
            histogram = list(self._histogram)
        uptime = max(1e-9, time.perf_counter() - self.started) if self.started else 0.0
        scale = uptime if uptime > 0 else 1.0
        return {
            "uptime_s": round(uptime, 3),
            "packets": self.packets,
            "flows": self.flows,
            "alerts": self.alerts,
            "packets_per_s": round(self.packets / scale, 1),
            "flows_per_s": round(self.flows / scale, 1),
            "mbps": round(self.bytes * 8 / 1e6 / scale, 3),
            "latency_ms": {
                "p50": _quantile(samples, 0.50),
                "p95": _quantile(samples, 0.95),
                "p99": _quantile(samples, 0.99),
                "p999": _quantile(samples, 0.999),
            },
            "latency_histogram": [
                {"le_ms": le, "count": histogram[i]} for i, le in enumerate(LATENCY_BUCKETS_MS)
            ],
            "rss_mb": _rss_mb(),
        }


def _bucket_index(ms: float) -> int:
    for i, le in enumerate(LATENCY_BUCKETS_MS):
        if ms <= le:
            return i
    return len(LATENCY_BUCKETS_MS)


def _quantile(samples: list[float], q: float) -> float:
    if not samples:
        return 0.0
    index = min(len(samples) - 1, int(round(q * (len(samples) - 1))))
    return round(samples[index], 3)


def _rss_mb() -> float:
    try:
        import psutil
    except ImportError:
        return 0.0
    return round(psutil.Process().memory_info().rss / 1e6, 1)


class RuleEngine:
    name = "rules-fallback"

    def __init__(self, config: dict | None = None) -> None:
        config = config or {}
        self.flows = FlowTable(capacity=int(config.get("flow_capacity", 200_000)))
        self.src_entropy = SlidingEntropy(window_s=1.0, buckets=20)
        self.ports_by_src = HLLFamily(m_bits=8, capacity=20_000)
        self.hosts_by_src = HLLFamily(m_bits=8, capacity=20_000)
        self.packets = 0
        self.detections = 0
        self.opaque_flows = 0
        self.high_flows = 0
        self.low_flows = 0
        self.quic_flows = 0
        self.no_sni_flows = 0
        self.stage_ns = {"state": 0.0, "detect": 0.0}
        self._dst_windows: OrderedDict[int, list[int]] = OrderedDict()
        self._cooldown: dict[tuple[str, int], int] = {}
        self._scan_window = -1
        self._swept = False

    def feed(self, meta: PacketMeta) -> list[Detection]:
        self.packets += 1
        t0 = time.perf_counter_ns()
        self.flows.observe(meta)
        self.src_entropy.add(meta.ts_ns, meta.src_ip.to_bytes(4, "big", signed=False))
        if meta.tls is not None and meta.tls.is_client_hello and not meta.tls.sni_present:
            self.no_sni_flows += 1
        t2 = time.perf_counter_ns()
        out: list[Detection] = []
        ddos = self._ddos(meta)
        if ddos is not None:
            out.append(ddos)
        scan = self._scan(meta)
        if scan is not None:
            out.append(scan)
        t3 = time.perf_counter_ns()
        self.stage_ns["state"] = _ewma(self.stage_ns["state"], t2 - t0)
        self.stage_ns["detect"] = _ewma(self.stage_ns["detect"], t3 - t2)
        self.detections += len(out)
        return out

    def tick(self, now_ns: int) -> list[Detection]:
        for flow in self.flows.expire(now_ns):
            self._classify(flow)
        return []

    def lineage(self) -> dict:
        return {key: value for key, value in FALLBACK_LINEAGE.items() if key != "calibrated"}

    def lineage_for(self, detection: Detection) -> dict:
        out = self.lineage()
        out["calibrated"] = bool((detection.context or {}).get("calibrated", False))
        return out

    def sweep(self) -> None:
        if self._swept:
            return
        self._swept = True
        for flow in list(self.flows):
            self._classify(flow)

    def _classify(self, flow) -> None:
        key = flow.key
        ports = (key.lo_port, key.hi_port)
        encrypted = any(p in TLS_PORTS for p in ports) and flow.completeness_flag
        if key.proto == UDP and 443 in ports:
            self.quic_flows += 1
            self.opaque_flows += 1
        elif encrypted and not flow.ja4:
            self.opaque_flows += 1
        elif flow.completeness_flag and flow.orientation_confidence >= 1.0:
            self.high_flows += 1
        else:
            self.low_flows += 1

    def stats(self) -> dict:
        sketches = self.ports_by_src.nbytes + self.hosts_by_src.nbytes + self.src_entropy.nbytes
        caps = self.ports_by_src.capacity_bytes + self.hosts_by_src.capacity_bytes + self.src_entropy.nbytes
        return {
            "engine": self.name,
            "packets": self.packets,
            "detections": self.detections,
            "flow_table_entries": len(self.flows),
            "memory_bytes": {
                "flow_table": self.flows.nbytes,
                "beacon_table": 0,
                "sketches": sketches,
                "models": 0,
            },
            "memory_caps_bytes": {
                "flow_table": self.flows.capacity_bytes,
                "beacon_table": 0,
                "sketches": caps,
                "models": 0,
            },
            "stage_timing_us": {k: round(v / 1000.0, 3) for k, v in self.stage_ns.items()},
            "coverage_counts": {
                "high": self.high_flows,
                "low": self.low_flows,
                "opaque": self.opaque_flows,
                "quic": self.quic_flows,
                "no_sni": self.no_sni_flows,
                "flows": self.high_flows + self.low_flows + self.opaque_flows,
            },
        }

    def _ddos(self, meta: PacketMeta) -> Detection | None:
        if meta.proto != TCP:
            return None
        second = meta.ts_ns // 1_000_000_000
        window = self._dst_windows.get(meta.dst_ip)
        if window is None or window[0] != second:
            window = [second, 0, 0]
            self._dst_windows[meta.dst_ip] = window
            self._dst_windows.move_to_end(meta.dst_ip)
            while len(self._dst_windows) > 4096:
                self._dst_windows.popitem(last=False)
        syn = bool(meta.tcp_flags & SYN)
        ack = bool(meta.tcp_flags & ACK)
        if syn and not ack:
            window[1] += meta.packets
        elif syn and ack:
            window[2] += meta.packets
        if window[1] < SYN_BURST_MIN:
            return None
        ratio = window[1] / max(1, window[2])
        entropy = self.src_entropy.entropy(meta.ts_ns)
        if ratio < SYN_RATIO_MIN or entropy < SRC_ENTROPY_MIN:
            return None
        if not self._fire("volumetric-ddos", meta.dst_ip, meta.ts_ns):
            return None
        confidence = min(0.99, 0.55 + 0.04 * min(10.0, ratio) + 0.2 * entropy)
        return Detection(
            ts_ns=meta.ts_ns,
            threat_class="volumetric-ddos",
            subtype="syn-flood",
            confidence=confidence,
            severity="HIGH" if confidence < 0.9 else "CRITICAL",
            source="rule.syn_entropy",
            flow=_flow_identity(meta, "FWD_ONLY", False),
            evidence=[
                Evidence("syn_synack_ratio_1s", round(ratio, 2), 0.34),
                Evidence("src_entropy_1s", round(entropy, 3), 0.21),
                Evidence("syn_count_1s", float(window[1]), 0.18),
            ],
            summary=(
                "elevated syn to syn-ack ratio with high source-ip entropy over 1s against "
                f"{format_ip(meta.dst_ip)}:{meta.dst_port}"
            ),
            context={"shedding_tier": "none", "sampling_active": False, "sampling_ratio": 1.0},
        )

    def _scan(self, meta: PacketMeta) -> Detection | None:
        if meta.proto != TCP or not (meta.tcp_flags & SYN) or meta.tcp_flags & ACK:
            return None
        window = meta.ts_ns // SCAN_WINDOW_NS
        if window != self._scan_window:
            self._scan_window = window
            self.ports_by_src.clear()
            self.hosts_by_src.clear()
        src = meta.src_ip.to_bytes(4, "big", signed=False)
        self.ports_by_src.add(src, meta.dst_port.to_bytes(2, "big"))
        self.hosts_by_src.add(src + meta.dst_port.to_bytes(2, "big"), meta.dst_ip.to_bytes(4, "big"))
        vertical = self.ports_by_src.count(src)
        horizontal = self.hosts_by_src.count(src + meta.dst_port.to_bytes(2, "big"))
        if vertical < FANOUT_MIN and horizontal < FANOUT_MIN:
            return None
        if not self._fire("recon-scanning", meta.src_ip, meta.ts_ns):
            return None
        subtype = "vertical-scan" if vertical >= horizontal else "horizontal-scan"
        confidence = min(0.97, 0.6 + max(vertical, horizontal) / 1000.0)
        return Detection(
            ts_ns=meta.ts_ns,
            threat_class="recon-scanning",
            subtype=subtype,
            confidence=confidence,
            severity="MEDIUM",
            source="rule.fanout",
            flow=_flow_identity(meta, "FWD_ONLY", False),
            evidence=[
                Evidence("vertical_fanout", round(vertical, 1), 0.31),
                Evidence("horizontal_fanout", round(horizontal, 1), 0.27),
                Evidence("mean_bytes_per_flow", float(meta.length), 0.11),
            ],
            summary=(
                f"{format_ip(meta.src_ip)} fanned out to {int(vertical)} ports and "
                f"{int(horizontal)} hosts inside one 60s window"
            ),
            context={"shedding_tier": "none", "sampling_active": False, "sampling_ratio": 1.0},
        )

    def _fire(self, kind: str, subject: int, ts_ns: int) -> bool:
        key = (kind, subject)
        last = self._cooldown.get(key, 0)
        if ts_ns - last < COOLDOWN_NS:
            return False
        if len(self._cooldown) > 8192:
            self._cooldown.clear()
        self._cooldown[key] = ts_ns
        return True


def _ewma(current: float, sample: float, alpha: float = 0.05) -> float:
    return sample if current == 0.0 else current + alpha * (sample - current)


def _flow_identity(meta: PacketMeta, directionality: str, complete: bool) -> dict:
    proto = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(meta.proto, str(meta.proto))
    stamp = iso(meta.ts_ns)
    return {
        "proto": proto,
        "src_ip": format_ip(meta.src_ip),
        "dst_ip": format_ip(meta.dst_ip),
        "src_port": meta.src_port,
        "dst_port": meta.dst_port,
        "directionality": directionality,
        "completeness_flag": complete,
        "window_start": stamp,
        "window_end": stamp,
    }


def build_alert(detection: Detection, lineage: dict) -> dict:
    technique, technique_name = ATTACK_TECHNIQUE.get(detection.threat_class, ("T1046", "Network Service Discovery"))
    flow = detection.flow
    stamp = iso(detection.ts_ns)
    context = detection.context or {}
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": "indicator--" + str(uuid.uuid4()),
        "created": stamp,
        "name": detection.subtype.replace("-", " ").capitalize(),
        "description": detection.summary,
        "indicator_types": ["anomalous-activity"],
        "pattern": (
            f"[network-traffic:dst_ref.value = '{flow.get('dst_ip', '')}' "
            f"AND network-traffic:dst_port = {flow.get('dst_port', 0)}]"
        ),
        "pattern_type": "stix",
        "valid_from": stamp,
        "confidence": int(round(max(0.0, min(1.0, detection.confidence)) * 100)),
        "x_flow_identifier": flow,
        "x_threat_class": detection.threat_class,
        "x_subtype": detection.subtype,
        "x_severity": detection.severity,
        "x_confidence_calibrated": bool(lineage.get("calibrated", False)),
        "x_detector": detection.source,
        "x_latency_ms": round(float(lineage.get("latency_ns", 0.0)) / 1e6, 3),
        "x_model_lineage": {
            "model_id": str(lineage.get("model_id", FALLBACK_LINEAGE["model_id"])),
            "model_hash": str(lineage.get("model_hash", FALLBACK_LINEAGE["model_hash"])),
            "dataset_version": str(lineage.get("dataset_version", FALLBACK_LINEAGE["dataset_version"])),
        },
        "x_supporting_evidence": [
            {"feature": e.feature, "value": float(e.value), "shap": float(e.contribution)}
            for e in detection.evidence
        ],
        "x_detection_context": {
            "sampling_active": bool(context.get("sampling_active", False)),
            "sampling_ratio": float(context.get("sampling_ratio", 1.0)),
            "shedding_tier": str(context.get("shedding_tier", "none")),
        },
        "x_prev_hash": str(lineage.get("prev_hash", "")),
        "external_references": [
            {"source_name": "mitre-attack", "external_id": technique, "description": technique_name}
        ],
        "labels": ["cii-relevant"],
    }


def resolve_engine_factory() -> tuple[Callable[[dict], Any], str]:
    try:
        from engine.pipeline import Engine
    except ImportError:
        if os.environ.get("SIH_PRODUCTION") == "1":
            raise
        return (lambda config: RuleEngine(config)), RuleEngine.name
    return (lambda config: Engine(config)), "engine.pipeline"


def resolve_meter() -> Any:
    try:
        from engine.metrics import Meter as EngineMeter
    except ImportError:
        return Meter()
    return EngineMeter()


def resolve_alert_builder() -> Callable[[Detection, dict], dict]:
    try:
        from engine.alerts.schema import build_alert as engine_build_alert
    except ImportError:
        return build_alert
    return engine_build_alert


def scenario_list() -> list[dict]:
    out = []
    for spec in catalogue.SCENARIOS:
        out.append(
            {
                "id": spec["id"],
                "name": spec["name"],
                "file": spec["file"],
                "proves": spec["proves"],
                "threat_class": spec["threat_class"],
                "packets": int(spec["packets"]),
                "duration_s": float(spec["duration_s"]),
            }
        )
    return out


class ReplayController:
    def __init__(self, queue: FrameQueue, store: Any, config: dict | None = None) -> None:
        self.queue = queue
        self.store = store
        self.config = config or {}
        self.engine_factory, self.engine_name = resolve_engine_factory()
        self.build_alert = resolve_alert_builder()
        self.meter = resolve_meter()
        self.engine: Any = self.engine_factory(self.config)
        self.clock = ReplayClock(1.0, "virtual")
        self.scenario: str | None = None
        self.source_kind: str | None = None
        self.speed = 1.0
        self.mode = "virtual"
        self.run_alerts = 0
        self.packets = 0
        self.total_packets = 0
        self.decode_ns = 0.0
        self.finished = True
        self.error: str | None = None
        self._arrival_ns = time.perf_counter_ns()
        self._thread: threading.Thread | None = None
        self._control_lock = threading.RLock()
        self._stop = threading.Event()
        self._resume = threading.Event()
        self._resume.set()
        self._lock = threading.Lock()

    def start(self, scenario_id: str, speed: float, mode: str, source_kind: str = "pcap") -> dict:
        with self._control_lock:
            return self._start(scenario_id, speed, mode, source_kind)

    def _start(self, scenario_id: str, speed: float, mode: str, source_kind: str) -> dict:
        if source_kind not in ("pcap", "rust-pcap", "flows"):
            raise ValueError("source must be pcap, rust-pcap or flows")
        spec = catalogue.get(scenario_id)
        path = catalogue.abspath(spec["flow_file" if source_kind == "flows" else "file"])
        if not os.path.exists(path):
            raise FileNotFoundError(path)
        self.stop()
        with self._lock:
            self.source_kind = source_kind
            self.scenario = scenario_id
            self.speed = float(speed)
            self.mode = mode
            self.run_alerts = 0
            self.packets = 0
            self.decode_ns = 0.0
            self.finished = False
            self.error = None
            self.engine = self.engine_factory(self.config)
            self.meter = resolve_meter()
            self.clock = ReplayClock(float(speed), mode)
            self._stop.clear()
            self._resume.set()
            if source_kind == "flows":
                source = FlowRecordSource(path)
            elif source_kind == "rust-pcap" or self.config.get("pcap_backend") == "rust":
                source = RustPcapSource(path)
            else:
                source = PcapSource(path)
            self.total_packets = source.approximate_count or int(spec["packets"]) or 1
            if hasattr(self.meter, "start"):
                self.meter.start()
            self._thread = threading.Thread(target=self._run, args=(source,), daemon=True)
            self._thread.start()
        return self.status()

    def pause(self) -> dict:
        self._resume.clear()
        return self.status()

    def resume(self) -> dict:
        if not self._resume.is_set():
            self._resume.set()
        return self.status()

    def stop(self) -> dict:
        with self._control_lock:
            return self._stop_worker()

    def _stop_worker(self) -> dict:
        thread = self._thread
        self._stop.set()
        self._resume.set()
        if thread is not None and thread.is_alive():
            thread.join(timeout=5.0)
            if thread.is_alive():
                raise RuntimeError("Replay worker did not stop; a second worker will not be started")
        self._thread = None
        self.finished = True
        return self.status()

    def running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def status(self) -> dict:
        clock_ts = self.clock.last_ts_ns / 1e9 if self.clock.last_ts_ns else None
        progress = min(1.0, self.packets / max(1, self.total_packets)) if self.scenario else 0.0
        return {
            "running": self.running(),
            "paused": self.running() and not self._resume.is_set(),
            "scenario": self.scenario,
            "speed": self.speed,
            "mode": self.mode,
            "clock_ts": clock_ts,
            "progress": round(progress, 4),
            "alerts": self.run_alerts,
        }

    def metrics(self) -> dict:
        snapshot = dict(self.meter.snapshot())
        stats = dict(self.engine.stats())
        detectors = {row["name"]: row for row in stats.get("rules", {}).get("detectors", [])}
        beacon = detectors.get("beaconing", {})
        rates = detectors.get("ddos", {}).get("extended", {})
        encrypted = detectors.get("encrypted", {})
        snapshot["analysis_limits"] = {
            "beacon_event_bin_limit": beacon.get("event_bin_limit", 0),
            "beacon_windows_skipped": beacon.get("resource_budget_skipped", 0),
            "late_rate_packets_skipped": rates.get("late_packets_skipped", 0),
            "rate_monitors_evicted": rates.get("monitors_evicted", 0),
            "encrypted_sequence_updates": encrypted.get("sequence_updates", 0),
            "udp443_sequence_updates": encrypted.get("udp443_sequence_updates", 0),
            "model_candidates_without_support": stats.get("model_candidates_without_support", 0),
        }
        snapshot["novelty"] = dict(stats.get("novelty") or {"status": "unavailable"})
        snapshot["flow_table_entries"] = int(stats.get("flow_table_entries", 0))
        for key in ("memory_bytes", "memory_caps_bytes", "stage_timing_us"):
            merged = dict(snapshot.get(key) or {})
            merged.update(stats.get(key) or {})
            snapshot[key] = merged
        packets = max(1, self.packets)
        snapshot["stage_timing_us"]["decode"] = round(self.decode_ns / 1000.0 / packets, 3)
        per_packet = dict(snapshot.get("stage_timing_per_packet_us") or {})
        per_packet.update(stats.get("stage_timing_per_packet_us") or {})
        per_packet["decode"] = snapshot["stage_timing_us"]["decode"]
        snapshot["stage_timing_per_packet_us"] = per_packet
        calls = dict(stats.get("stage_calls") or {})
        calls["decode"] = self.packets
        snapshot["stage_calls"] = calls
        snapshot["queue"] = self.queue.stats()
        snapshot["store"] = {
            "alerts_stored": int(self.store.count()),
            "duplicates_ignored": int(getattr(self.store, "duplicates", 0)),
            "policy": "alert ids are a uuid5 of the alert content, so a replayed scenario re-emits "
                      "the same ids and the store keeps one copy of each",
        }
        snapshot["engine"] = stats.get("engine", self.engine_name)
        snapshot.setdefault("latency_ms", {"p50": 0.0, "p95": 0.0, "p99": 0.0, "p999": 0.0})
        return snapshot

    def coverage(self) -> dict:
        counts = dict(self.engine.stats().get("coverage_counts", {}))
        flows = float(counts.get("flows", 0))
        if flows <= 0:
            return {
                "high_confidence": 0.0,
                "low_confidence": 1.0,
                "unclassifiable_opaque": 0.0,
                "reasons": [],
            }
        opaque = float(counts.get("opaque", 0))
        quic = float(counts.get("quic", 0))
        no_sni = float(counts.get("no_sni", 0))
        high = round(float(counts.get("high", 0)) / flows, 6)
        low = round(float(counts.get("low", 0)) / flows, 6)
        return {
            "high_confidence": high,
            "low_confidence": low,
            "unclassifiable_opaque": max(0.0, round(1.0 - high - low, 6)),
            "reasons": [
                {
                    "code": "payload-opaque",
                    "label": "Payload is never read",
                    "fraction": round(opaque / flows, 6),
                    "detail": (
                        "constraint C-b discards payload at the parse boundary, so content-based "
                        "classification is out of reach for encrypted sessions"
                    ),
                },
                {
                    "code": "quic-handshake",
                    "label": "QUIC obscures handshake metadata",
                    "fraction": round(quic / flows, 6),
                    "detail": "quic encrypts most of its handshake, so no ja4 or sni flag is recoverable",
                },
                {
                    "code": "ech-hidden-sni",
                    "label": "SNI hidden by Encrypted Client Hello",
                    "fraction": round(no_sni / flows, 6),
                    "detail": "with ech the server name is encrypted, leaving ja4 and packet timing only",
                },
            ],
        }

    def _run(self, source: Iterable[PacketMeta]) -> None:
        try:
            self._consume(source)
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            self.finished = True
            self.queue.offer("status", {**self.status(), "running": False})

    def _consume(self, source: Iterable[PacketMeta]) -> None:
        last_metrics = time.perf_counter()
        last_tick_ns = 0
        last_packet_ns = None
        seen_flows = 0
        table = getattr(self.engine, "flows", None)
        iterator = iter(source)
        while not self._stop.is_set():
            if not self._resume.is_set():
                self._resume.wait()
                if self._stop.is_set():
                    break
                self.clock.set_speed(self.clock.speed)
            t0 = time.perf_counter_ns()
            try:
                meta = next(iterator)
            except StopIteration:
                break
            self.decode_ns += time.perf_counter_ns() - t0
            self.clock.wait_until(meta.ts_ns)
            self._arrival_ns = time.perf_counter_ns()
            self.packets += 1
            last_packet_ns = max(last_packet_ns if last_packet_ns is not None else meta.ts_ns, meta.ts_ns)
            self.meter.observe_packet(meta.length)
            for detection in self.engine.feed(meta):
                self._emit(detection)
            if meta.ts_ns - last_tick_ns > 1_000_000_000:
                last_tick_ns = meta.ts_ns
                for detection in self.engine.tick(meta.ts_ns):
                    self._emit(detection)
            created = getattr(table, "created", 0)
            while seen_flows < created:
                seen_flows += 1
                self.meter.observe_flow()
            now = time.perf_counter()
            if now - last_metrics >= METRICS_INTERVAL_S:
                last_metrics = now
                self.queue.offer("metrics", self.metrics())
                self.queue.offer("status", self.status())
        if last_packet_ns is not None and not self._stop.is_set():
            # EOF closes the last occupied second even when no later packet arrives.
            # Cancellation is not EOF and must not synthesize further detections.
            final_tick_ns = (last_packet_ns // 1_000_000_000 + 1) * 1_000_000_000
            for detection in self.engine.tick(final_tick_ns):
                self._emit(detection)
        if hasattr(self.engine, "sweep"):
            final = self.engine.sweep()
            if final:
                for detection in final:
                    self._emit(detection)
        self.finished = True
        self.queue.offer("metrics", self.metrics())
        self.queue.offer("status", self.status())

    def _lineage_for(self, detection: Detection) -> dict:
        source = getattr(self.engine, "lineage_for", None)
        if source is None:
            return dict(FALLBACK_LINEAGE)
        return dict(source(detection))

    def _emit(self, detection: Detection) -> None:
        latency_ns = max(0, time.perf_counter_ns() - self._arrival_ns)
        detection.context = dict(detection.context or {})
        detection.context["shedding_tier"] = self.queue.shedding_tier
        lineage = self._lineage_for(detection)
        lineage["latency_ns"] = latency_ns
        lineage["latency_ms"] = latency_ns / 1e6
        lineage["prev_hash"] = getattr(self.store.ledger, "head", "")
        alert = self.build_alert(detection, lineage)
        entry = self.store.append(alert)
        if isinstance(entry, dict):
            alert = entry.get("record", alert)
        self.run_alerts += 1
        self.meter.observe_alert(latency_ns)
        self.queue.offer("alert", alert)


def validate_speed(speed: float) -> float:
    value = float(speed)
    if not value > 0 or value > MAX_SPEED or value != value:
        raise ValueError(f"speed must be greater than 0 and at most {MAX_SPEED:g}")
    return value


def validate_mode(mode: str) -> str:
    if mode not in MODES:
        raise ValueError("mode must be one of %s" % (MODES,))
    return mode
