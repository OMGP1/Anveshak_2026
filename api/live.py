"""One monitoring session: passive live capture or a replay, sharing alert storage."""
from collections import deque
import copy
import json
from pathlib import Path
import threading
import time
import uuid

from api.replay import ReplayController, resolve_meter, METRICS_INTERVAL_S
from engine.sources.live_source import LiveSource, interfaces
from engine.sources.replay_clock import ReplayClock
from engine.metrics import LatencyHistogram


def live_config(overrides=None):
    defaults = json.loads((Path(__file__).resolve().parents[1] / "config/engine-live.json").read_text())
    def merge(target, changes):
        for key, value in changes.items():
            if isinstance(value, dict) and isinstance(target.get(key), dict):
                merge(target[key], value)
            else:
                target[key] = copy.deepcopy(value)
    merge(defaults, overrides or {})
    return defaults


class MonitoringController(ReplayController):
    def __init__(self, queue, store, config=None):
        super().__init__(queue, store, config)
        self.live_source = None
        self.live_session = None
        self.started_at = None
        self.live_counts = {}
        self._engine_lock = threading.RLock()
        self._rate_samples = deque(maxlen=32)
        self._persist_latency = LatencyHistogram()

    def start(self, *args, **kwargs):
        with self._control_lock:
            if self.running() and self.source_kind == "live":
                raise RuntimeError("Stop live monitoring before starting a replay")
            return super().start(*args, **kwargs)

    def start_live(self, interface: str, capture_filter: str = "ip") -> dict:
        with self._control_lock:
            if self.running():
                raise RuntimeError("Stop the current live session or replay first")
            listing = interfaces()
            if not listing["available"]:
                raise RuntimeError(listing["error"])
            if interface not in {row["id"] for row in listing["interfaces"]}:
                raise ValueError("Choose a local interface from the available interface list")
            self.stop()
            config = live_config(self.config)
            # Preserve per-subject cooldowns while allowing distinct attack hosts
            # to produce model alerts beyond the replay preset's global quota.
            new_engine = self.engine_factory(config)
            source = LiveSource(interface, capture_filter)
            source.start()
            with self._engine_lock:
                self.engine = new_engine
                self.meter = resolve_meter()
                self.meter.start()
                self.live_source = source
                self.live_session = uuid.uuid4().hex
                self.started_at = time.time()
                self.live_counts = {}
                self._rate_samples.clear()
                self._persist_latency = LatencyHistogram()
                self._rate_samples.append((time.monotonic(), 0, 0))
                self.source_kind = "live"
                self.scenario = None
                self.mode = "realtime"
                self.speed = 1.0
                self.packets = self.run_alerts = self.decode_ns = 0
                self.total_packets = 0
                self.finished = False
                self.error = None
                self.clock = ReplayClock(1, "virtual")
                self._stop.clear()
                self._resume.set()
                self._thread = threading.Thread(target=self._run_live, daemon=True, name="sih-live-analysis")
                self._thread.start()
            return self.live_status()

    def pause(self):
        if self.running() and self.source_kind == "live":
            raise RuntimeError("Live capture cannot be paused without losing traffic; use Stop monitoring")
        return super().pause()

    def _stop_worker(self):
        self._stop.set()
        if self.live_source is not None:
            self.live_source.close()
        return super()._stop_worker()

    def live_status(self):
        with self._engine_lock:
            return {"running": self.running() and self.source_kind == "live",
                    "active_source": self.source_kind or "idle", "session_id": self.live_session,
                    "started_at": self.started_at, "error": self.error,
                    "alerts": self.run_alerts if self.source_kind == "live" else 0,
                    "class_counts": dict(self.live_counts),
                    "capture": self.live_source.stats() if self.live_source else None,
                    "persistence": {"format": "JSON Lines with a signed hash chain", "automatic": True,
                                    "export_json": "/api/alerts/export?format=json",
                                    "export_jsonl": "/api/alerts/export?format=jsonl"}}

    def metrics(self):
        with self._engine_lock:
            snapshot = super().metrics()
            snapshot["monitor_session"] = self.live_session if self.source_kind == "live" else None
            if self.source_kind == "live" and self._rate_samples:
                now = time.monotonic()
                while len(self._rate_samples) > 1 and now - self._rate_samples[1][0] >= 5:
                    self._rate_samples.popleft()
                then, packets, byte_count = self._rate_samples[0]
                duration = max(0.001, now - then)
                snapshot["packets_per_s"] = round((self.packets - packets) / duration, 1)
                snapshot["mbps"] = round((self.meter.bytes - byte_count) * 8 / 1e6 / duration, 3)
                snapshot["capture"] = self.live_source.stats()
                snapshot["rate_basis"] = "trailing five seconds of processed live packets"
                snapshot["live_latency_ms"] = {name: round(self._persist_latency.quantile(q) / 1e6, 3)
                                                for name, q in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99))}
                snapshot["live_latency_ms"]["count"] = self._persist_latency.count
            return snapshot

    def coverage(self):
        with self._engine_lock:
            return super().coverage()

    def _run_live(self):
        source = self.live_source
        last_tick = 0
        last_report = time.monotonic()
        try:
            while not self._stop.is_set():
                item = source.next_packet()
                with self._engine_lock:
                    if self._stop.is_set():
                        break
                    if item:
                        meta, self._arrival_ns = item
                        self.clock.last_ts_ns = meta.ts_ns
                        self.packets += 1
                        self.meter.observe_packet(meta.length)
                        created = self.engine.flows.created
                        for detection in self.engine.feed(meta):
                            self._emit(detection)
                        if self.engine.flows.created > created:
                            self.meter.observe_flow()
                        tick_ns = meta.ts_ns
                    else:
                        if source.done.is_set():
                            raise RuntimeError(source.error or "Capture stopped unexpectedly")
                        # Only use wall time when the capture queue is drained.
                        # Never expire history ahead of already-buffered packets.
                        # Allow capture-helper buffering around second boundaries;
                        # immediate wall-clock ticks would mark ordinary arrivals
                        # late before dumpcap has delivered them.
                        tick_ns = time.time_ns() - 1_000_000_000 if source.queue.empty() else last_tick
                        self._arrival_ns = time.perf_counter_ns()
                    if tick_ns - last_tick >= 1_000_000_000:
                        last_tick = tick_ns
                        for detection in self.engine.tick(tick_ns):
                            self._emit(detection)
                    self.decode_ns = source.decode_ns
                    now = time.monotonic()
                    if now - last_report >= METRICS_INTERVAL_S:
                        last_report = now
                        self._rate_samples.append((now, self.packets, self.meter.bytes))
                        self.queue.offer("metrics", self.metrics())
                        self.queue.offer("status", self.status())
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            source.close()
            with self._engine_lock:
                final = self.engine.sweep()
                if final:
                    for detection in final:
                        self._emit(detection)
                self.finished = True
                self.queue.offer("metrics", self.metrics())
                self.queue.offer("status", {**self.status(), "running": False})

    def _emit(self, detection):
        if self.source_kind == "live":
            capture = self.live_source.stats()
            drops = capture["queue_dropped"] + capture["stale_dropped"]
            detection.context = {**(detection.context or {}), "ingest": "passive-live",
                                 "capture_session": self.live_session,
                                 "capture_interface": self.live_source.interface,
                                 "sampling_active": drops > 0,
                                 "sampling_ratio": 1 - drops / max(1, capture["packets_decoded"]),
                                 "capture_dropped": drops, "kernel_dropped": None,
                                 "latency_basis": "metadata ingest through alert construction; excludes driver buffering"}
            self.live_counts[detection.threat_class] = self.live_counts.get(detection.threat_class, 0) + 1
        super()._emit(detection)
        if self.source_kind == "live":
            self._persist_latency.add(max(0, time.perf_counter_ns() - self._arrival_ns))
