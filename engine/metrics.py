from __future__ import annotations

import ctypes
import math
import os
import sys
import time
from collections import deque

HIST_MIN_NS = 1000.0
HIST_PER_DECADE = 20
HIST_DECADES = 8
HIST_BUCKETS = HIST_PER_DECADE * HIST_DECADES
STAGES = ("decode", "flow_table", "detect", "features", "tier1", "alert")
RATE_WINDOW_S = 10.0
RATE_SAMPLE_MASK = 0xFF
QUANTILES = ((0.5, "p50"), (0.95, "p95"), (0.99, "p99"), (0.999, "p999"))


def _windows_rss() -> int:
    import ctypes.wintypes as wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetCurrentProcess.argtypes = []
    getter = getattr(kernel32, "K32GetProcessMemoryInfo", None)
    if getter is None:
        getter = ctypes.WinDLL("psapi", use_last_error=True).GetProcessMemoryInfo
    getter.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    getter.restype = wintypes.BOOL
    counters = Counters()
    counters.cb = ctypes.sizeof(Counters)
    if not getter(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
        return 0
    return int(counters.WorkingSetSize)


def _posix_rss() -> int:
    try:
        with open("/proc/self/statm", "r", encoding="ascii") as handle:
            pages = int(handle.read().split()[1])
        return pages * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        pass
    try:
        import resource

        usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(usage) if sys.platform == "darwin" else int(usage) * 1024
    except Exception:
        return 0


def rss_bytes() -> int:
    if sys.platform == "win32":
        return _windows_rss()
    return _posix_rss()


class LatencyHistogram:
    def __init__(self) -> None:
        self.edges = [HIST_MIN_NS * (10.0 ** (i / HIST_PER_DECADE)) for i in range(HIST_BUCKETS + 1)]
        self.counts = [0] * (HIST_BUCKETS + 2)
        self.count = 0
        self.total_ns = 0.0
        self.min_ns = 0.0
        self.max_ns = 0.0

    def add(self, value_ns: float) -> None:
        value = float(value_ns)
        if value < 0.0:
            value = 0.0
        if self.count == 0 or value < self.min_ns:
            self.min_ns = value
        if value > self.max_ns:
            self.max_ns = value
        self.count += 1
        self.total_ns += value
        self.counts[self._index(value)] += 1

    def _index(self, value: float) -> int:
        if value < HIST_MIN_NS:
            return 0
        slot = int(math.log10(value / HIST_MIN_NS) * HIST_PER_DECADE) + 1
        return min(slot, HIST_BUCKETS + 1)

    def quantile(self, q: float) -> float:
        if self.count == 0:
            return 0.0
        target = q * self.count
        seen = 0
        for slot, count in enumerate(self.counts):
            if count == 0:
                continue
            if seen + count < target:
                seen += count
                continue
            lo, hi = self._bounds(slot)
            frac = (target - seen) / count
            if lo <= 0.0:
                return hi * frac
            return min(self.max_ns, lo * ((hi / lo) ** frac))
        return self.max_ns

    def _bounds(self, slot: int) -> tuple[float, float]:
        if slot == 0:
            return 0.0, self.edges[0]
        if slot > HIST_BUCKETS:
            return self.edges[HIST_BUCKETS], max(self.max_ns, self.edges[HIST_BUCKETS])
        return self.edges[slot - 1], self.edges[slot]

    def cumulative_ms(self) -> list[dict]:
        rows = []
        seen = 0
        for slot, count in enumerate(self.counts):
            seen += count
            if count == 0 or slot == 0:
                continue
            rows.append({"le_ms": round(self._bounds(slot)[1] / 1e6, 4), "count": seen})
        return rows

    @property
    def mean_ns(self) -> float:
        return self.total_ns / self.count if self.count else 0.0

    @property
    def nbytes(self) -> int:
        return (len(self.counts) + len(self.edges)) * 8 + 64


class Meter:
    def __init__(self, window_s: float = RATE_WINDOW_S) -> None:
        self.window_s = float(window_s)
        self.started_ns = time.perf_counter_ns()
        self.packets = 0
        self.flows = 0
        self.alerts = 0
        self.bytes = 0
        self.latency = LatencyHistogram()
        self.stage_ns = {name: 0.0 for name in STAGES}
        self.stage_calls = {name: 0 for name in STAGES}
        self.samples: deque[tuple[int, int, int, int, int]] = deque(maxlen=128)
        self.tracked: dict[str, tuple[object, int | None]] = {}
        self.wire_ts_ns = 0
        self.wire_mono_ns = 0
        self.wire_set = False
        self.speed = 1.0
        self._sample(time.perf_counter_ns())

    def start(self) -> None:
        self.reset()

    def observe_packet(self, n_bytes: int) -> None:
        self.packets += 1
        self.bytes += int(n_bytes)
        if not self.packets & RATE_SAMPLE_MASK:
            self._sample(time.perf_counter_ns())

    def observe_flow(self) -> None:
        self.flows += 1

    def observe_alert(self, latency_ns: int) -> None:
        self.alerts += 1
        self.latency.add(latency_ns)

    def observe_stage(self, stage: str, elapsed_ns: float) -> None:
        self.stage_ns[stage] = self.stage_ns.get(stage, 0.0) + float(elapsed_ns)
        self.stage_calls[stage] = self.stage_calls.get(stage, 0) + 1

    def mark_wire(self, ts_ns: int, mono_ns: int | None = None) -> None:
        self.wire_ts_ns = int(ts_ns)
        self.wire_mono_ns = time.perf_counter_ns() if mono_ns is None else int(mono_ns)
        self.wire_set = True

    def anchor_replay(self, ts_ns: int, speed: float = 1.0, mono_ns: int | None = None) -> None:
        self.speed = max(1e-9, float(speed))
        self.mark_wire(ts_ns, mono_ns)

    def latency_for(self, ts_ns: int, now_mono_ns: int | None = None) -> int:
        if not self.wire_set:
            return 0
        now = time.perf_counter_ns() if now_mono_ns is None else int(now_mono_ns)
        wire = self.wire_mono_ns + (int(ts_ns) - self.wire_ts_ns) / self.speed
        return int(max(0.0, now - wire))

    def observe_alert_for(self, ts_ns: int, now_mono_ns: int | None = None) -> int:
        latency = self.latency_for(ts_ns, now_mono_ns)
        self.observe_alert(latency)
        return latency

    def track(self, name: str, obj: object, cap: int | None = None) -> None:
        self.tracked[name] = (obj, cap)

    def _sample(self, now_ns: int) -> None:
        self.samples.append((now_ns, self.packets, self.bytes, self.flows, self.alerts))

    def _rates(self, now_ns: int) -> tuple[float, float, float, float]:
        self._sample(now_ns)
        oldest = self.samples[0]
        for sample in self.samples:
            if (now_ns - sample[0]) / 1e9 <= self.window_s:
                oldest = sample
                break
        span = (now_ns - oldest[0]) / 1e9
        if span < 0.05:
            span = (now_ns - self.started_ns) / 1e9
            oldest = (self.started_ns, 0, 0, 0, 0)
        if span <= 0.0:
            return 0.0, 0.0, 0.0, 0.0
        return ((self.packets - oldest[1]) / span, (self.bytes - oldest[2]) * 8.0 / 1e6 / span,
                (self.flows - oldest[3]) / span, (self.alerts - oldest[4]) / span)

    def memory(self) -> tuple[dict, dict]:
        sizes, caps = {}, {}
        for name, (obj, cap) in list(self.tracked.items()):
            value = getattr(obj, "nbytes", None)
            if value is None:
                continue
            sizes[name] = int(value)
            caps[name] = int(cap if cap is not None else getattr(obj, "capacity_bytes", value))
        return sizes, caps

    def snapshot(self) -> dict:
        now = time.perf_counter_ns()
        pps, mbps, fps, aps = self._rates(now)
        sizes, caps = self.memory()
        stages = list(self.stage_ns.items())
        rss = rss_bytes()
        return {
            "uptime_s": round((now - self.started_ns) / 1e9, 3),
            "packets": self.packets,
            "flows": self.flows,
            "alerts": self.alerts,
            "bytes": self.bytes,
            "packets_per_s": round(pps, 1),
            "flows_per_s": round(fps, 2),
            "alerts_per_s": round(aps, 3),
            "mbps": round(mbps, 3),
            "latency_ms": {name: round(self.latency.quantile(q) / 1e6, 3) for q, name in QUANTILES},
            "latency_mean_ms": round(self.latency.mean_ns / 1e6, 3),
            "latency_max_ms": round(self.latency.max_ns / 1e6, 3),
            "latency_count": self.latency.count,
            "latency_histogram": self.latency.cumulative_ms(),
            "rss_mb": round(rss / 1e6, 2),
            "rss_bytes": rss,
            "stage_timing_us": {name: round(total / 1000.0 / max(1, self.stage_calls.get(name, 0)), 3)
                                for name, total in stages},
            "stage_timing_per_packet_us": {name: round(total / 1000.0 / max(1, self.packets), 3)
                                           for name, total in stages},
            "stage_calls": dict(self.stage_calls),
            "stage_total_ms": {name: round(total / 1e6, 3) for name, total in stages},
            "memory_bytes": sizes,
            "memory_caps_bytes": caps,
            "memory_total_bytes": sum(sizes.values()),
        }

    def reset(self) -> None:
        tracked = dict(self.tracked)
        self.__init__(self.window_s)
        self.tracked = tracked

    @property
    def nbytes(self) -> int:
        return self.latency.nbytes + self.samples.maxlen * 48 + 256
