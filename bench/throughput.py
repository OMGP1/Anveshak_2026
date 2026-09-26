from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from dataclasses import replace
from typing import Any, Iterable, Iterator

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from engine.alerts.schema import GENESIS_HASH, build_alert, validate_alert
from engine.detect import Context, build_detectors
from engine.metrics import Meter, rss_bytes
from engine.sources.flowrecord_source import FlowRecordSource
from engine.sources.pcap_source import PcapSource
from engine.sources.rust_source import RustPcapSource
from engine.sources.replay_clock import ReplayClock
from engine.state.flow_table import FlowTable
from engine.types import Detection, PacketMeta
from training.scenarios import SCENARIOS, abspath

FALLBACK_LINEAGE = {
    "model_id": "rules-v0",
    "model_hash": GENESIS_HASH,
    "dataset_version": "2026-09-07-synthetic-v1",
}

LOOP_GAP_NS = 1_000_000_000
DEFAULT_TICK_S = 1.0
DEFAULT_BUCKET_S = 1.0
DEFAULT_WARMUP_S = 2.0
DEFAULT_DURATION_S = 60.0
MAX_LATENCY_SAMPLES = 200_000
TOP_STAGES = ("source", "clock", "engine_feed", "engine_tick", "alert_out")

VIRTUAL_LATENCY_BASIS = (
    "ingest-to-alert: the packet entering the engine to a built and schema-validated alert. "
    "virtual mode has no wall clock wire, so this is pipeline latency, not wire-to-alert"
)
REALTIME_LATENCY_BASIS = (
    "wire-to-alert: from the scheduled wire moment of the alert's own timestamp on the replay "
    "clock to a built and schema-validated alert"
)


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    pos = q * (len(ordered) - 1)
    low = int(pos)
    high = min(low + 1, len(ordered) - 1)
    frac = pos - low
    return float(ordered[low] * (1.0 - frac) + ordered[high] * frac)


def shift(meta: PacketMeta, offset_ns: int) -> PacketMeta:
    return replace(meta, ts_ns=meta.ts_ns + offset_ns)


class BenchEngine:
    name = "bench.inline"

    def __init__(self, config: dict | None = None) -> None:
        cfg = dict(config or {})
        self.config = cfg
        self.meter = Meter()
        self.flows = FlowTable(
            capacity=int(cfg.get("flow_capacity", 200_000)),
            idle_timeout_s=float(cfg.get("flow_idle_timeout_s", 120.0)),
        )
        self.ctx = Context(cfg.get("context"))
        self.detectors = build_detectors(cfg.get("detectors"))
        self.packets = 0
        self.expired = 0
        self.meter.track("flow_table", self.flows)
        self.meter.track("beacon_table", self.ctx.beacons)

    def feed(self, meta: PacketMeta) -> list[Detection]:
        t0 = time.perf_counter_ns()
        self.packets += 1
        flow = self.flows.observe(meta)
        self.ctx.begin_packet(meta, flow)
        t1 = time.perf_counter_ns()
        out: list[Detection] = []
        for detector in self.detectors:
            found = detector.observe(meta, flow, self.ctx)
            if found:
                out.extend(found)
        t2 = time.perf_counter_ns()
        self.meter.observe_stage("flow_table", t1 - t0)
        self.meter.observe_stage("detect", t2 - t1)
        return out

    def tick(self, now_ns: int) -> list[Detection]:
        t0 = time.perf_counter_ns()
        self.expired += len(self.flows.expire(now_ns))
        t1 = time.perf_counter_ns()
        out: list[Detection] = []
        for detector in self.detectors:
            found = detector.tick(now_ns, self.ctx)
            if found:
                out.extend(found)
        self.meter.observe_stage("flow_table", t1 - t0)
        self.meter.observe_stage("detect", time.perf_counter_ns() - t1)
        return out

    def memory_bytes(self) -> dict[str, int]:
        sizes = {"flow_table": int(self.flows.nbytes)}
        sizes.update(self.ctx.memory_bytes())
        return sizes

    def memory_caps_bytes(self) -> dict[str, int]:
        caps = {"flow_table": int(self.flows.capacity_bytes)}
        caps.update(self.ctx.memory_caps_bytes())
        return caps

    def lineage(self) -> dict:
        return dict(FALLBACK_LINEAGE)

    def stats(self) -> dict:
        return {
            "engine": self.name,
            "packets": self.packets,
            "flow_table_entries": len(self.flows),
            "flows_created": self.flows.created,
            "flows_evicted": self.flows.evicted,
            "flows_expired": self.expired,
            "memory_bytes": self.memory_bytes(),
            "memory_caps_bytes": self.memory_caps_bytes(),
        }


def resolve_engine(config: dict | None) -> tuple[Any, str]:
    try:
        from engine.pipeline import Engine
    except ImportError:
        return BenchEngine(config), BenchEngine.name
    return Engine(dict(config or {})), "engine.pipeline"


def scenario_paths(names: list[str], kind: str) -> list[tuple[str, str]]:
    index = {row["id"]: row for row in SCENARIOS}
    key = "flow_file" if kind == "flows" else "file"
    chosen: list[tuple[str, str]] = []
    for name in names:
        if name == "all":
            chosen.extend((row["id"], row[key]) for row in SCENARIOS)
            continue
        row = index.get(name)
        if row is not None:
            chosen.append((row["id"], row[key]))
        elif os.path.exists(name):
            chosen.append((os.path.basename(name), name))
        else:
            raise SystemExit("unknown scenario %r, expected all, a file path, or one of %s"
                             % (name, ", ".join(sorted(index))))
    return [(sid, path if os.path.isabs(path) else abspath(path)) for sid, path in chosen]


def open_source(path: str, kind: str) -> Any:
    return FlowRecordSource(path) if kind == "flows" else RustPcapSource(path) if kind == "rust-pcap" else PcapSource(path)


def host_facts() -> dict:
    return {
        "python": sys.version.split()[0],
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
    }


class Run:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.meter = Meter()
        self.engine, self.engine_name = resolve_engine(args.config)
        self.clock = ReplayClock(speed=args.speed, mode=args.mode)
        self.ledger = self._open_ledger()
        self.lineage = self._lineage()
        self.packets = 0
        self.records = 0
        self.bytes = 0
        self.alerts = 0
        self.starts = 0
        self.sources_n = 0
        self.ticks = 0
        self.top_ns = {name: 0 for name in TOP_STAGES}
        self.latencies: list[int] = []
        self.samples: list[dict] = []
        self.peak_rss = 0
        self.anchored = False
        self.offset_ns = 0
        self.ingress_ns = 0
        self.started_ns = 0
        self.looped_ns = 0
        self.stopped_ns = 0

    def _open_ledger(self) -> Any:
        if not self.args.ledger:
            return None
        from engine.alerts.ledger import Ledger

        return Ledger(self.args.ledger)

    def _lineage(self) -> dict:
        getter = getattr(self.engine, "lineage", None)
        base = dict(FALLBACK_LINEAGE)
        if callable(getter):
            found = getter()
            if isinstance(found, dict):
                base.update({k: v for k, v in found.items() if v})
        return base

    def _lineage_for(self, detection: Detection) -> dict:
        base = dict(self.lineage)
        getter = getattr(self.engine, "lineage_for", None)
        if callable(getter):
            base.update({k: v for k, v in getter(detection).items() if v is not None})
        return base

    def flows_created(self) -> int:
        table = getattr(self.engine, "flows", None)
        return int(getattr(table, "created", 0))

    def open_sources(self) -> list[tuple[str, Any]]:
        pairs = scenario_paths(self.args.scenario, self.args.source)
        self.sources_n = len(pairs)
        return [(sid, open_source(path, self.args.source)) for sid, path in pairs]

    def cycle(self, opened: list[tuple[str, Any]]) -> Iterator[tuple[str, Any]]:
        while True:
            for sid, source in opened:
                self.starts += 1
                yield sid, source
            if not self.args.loop:
                return

    def emit(self, detection: Detection) -> None:
        t0 = time.perf_counter_ns()
        if self.args.mode == "realtime" and self.anchored:
            before = self.meter.latency_for(detection.ts_ns, t0)
        else:
            before = max(0, t0 - self.ingress_ns)
        lineage = self._lineage_for(detection)
        lineage["latency_ns"] = before
        lineage["latency_ms"] = before / 1e6
        lineage["prev_hash"] = getattr(self.ledger, "head", GENESIS_HASH) or GENESIS_HASH
        alert = build_alert(detection, lineage)
        validate_alert(alert)
        if self.ledger is not None:
            self.ledger.append(alert)
        t1 = time.perf_counter_ns()
        self.top_ns["alert_out"] += t1 - t0
        latency = before + (t1 - t0)
        self.meter.observe_alert(latency)
        self.alerts += 1
        if len(self.latencies) < MAX_LATENCY_SAMPLES:
            self.latencies.append(latency)

    def sample(self, now_ns: int, phase: str = "run") -> None:
        rss = rss_bytes()
        if rss > self.peak_rss:
            self.peak_rss = rss
        self.samples.append({
            "phase": phase,
            "wall_s": (now_ns - self.started_ns) / 1e9,
            "packets": self.packets,
            "records": self.records,
            "bytes": self.bytes,
            "flows": self.flows_created(),
            "alerts": self.alerts,
            "rss_bytes": rss,
        })

    def execute(self) -> None:
        args = self.args
        bucket_ns = int(args.bucket * 1e9)
        deadline_ns = int(args.duration * 1e9)
        tick_every_ns = int(args.tick_interval * 1e9)
        last_tick_ns = 0
        opened = self.open_sources()
        self.started_ns = time.perf_counter_ns()
        next_sample_ns = self.started_ns + bucket_ns
        self.sample(self.started_ns, "start")
        stop = False
        for _sid, source in self.cycle(opened):
            first_ts = 0
            last_ts = 0
            iterator: Iterable[PacketMeta] = iter(source)
            while True:
                t0 = time.perf_counter_ns()
                try:
                    meta = next(iterator)
                except StopIteration:
                    self.top_ns["source"] += time.perf_counter_ns() - t0
                    break
                if self.offset_ns:
                    meta = shift(meta, self.offset_ns)
                t1 = time.perf_counter_ns()
                self.top_ns["source"] += t1 - t0
                if not first_ts:
                    first_ts = meta.ts_ns
                last_ts = meta.ts_ns
                self.clock.wait_until(meta.ts_ns)
                self.ingress_ns = time.perf_counter_ns()
                self.top_ns["clock"] += self.ingress_ns - t1
                if not self.anchored:
                    self.anchored = True
                    self.meter.anchor_replay(meta.ts_ns, args.speed, self.ingress_ns)
                self.packets += meta.packets
                self.records += 1
                self.bytes += meta.length
                self.meter.observe_packet(meta.length)
                spent = self.top_ns["alert_out"]
                for detection in self.engine.feed(meta):
                    self.emit(detection)
                t2 = time.perf_counter_ns()
                self.top_ns["engine_feed"] += (t2 - self.ingress_ns) - (self.top_ns["alert_out"] - spent)
                if meta.ts_ns - last_tick_ns >= tick_every_ns:
                    last_tick_ns = meta.ts_ns
                    self.ticks += 1
                    spent = self.top_ns["alert_out"]
                    for detection in self.engine.tick(meta.ts_ns):
                        self.emit(detection)
                    self.top_ns["engine_tick"] += (time.perf_counter_ns() - t2
                                                   - (self.top_ns["alert_out"] - spent))
                now = time.perf_counter_ns()
                if now >= next_sample_ns:
                    self.sample(now)
                    while next_sample_ns <= now:
                        next_sample_ns += bucket_ns
                if now - self.started_ns >= deadline_ns:
                    stop = True
                    break
            if last_ts:
                self.offset_ns += (last_ts - first_ts) + LOOP_GAP_NS
            if stop:
                break
        self.looped_ns = time.perf_counter_ns()
        for detection in self.engine.tick(last_tick_ns + tick_every_ns):
            self.emit(detection)
        if hasattr(self.engine, "sweep"):
            final = self.engine.sweep()
            if final:
                for detection in final:
                    self.emit(detection)
        self.stopped_ns = time.perf_counter_ns()
        self.sample(self.stopped_ns, "flush")
        if self.ledger is not None:
            self.ledger.close()

    def rates(self) -> dict:
        floor = 0.5 * self.args.bucket
        rows = []
        for prev, cur in zip(self.samples, self.samples[1:]):
            span = cur["wall_s"] - prev["wall_s"]
            if span < floor or cur["phase"] != "run":
                continue
            rows.append({
                "wall_s": cur["wall_s"],
                "packets_per_s": (cur["packets"] - prev["packets"]) / span,
                "records_per_s": (cur["records"] - prev["records"]) / span,
                "flows_per_s": (cur["flows"] - prev["flows"]) / span,
                "mbps": (cur["bytes"] - prev["bytes"]) * 8.0 / 1e6 / span,
            })
        steady = [row for row in rows if row["wall_s"] >= self.args.warmup] or rows
        out: dict[str, Any] = {
            "buckets": len(rows),
            "steady_buckets": len(steady),
            "warmup_s": self.args.warmup,
        }
        for name in ("flows_per_s", "packets_per_s", "records_per_s", "mbps"):
            values = [row[name] for row in steady]
            out[name] = {
                "p50": round(percentile(values, 0.5), 1),
                "p5": round(percentile(values, 0.05), 1),
                "min": round(min(values), 1) if values else 0.0,
                "max": round(max(values), 1) if values else 0.0,
                "mean": round(sum(values) / len(values), 1) if values else 0.0,
            }
        return out

    def stages(self, elapsed_ns: int) -> dict:
        top = {name: round(self.top_ns[name] / 1e6, 1) for name in TOP_STAGES}
        accounted = sum(self.top_ns.values())
        top["harness"] = round(max(0, elapsed_ns - accounted) / 1e6, 1)
        calls = {
            "source": self.records,
            "clock": self.records,
            "engine_feed": self.records,
            "engine_tick": self.ticks,
            "alert_out": self.alerts,
            "harness": self.records,
        }
        per_call = {name: round(self.top_ns.get(name, 0) / 1000.0 / max(1, calls[name]), 3) for name in top}
        inner_ns: dict[str, float] = {}
        inner_calls: dict[str, int] = {}
        meter = getattr(self.engine, "meter", None)
        if meter is not None:
            for name, total in meter.stage_ns.items():
                if total <= 0.0:
                    continue
                inner_ns[name] = round(total / 1e6, 1)
                inner_calls[name] = int(meter.stage_calls.get(name, 0))
        return {
            "top_total_ms": top,
            "top_calls": calls,
            "top_us_per_call": per_call,
            "engine_total_ms": inner_ns,
            "engine_calls": inner_calls,
            "engine_us_per_call": {
                name: round(inner_ns[name] * 1000.0 / max(1, inner_calls.get(name, 0)), 3) for name in inner_ns
            },
        }

    def notes(self, elapsed: float) -> list[str]:
        out = []
        speedup = (self.offset_ns / 1e9) / elapsed if elapsed > 0 else 0.0
        if self.ticks and speedup > 1.5:
            out.append(
                "periodic tick work is driven by capture time, not by tick count: this run pushed %.0f s "
                "of capture through in %.1f s of wall clock, a %.0fx speedup, so the engine did about "
                "%.0f times the periodic analysis per wall second that a live link at this packet rate "
                "would ask for" % (self.offset_ns / 1e9, elapsed, speedup, speedup)
            )
        if self.starts > self.sources_n:
            out.append(
                "the capture set was replayed %.1f times end to end, each pass offset forward in capture "
                "time; repeated sessions then look periodic at the capture period, which raises beacon "
                "evaluation cost, so any alert from a looped run is a replay artefact, not a detection"
                % (self.starts / max(1, self.sources_n))
            )
        if self.args.mode == "virtual":
            out.append("virtual mode consumes as fast as the engine can, so this is the throughput claim "
                       "and not the demo claim, and its latency is ingest-to-alert")
        else:
            out.append("realtime mode honours the original packet timing at speed %g, so this is the demo "
                       "claim and its latency is true wire-to-alert" % self.args.speed)
        out.append("opening each source indexes the capture and happens before the clock starts, so it is "
                   "not counted against throughput")
        if len(self.latencies) < 1000:
            out.append("p999 needs at least 1000 alerts to mean anything and this run produced %d"
                       % len(self.latencies))
        return out

    def report(self) -> dict:
        elapsed_ns = self.looped_ns - self.started_ns
        elapsed = elapsed_ns / 1e9
        flush = (self.stopped_ns - self.looped_ns) / 1e9
        snapshot = self.meter.snapshot()
        stats = self.engine.stats() if hasattr(self.engine, "stats") else {}
        sizes = stats.get("memory_bytes") or {}
        caps = stats.get("memory_caps_bytes") or {}
        return {
            "harness": "bench/throughput.py",
            "command": " ".join(["python"] + sys.argv),
            "host": host_facts(),
            "config": {
                "scenario": self.args.scenario,
                "mode": self.args.mode,
                "speed": self.args.speed,
                "source": self.args.source,
                "duration_s": self.args.duration,
                "bucket_s": self.args.bucket,
                "warmup_s": self.args.warmup,
                "tick_interval_capture_s": self.args.tick_interval,
                "loop": self.args.loop,
                "ledger": self.args.ledger or "off",
                "engine_config": self.args.config or {},
            },
            "engine": self.engine_name,
            "lineage": {k: v for k, v in self.lineage.items() if not k.startswith("latency")},
            "elapsed_s": round(elapsed, 3),
            "final_flush_s": round(flush, 3),
            "capture_span_s": round(self.offset_ns / 1e9, 3),
            "cycles": round(self.starts / max(1, self.sources_n), 2),
            "capture_speedup": round((self.offset_ns / 1e9) / elapsed, 1) if elapsed else 0.0,
            "totals": {
                "records": self.records,
                "packets": self.packets,
                "bytes": self.bytes,
                "flows": self.flows_created(),
                "alerts": self.alerts,
                "ticks": self.ticks,
            },
            "mean": {
                "records_per_s": round(self.records / elapsed, 1) if elapsed else 0.0,
                "packets_per_s": round(self.packets / elapsed, 1) if elapsed else 0.0,
                "flows_per_s": round(self.flows_created() / elapsed, 1) if elapsed else 0.0,
                "mbps": round(self.bytes * 8.0 / 1e6 / elapsed, 3) if elapsed else 0.0,
            },
            "sustained": self.rates(),
            "latency_ms": {
                "p50": round(percentile(self.latencies, 0.5) / 1e6, 3),
                "p95": round(percentile(self.latencies, 0.95) / 1e6, 3),
                "p99": round(percentile(self.latencies, 0.99) / 1e6, 3),
                "p999": round(percentile(self.latencies, 0.999) / 1e6, 3),
                "max": round(max(self.latencies) / 1e6, 3) if self.latencies else 0.0,
            },
            "latency_samples": len(self.latencies),
            "latency_basis": (REALTIME_LATENCY_BASIS if self.args.mode == "realtime" else VIRTUAL_LATENCY_BASIS)
                + ("; includes ledger append/fsync, excludes DuckDB and browser delivery" if self.ledger else ""),
            "latency_histogram_ms": snapshot["latency_ms"],
            "peak_rss_mb": round(self.peak_rss / 1e6, 2),
            "final_rss_mb": snapshot["rss_mb"],
            "memory_bytes": sizes,
            "memory_caps_bytes": caps,
            "stages": self.stages(elapsed_ns),
            "engine_stats": {k: v for k, v in stats.items() if k not in ("memory_bytes", "memory_caps_bytes")},
            "notes": self.notes(elapsed),
        }


def format_report(report: dict) -> str:
    cfg = report["config"]
    lines = [
        "scenario %s  mode %s  source %s  speed %g  engine %s"
        % (",".join(cfg["scenario"]), cfg["mode"], cfg["source"], cfg["speed"], report["engine"]),
        "model %s  hash %s  dataset %s"
        % (report["lineage"].get("model_id"), str(report["lineage"].get("model_hash"))[:23],
           report["lineage"].get("dataset_version")),
        "elapsed %.2f s covering %.1f s of capture time over %.2f passes of the capture set, "
        "plus %.2f s of end of run flush"
        % (report["elapsed_s"], report["capture_span_s"], report["cycles"], report["final_flush_s"]),
    ]
    totals = report["totals"]
    lines.append("totals: %d records, %d packets, %.1f MB, %d flows, %d alerts, %d ticks"
                 % (totals["records"], totals["packets"], totals["bytes"] / 1e6,
                    totals["flows"], totals["alerts"], totals["ticks"]))
    mean = report["mean"]
    lines.append("run mean: %.0f packets/s, %.0f flows/s, %.2f Mbps"
                 % (mean["packets_per_s"], mean["flows_per_s"], mean["mbps"]))
    sus = report["sustained"]
    lines += ["", "sustained rate over %d samples of %.2f s, first %.1f s discarded"
              % (sus["steady_buckets"], cfg["bucket_s"], sus["warmup_s"]),
              "  %-14s %11s %11s %11s %11s" % ("", "p50", "p5", "min", "max")]
    for name, label in (("flows_per_s", "flows/s"), ("packets_per_s", "packets/s"),
                        ("records_per_s", "records/s"), ("mbps", "Mbps")):
        row = sus[name]
        lines.append("  %-14s %11.1f %11.1f %11.1f %11.1f" % (label, row["p50"], row["p5"], row["min"], row["max"]))
    lat = report["latency_ms"]
    lines += ["", "latency from %d alerts, %s" % (report["latency_samples"], report["latency_basis"]),
              "  p50 %.3f ms   p95 %.3f ms   p99 %.3f ms   p999 %.3f ms   max %.3f ms"
              % (lat["p50"], lat["p95"], lat["p99"], lat["p999"], lat["max"])]
    lines += ["", "peak rss %.2f MB, final rss %.2f MB" % (report["peak_rss_mb"], report["final_rss_mb"])]
    for name, value in sorted(report["memory_bytes"].items()):
        cap = report["memory_caps_bytes"].get(name)
        lines.append("  %-14s %8.2f MB%s" % (name, value / 1e6, " of %.1f MB cap" % (cap / 1e6) if cap else ""))
    stages = report["stages"]
    elapsed_ms = report["elapsed_s"] * 1000.0 or 1.0
    lines += ["", "where the wall clock went", "  %-14s %10s %12s %12s %8s"
              % ("stage", "calls", "us/call", "total ms", "share")]
    for name, total in stages["top_total_ms"].items():
        lines.append("  %-14s %10d %12.3f %12.1f %7.1f%%"
                     % (name, stages["top_calls"].get(name, 0), stages["top_us_per_call"].get(name, 0.0),
                        total, 100.0 * total / elapsed_ms))
    if stages["engine_total_ms"]:
        lines += ["", "inside the engine, as the engine's own meter reports it",
                  "  %-14s %10s %12s %12s %8s" % ("stage", "calls", "us/call", "total ms", "share")]
        for name, total in stages["engine_total_ms"].items():
            lines.append("  %-14s %10d %12.3f %12.1f %7.1f%%"
                         % (name, stages["engine_calls"].get(name, 0),
                            stages["engine_us_per_call"].get(name, 0.0), total, 100.0 * total / elapsed_ms))
    lines.append("")
    lines += ["note: " + note for note in report.get("notes", [])]
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="bench/throughput.py",
                                     description="throughput and latency harness for constraint C-d")
    parser.add_argument("--scenario", action="append", default=None,
                        help="scenario id, all, or a pcap or csv path; repeatable")
    parser.add_argument("--mode", choices=("virtual", "realtime"), default="virtual")
    parser.add_argument("--speed", type=float, default=1.0, help="replay speed multiplier, realtime only")
    parser.add_argument("--source", choices=("pcap", "rust-pcap", "flows"), default="pcap")
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION_S, help="wall clock seconds to run")
    parser.add_argument("--bucket", type=float, default=DEFAULT_BUCKET_S, help="rate sampling interval, seconds")
    parser.add_argument("--warmup", type=float, default=DEFAULT_WARMUP_S, help="seconds dropped from percentiles")
    parser.add_argument("--tick-interval", type=float, default=DEFAULT_TICK_S,
                        help="capture seconds between periodic detector ticks")
    parser.add_argument("--loop", dest="loop", action="store_true",
                        help="replay the scenario set again, offset forward, until the duration is reached")
    parser.add_argument("--no-loop", dest="loop", action="store_false", help="one pass only, the default")
    parser.add_argument("--rules-only", action="store_true", help="disable the model layer, rules only")
    parser.add_argument("--engine-config", default="", help="JSON engine profile to qualify")
    parser.add_argument("--ledger", default="", help="also append every alert to this ledger path")
    parser.add_argument("--json", dest="json_path", default="", help="write the full report as json")
    parser.set_defaults(loop=False, config=None)
    args = parser.parse_args(argv)
    if not args.scenario:
        args.scenario = ["all"]
    if args.engine_config:
        with open(args.engine_config, encoding="utf-8") as config_file:
            args.config = json.load(config_file)
        if not isinstance(args.config, dict):
            raise SystemExit("engine config must be a JSON object")
    if args.rules_only:
        args.config = {**(args.config or {}), "model_enabled": False, "anomaly_enabled": False}
    if args.duration <= 0 or args.bucket <= 0 or args.tick_interval <= 0 or args.speed <= 0:
        raise SystemExit("duration, bucket, tick-interval and speed must all be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    run = Run(args)
    run.execute()
    report = run.report()
    print(format_report(report))
    if args.json_path:
        with open(args.json_path, "w", encoding="ascii") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
        print("\nwrote " + args.json_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
