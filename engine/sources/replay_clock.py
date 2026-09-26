from __future__ import annotations

import time

VIRTUAL = "virtual"
REALTIME = "realtime"
MODES = (VIRTUAL, REALTIME)


class ReplayClock:
    def __init__(self, speed: float = 1.0, mode: str = VIRTUAL, max_sleep_s: float = 5.0) -> None:
        if mode not in MODES:
            raise ValueError("mode must be one of %s" % (MODES,))
        if speed <= 0:
            raise ValueError("speed must be positive")
        self.mode = mode
        self.speed = float(speed)
        self.max_sleep_s = float(max_sleep_s)
        self.first_ts_ns = 0
        self.last_ts_ns = 0
        self.sleeps = 0
        self.slept_s = 0.0
        self.skipped_gaps = 0
        self._anchor_wall = 0.0
        self._anchor_ts_ns = 0
        self._wall_start = 0.0
        self._started = False

    def wait_until(self, ts_ns: int) -> None:
        if not self._started:
            self._start(ts_ns)
        self.last_ts_ns = ts_ns
        if self.mode == VIRTUAL:
            return
        target = self._anchor_wall + (ts_ns - self._anchor_ts_ns) / 1e9 / self.speed
        delay = target - time.perf_counter()
        if delay <= 0:
            return
        if delay > self.max_sleep_s:
            self.skipped_gaps += 1
            self._anchor_wall = time.perf_counter()
            self._anchor_ts_ns = ts_ns
            return
        time.sleep(delay)
        self.sleeps += 1
        self.slept_s += delay

    def set_speed(self, speed: float) -> None:
        if speed <= 0:
            raise ValueError("speed must be positive")
        self._anchor_wall = time.perf_counter()
        self._anchor_ts_ns = self.last_ts_ns
        self.speed = float(speed)

    def reset(self) -> None:
        self.first_ts_ns = 0
        self.last_ts_ns = 0
        self.sleeps = 0
        self.slept_s = 0.0
        self.skipped_gaps = 0
        self._started = False

    @property
    def elapsed_wall_s(self) -> float:
        if not self._started:
            return 0.0
        return time.perf_counter() - self._wall_start

    @property
    def capture_elapsed_s(self) -> float:
        if not self._started:
            return 0.0
        return (self.last_ts_ns - self.first_ts_ns) / 1e9

    def stats(self) -> dict:
        return {
            "mode": self.mode,
            "speed": self.speed,
            "elapsed_wall_s": self.elapsed_wall_s,
            "capture_elapsed_s": self.capture_elapsed_s,
            "sleeps": self.sleeps,
            "slept_s": self.slept_s,
            "skipped_gaps": self.skipped_gaps,
        }

    def _start(self, ts_ns: int) -> None:
        now = time.perf_counter()
        self.first_ts_ns = ts_ns
        self._wall_start = now
        self._anchor_wall = now
        self._anchor_ts_ns = ts_ns
        self._started = True
