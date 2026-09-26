from __future__ import annotations

import math

import numpy as np

N_FREQS = 512
OVERSAMPLE = 8.0
FMAX_SCALE = 0.9
GAP_QUANTILE = 0.1
HARMONIC_FRAC = 0.5
_BLOCK = 64
MAX_EVENT_BINS = 4096


class PeriodogramBudgetExceeded(ValueError):
    """Abstain instead of allocating a grid proportional to an arbitrarily long gap."""


def lomb_scargle(times: np.ndarray, values: np.ndarray, freqs: np.ndarray) -> np.ndarray:
    t = np.asarray(times, dtype=np.float64)
    y = np.asarray(values, dtype=np.float64)
    f = np.asarray(freqs, dtype=np.float64)
    if t.size != y.size:
        raise ValueError("times and values must have the same length")
    power = np.zeros(f.size, dtype=np.float64)
    if t.size < 3 or f.size == 0:
        return power
    y = y - y.mean()
    var = float(y.var(ddof=1))
    if var <= 0.0:
        return power
    for lo in range(0, f.size, _BLOCK):
        hi = min(lo + _BLOCK, f.size)
        w = 2.0 * np.pi * f[lo:hi]
        wt = w[:, None] * t[None, :]
        tau = np.arctan2(np.sin(2.0 * wt).sum(axis=1), np.cos(2.0 * wt).sum(axis=1)) / (2.0 * w)
        shifted = wt - (w * tau)[:, None]
        co = np.cos(shifted)
        si = np.sin(shifted)
        cc = (co * co).sum(axis=1)
        ss = (si * si).sum(axis=1)
        yc = co @ y
        ys = si @ y
        block = np.zeros(hi - lo, dtype=np.float64)
        ok = cc > 1e-12
        block[ok] += yc[ok] ** 2 / cc[ok]
        ok = ss > 1e-12
        block[ok] += ys[ok] ** 2 / ss[ok]
        power[lo:hi] = block / (2.0 * var)
    return power


def event_train(arrivals_s: np.ndarray, oversample: float = OVERSAMPLE) -> tuple[np.ndarray, np.ndarray]:
    t = np.asarray(arrivals_s, dtype=np.float64)
    t = t - t[0]
    gaps = np.diff(t)
    step = float(np.median(gaps)) / oversample
    if step <= 0.0:
        step = max(float(t[-1]) / (t.size * oversample), 1e-9)
    n = int(math.ceil(t[-1] / step)) + 1
    if n > MAX_EVENT_BINS:
        raise PeriodogramBudgetExceeded(f"periodogram event-bin budget exceeded: {n} > {MAX_EVENT_BINS}")
    counts = np.zeros(n, dtype=np.float64)
    np.add.at(counts, np.clip((t / step).astype(np.int64), 0, n - 1), 1.0)
    return np.arange(n, dtype=np.float64) * step, counts


def frequency_grid(arrivals_s: np.ndarray, n_freqs: int = N_FREQS, fmax_scale: float = FMAX_SCALE) -> np.ndarray:
    t = np.asarray(arrivals_s, dtype=np.float64)
    span = float(t[-1] - t[0])
    short_gap = float(np.quantile(np.diff(t), GAP_QUANTILE))
    if span <= 0.0 or short_gap <= 0.0:
        return np.empty(0, dtype=np.float64)
    fmin = 2.0 / span
    fmax = 1.0 / (fmax_scale * short_gap)
    if fmax <= fmin:
        fmax = 2.0 * fmin
    return np.logspace(math.log10(fmin), math.log10(fmax), n_freqs)


def false_alarm_probability(power: float, n_freqs: int) -> float:
    if power <= 0.0:
        return 1.0
    tail = math.exp(-power)
    if tail <= 0.0:
        return 0.0
    return float(-math.expm1(n_freqs * math.log1p(-tail)))


def peak_period(
    times: np.ndarray,
    values: np.ndarray | None = None,
    n_freqs: int = N_FREQS,
) -> tuple[float, float, float]:
    t = np.asarray(times, dtype=np.float64)
    if t.size < 4:
        return 0.0, 0.0, 1.0
    freqs = frequency_grid(t, n_freqs)
    if freqs.size == 0:
        return 0.0, 0.0, 1.0
    if values is None:
        grid, series = event_train(t)
    else:
        grid, series = t, np.asarray(values, dtype=np.float64)
    power = lomb_scargle(grid, series, freqs)
    i = _fundamental(power, freqs)
    z = float(power[i])
    return float(1.0 / freqs[i]), z, false_alarm_probability(z, n_freqs)


def _fundamental(power: np.ndarray, freqs: np.ndarray) -> int:
    peak = int(np.argmax(power))
    top = float(power[peak])
    if top <= 0.0:
        return peak
    for k in (4, 3, 2):
        target = freqs[peak] / k
        if target < freqs[0]:
            continue
        j = int(np.argmin(np.abs(freqs - target)))
        if abs(freqs[j] - target) / target < 0.05 and power[j] >= HARMONIC_FRAC * top:
            return j
    return peak


def peak_period_from_iats(iats_s: np.ndarray, n_freqs: int = N_FREQS) -> tuple[float, float, float]:
    gaps = np.asarray(iats_s, dtype=np.float64)
    if gaps.size < 4:
        return 0.0, 0.0, 1.0
    arrivals = np.concatenate(([0.0], np.cumsum(gaps)))
    return peak_period(arrivals, None, n_freqs)
