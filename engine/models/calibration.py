"""Apply exported calibration curves identically in batch evaluation and live scoring."""
from __future__ import annotations

import numpy as np


def apply_curve(values, curve):
    if "a" in curve and "b" in curve:
        # sklearn's sigmoid calibrator uses expit(-(a * score + b)).
        return np.exp(-np.logaddexp(0.0, curve["a"] * values + curve["b"]))
    return np.interp(values, curve["x"], curve["y"])


def calibrate_matrix(source, fallback, curves, classes):
    source, fallback = np.asarray(source), np.asarray(fallback)
    out = np.empty_like(fallback, dtype=np.float64)
    for i, name in enumerate(classes):
        curve = curves.get(name)
        out[..., i] = apply_curve(source[..., i], curve) if curve else fallback[..., i]
    totals = out.sum(axis=-1, keepdims=True)
    return np.divide(out, totals, out=np.full_like(out, 1.0 / len(classes)), where=totals > 0)
