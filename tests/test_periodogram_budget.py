"""Resource bounds must abstain visibly, never silently change model features."""
import numpy as np
import pytest

from engine.analysis import lombscargle as periodogram
from engine.detect.base import Context
from engine.models.rules import RuleLayer
from api.replay import FrameQueue, ReplayController
from api.store import AlertStore


def test_long_gap_is_rejected_before_large_allocation(monkeypatch):
    arrivals = np.concatenate((np.arange(32, dtype=float), [10**8]))
    def forbidden(*args, **kwargs):
        raise AssertionError("Attempted timing-grid allocation before budget check")
    monkeypatch.setattr(periodogram.np, "zeros", forbidden)
    with pytest.raises(ValueError, match="event-bin budget"):
        periodogram.event_train(arrivals)


def test_regular_slow_beacon_remains_unchanged():
    arrivals = np.arange(65, dtype=float) * 21600
    grid, counts = periodogram.event_train(arrivals)
    assert len(grid) == 513
    assert counts.sum() == 65
    assert np.array_equal(grid, np.arange(513) * 2700)
    assert np.array_equal(np.flatnonzero(counts), np.arange(0, 513, 8))


def test_budget_abstention_is_counted_and_not_scored_as_benign(monkeypatch):
    rules, ctx = RuleLayer(), Context()
    gaps = np.concatenate((np.ones(31), [1000]))  # finite, small pre-fix reproduction
    key = (6, 1, 2, 443)
    monkeypatch.setattr(ctx.beacons, "ready", lambda now, limit=0: [(key, gaps, 1.0)])
    assert rules.tick_grouped(10**18, ctx) == []
    assert ctx.suppressions[("beaconing", "periodogram-event-bin-budget")] == 1
    assert rules.by_name["beaconing"].stats()["resource_budget_skipped"] == 1
    assert rules.by_name["beaconing"].features() == {}


def test_budget_counter_reaches_dashboard_metrics(tmp_path, monkeypatch):
    store = AlertStore(str(tmp_path / "db"), str(tmp_path / "ledger.jsonl"))
    try:
        controller = ReplayController(FrameQueue(8), store, {"model_enabled": False, "anomaly_enabled": False})
        gaps = np.concatenate((np.ones(31), [1000]))
        monkeypatch.setattr(controller.engine.ctx.beacons, "ready", lambda now, limit=0: [((6, 1, 2, 443), gaps, 1.0)])
        assert controller.engine.tick(10**18) == []
        limits = controller.metrics()["analysis_limits"]
        assert limits["beacon_event_bin_limit"] == 4096
        assert limits["beacon_windows_skipped"] == 1
    finally:
        store.close()
