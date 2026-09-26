import numpy as np
import pytest

from engine.models.anomaly import AnomalyModel
from engine.models.isolation import IsolationPaths


@pytest.mark.parametrize("max_features,samples,bootstrap", [(1.0, 256, False), (.5, 64, False),
                                                          (1.0, 1, False), (1.0, 2, True)])
def test_single_observation_paths_match_sklearn_exactly(max_features, samples, bootstrap):
    from sklearn.ensemble import IsolationForest
    rng = np.random.default_rng(26145)
    fitting = rng.normal(size=(400, 8))
    fitting[:30] = fitting[0]  # Duplicate observations exercise non-singleton leaves.
    forest = IsolationForest(n_estimators=37, max_samples=samples, max_features=max_features,
                             bootstrap=bootstrap, random_state=42, n_jobs=1).fit(fitting)
    fast = IsolationPaths.from_forest(forest)
    assert fast is not None and fast.nbytes > 0
    rows = np.vstack([fitting[:100], rng.normal(size=(100, 8)), np.full((1, 8), 1e20)])
    reference = -forest.score_samples(rows)
    actual = np.array([fast.score(row) for row in rows])
    assert np.array_equal(actual, reference)


def test_missing_values_and_tied_percentiles_preserve_anomaly_decisions():
    rng = np.random.default_rng(123)
    rows = rng.normal(size=(300, 4))
    rows[:40] = 0
    names = [f"x{i}" for i in range(4)]
    model = AnomalyModel.fit(rows, names, trees=31)
    check = np.vstack([rows[:50], [np.nan, np.inf, -np.inf, 0]])
    expected = model.score_many(check)
    observed = np.array([model.score(dict(zip(names, row))) for row in check])
    assert np.array_equal(observed, expected)


def test_values_outside_float32_range_preserve_sklearn_behavior():
    model = AnomalyModel.fit(np.array([[0.], [1.], [2.]]), ["x"], trees=3)
    assert model._paths.score([[1e300]]) is None
    with np.errstate(over="ignore"):
        assert model.score({"x": 1e300}) == model.score_many(np.array([[1e300]]))[0]


def test_unknown_forest_layout_uses_existing_scorer():
    assert IsolationPaths.from_forest(object()) is None
