"""Traverse a fitted Isolation Forest across all trees for one observation at a time."""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np


@dataclass(slots=True)
class IsolationPaths:
    roots: np.ndarray
    left: np.ndarray
    right: np.ndarray
    features: np.ndarray
    thresholds: np.ndarray
    contributions: np.ndarray
    maximum_depth: int
    denominator: np.ndarray

    @classmethod
    def from_forest(cls, forest):
        # These arrays are created by sklearn when fitting. Older unsupported
        # layouts retain sklearn's normal scoring path rather than guessing.
        required = ("_decision_path_lengths", "_average_path_length_per_tree",
                    "estimators_", "estimators_features_", "_max_samples", "_max_features", "n_features_in_")
        if not all(hasattr(forest, name) for name in required):
            return None
        try:
            from sklearn.ensemble._iforest import _average_path_length
        except ImportError:
            return None

        roots, left, right, features, thresholds, contributions = [], [], [], [], [], []
        offset, maximum_depth = 0, 0
        subsampled = forest._max_features != forest.n_features_in_
        for i, estimator in enumerate(forest.estimators_):
            tree = estimator.tree_
            nodes = np.arange(tree.node_count, dtype=np.intp) + offset
            roots.append(offset)
            left.append(np.where(tree.children_left < 0, nodes, tree.children_left + offset))
            right.append(np.where(tree.children_right < 0, nodes, tree.children_right + offset))
            feature = np.maximum(tree.feature, 0)
            features.append(forest.estimators_features_[i][feature] if subsampled else feature)
            thresholds.append(tree.threshold)
            contributions.append(forest._decision_path_lengths[i] + forest._average_path_length_per_tree[i] - 1.0)
            offset += tree.node_count
            maximum_depth = max(maximum_depth, tree.max_depth)
        if not roots:
            return None
        return cls(np.asarray(roots, dtype=np.intp), np.concatenate(left), np.concatenate(right),
                   np.concatenate(features), np.concatenate(thresholds), np.concatenate(contributions),
                   maximum_depth, len(roots) * _average_path_length([forest._max_samples]))

    def score(self, filled_row):
        # sklearn tree.apply compares float32 inputs against float64 thresholds.
        with np.errstate(over="ignore", invalid="ignore"):
            row = np.asarray(filled_row, dtype=np.float32).reshape(-1)
        if not np.isfinite(row).all():
            return None  # Let sklearn perform its normal input validation.
        nodes = self.roots.copy()
        for _ in range(self.maximum_depth):
            nodes = np.where(row[self.features[nodes]] <= self.thresholds[nodes],
                             self.left[nodes], self.right[nodes])
        # Sequential accumulation preserves sklearn's exact rounding at percentile
        # boundaries. A pairwise np.sum can move a tied score to another percentile.
        depth = np.array([np.cumsum(self.contributions[nodes])[-1]])
        score = 2 ** (-np.divide(depth, self.denominator, out=np.ones_like(depth),
                                where=self.denominator != 0))
        return float(score[0])

    @property
    def nbytes(self):
        return sum(value.nbytes for value in (self.roots, self.left, self.right, self.features,
                                              self.thresholds, self.contributions, self.denominator))
