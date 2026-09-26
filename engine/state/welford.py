from __future__ import annotations

import math


class Moments:
    __slots__ = ("n", "mean", "_m2", "_m3", "_m4", "minimum", "maximum")

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.n = 0
        self.mean = 0.0
        self._m2 = 0.0
        self._m3 = 0.0
        self._m4 = 0.0
        self.minimum = math.inf
        self.maximum = -math.inf

    def add(self, x: float) -> None:
        x = float(x)
        n1 = self.n
        self.n = n = n1 + 1
        delta = x - self.mean
        dn = delta / n
        dn2 = dn * dn
        term = delta * dn * n1
        self.mean += dn
        self._m4 += term * dn2 * (n * n - 3 * n + 3) + 6.0 * dn2 * self._m2 - 4.0 * dn * self._m3
        self._m3 += term * dn * (n - 2) - 3.0 * dn * self._m2
        self._m2 += term
        if x < self.minimum:
            self.minimum = x
        if x > self.maximum:
            self.maximum = x

    @property
    def var(self) -> float:
        return self._m2 / self.n if self.n > 0 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.var)

    @property
    def cv(self) -> float:
        return self.std / abs(self.mean) if self.n > 0 and self.mean != 0.0 else 0.0

    @property
    def skew(self) -> float:
        if self.n < 2 or self._m2 <= 0.0:
            return 0.0
        return math.sqrt(self.n) * self._m3 / self._m2 ** 1.5

    @property
    def kurtosis(self) -> float:
        if self.n < 2 or self._m2 <= 0.0:
            return 0.0
        return self.n * self._m4 / (self._m2 * self._m2) - 3.0
