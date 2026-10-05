"""Bounded streaming statistics used by detectors.

The implementations are deliberately dependency-free.  They are mergeable
where that is useful for window rollups and have fixed memory regardless of
the number of observations.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, field
from typing import Any


class HyperLogLog:
    """A small mergeable HLL-like distinct counter.

    ``precision`` controls memory (``2**precision`` registers).  The estimate
    is intentionally bounded to a non-negative finite value; small-cardinality
    linear counting makes the estimator useful for detector thresholds.
    """

    def __init__(self, precision: int = 10) -> None:
        if not 4 <= precision <= 16:
            raise ValueError("precision must be between 4 and 16")
        self.precision = precision
        self._registers = [0] * (1 << precision)

    @staticmethod
    def _hash(value: Any) -> int:
        return int.from_bytes(hashlib.blake2b(str(value).encode(), digest_size=8).digest(), "big")

    def add(self, value: Any) -> None:
        hashed = self._hash(value)
        index = hashed >> (64 - self.precision)
        remainder = hashed & ((1 << (64 - self.precision)) - 1)
        rank = (64 - self.precision) - remainder.bit_length() + 1
        self._registers[index] = max(self._registers[index], rank)

    def update(self, values: Any) -> None:
        for value in values:
            self.add(value)

    def merge(self, other: HyperLogLog) -> HyperLogLog:
        if self.precision != other.precision:
            raise ValueError("cannot merge HLLs with different precision")
        merged = HyperLogLog(self.precision)
        merged._registers = [
            max(left, right) for left, right in zip(self._registers, other._registers, strict=True)
        ]
        return merged

    def estimate(self) -> float:
        m = len(self._registers)
        alpha = 0.7213 / (1 + 1.079 / m)
        raw = alpha * m * m / sum(2.0**-register for register in self._registers)
        zeros = self._registers.count(0)
        if raw <= 2.5 * m and zeros:
            raw = m * math.log(m / zeros)
        return max(0.0, float(raw))

    def count(self) -> int:
        return round(self.estimate())


class CountMinSketch:
    """Fixed-width, fixed-depth Count-Min Sketch with conservative updates."""

    def __init__(self, width: int = 2048, depth: int = 5) -> None:
        if width < 2 or depth < 1:
            raise ValueError("width must be >= 2 and depth must be >= 1")
        self.width, self.depth = width, depth
        self._table = [[0] * width for _ in range(depth)]

    def _indexes(self, value: Any) -> list[int]:
        raw = str(value).encode()
        return [
            int.from_bytes(
                hashlib.blake2b(raw, digest_size=8, person=i.to_bytes(1, "big")).digest(),
                "big",
            )
            % self.width
            for i in range(self.depth)
        ]

    def add(self, value: Any, count: int = 1) -> None:
        if count < 0:
            raise ValueError("count must be non-negative")
        indexes = self._indexes(value)
        current = min(self._table[row][column] for row, column in enumerate(indexes))
        target = current + count
        for row, column in enumerate(indexes):
            self._table[row][column] = max(self._table[row][column], target)

    def estimate(self, value: Any) -> int:
        return min(self._table[row][column] for row, column in enumerate(self._indexes(value)))

    def merge(self, other: CountMinSketch) -> CountMinSketch:
        if (self.width, self.depth) != (other.width, other.depth):
            raise ValueError("cannot merge sketches with different dimensions")
        merged = CountMinSketch(self.width, self.depth)
        merged._table = [
            [left + right for left, right in zip(left_row, right_row, strict=True)]
            for left_row, right_row in zip(self._table, other._table, strict=True)
        ]
        return merged


@dataclass
class EWMA:
    """Exponentially weighted moving average."""

    alpha: float = 0.2
    value: float | None = None

    def __post_init__(self) -> None:
        if not 0 < self.alpha <= 1:
            raise ValueError("alpha must be in (0, 1]")

    def update(self, observation: float) -> float:
        self.value = (
            observation
            if self.value is None
            else (self.alpha * observation + (1 - self.alpha) * self.value)
        )
        return self.value


@dataclass
class CUSUM:
    """One-sided positive CUSUM shift detector."""

    drift: float = 0.0
    threshold: float = 5.0
    statistic: float = 0.0

    def __post_init__(self) -> None:
        if self.drift < 0 or self.threshold <= 0:
            raise ValueError("drift must be non-negative and threshold positive")

    def update(self, observation: float, baseline: float) -> bool:
        self.statistic = max(0.0, self.statistic + observation - baseline - self.drift)
        if self.statistic >= self.threshold:
            self.statistic = 0.0
            return True
        return False


@dataclass
class EWMACUSUM:
    """Convenience composition for rate baselines and positive shifts."""

    alpha: float = 0.2
    drift: float = 0.0
    threshold: float = 5.0
    ewma: EWMA = field(init=False)
    cusum: CUSUM = field(init=False)

    def __post_init__(self) -> None:
        self.ewma = EWMA(self.alpha)
        self.cusum = CUSUM(self.drift, self.threshold)

    def update(self, observation: float) -> tuple[float, bool]:
        baseline = self.ewma.value if self.ewma.value is not None else observation
        signal = self.cusum.update(observation, baseline)
        return self.ewma.update(observation), signal
