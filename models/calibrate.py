"""Isotonic calibration and the two verdict thresholds.

Thresholds are chosen on the raw stacked score of the calibration slice (strictly ordered, so
the FPR targets can be hit as closely as the slice allows): "suspicious" at FPR 1%, "dangerous"
at FPR 0.1%. The isotonic map turns a raw score into a probability for display and for the
runtime combiner; it never moves the thresholds.
"""

from __future__ import annotations

import numpy as np
from sklearn.isotonic import IsotonicRegression

from experiments.metrics import operating_point


class Calibrator:
    def __init__(self, targets: dict[str, float], min_negatives: int):
        self.targets, self.min_negatives = targets, min_negatives

    def fit(self, y: np.ndarray, raw: np.ndarray) -> Calibrator:
        self.iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
        self.iso.fit(raw, y)
        self.points = {
            name: operating_point(y, raw, fpr, self.min_negatives)
            for name, fpr in self.targets.items()
        }
        self.thresholds = {name: p["threshold"] for name, p in self.points.items()}
        return self

    def probability(self, raw: np.ndarray) -> np.ndarray:
        return self.iso.predict(raw)

    def verdict(self, raw: np.ndarray) -> np.ndarray:
        """0 = safe, 1 = suspicious, 2 = dangerous."""
        out = np.zeros(len(raw), dtype=int)
        out[raw >= self.thresholds["suspicious"]] = 1
        out[raw >= self.thresholds["dangerous"]] = 2
        return out


def brier(y: np.ndarray, p: np.ndarray) -> float:
    return float(np.mean((np.asarray(p) - np.asarray(y)) ** 2))


def expected_calibration_error(y: np.ndarray, p: np.ndarray, bins: int = 10) -> float:
    y, p = np.asarray(y, dtype=float), np.asarray(p, dtype=float)
    edges = np.linspace(0, 1, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    err = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            err += m.mean() * abs(y[m].mean() - p[m].mean())
    return float(err)
