"""Metrics for every reported number: recall at fixed FPR (report §12.3) plus the usual curves.

Operating point: the largest recall whose achieved FPR is at or below the target. It is
reported with the achieved FPR, the threshold, the negative count and 1/n_neg. A point whose
FPR budget allows fewer than ``min_negatives`` false positives (floor(target * n_neg)) rests on
too few negatives and is marked granularity-limited.
"""

from __future__ import annotations

import math

import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score, roc_curve


def fpr_tag(target: float) -> str:
    return f"{target * 100:g}pct".replace(".", "p")  # 0.01 -> 1pct, 0.001 -> 0p1pct


def operating_point(y: np.ndarray, score: np.ndarray, target: float, min_negatives: int) -> dict:
    y = np.asarray(y).astype(int)
    n_neg, n_pos = int((y == 0).sum()), int((y == 1).sum())
    out = {
        "n_neg": n_neg,
        "resolution": 1 / n_neg if n_neg else math.nan,
        "granularity_limited": math.floor(target * n_neg) < min_negatives,
    }
    if n_neg == 0 or n_pos == 0:
        return out | {"recall": math.nan, "achieved_fpr": math.nan, "threshold": math.nan}
    fpr, tpr, thr = roc_curve(y, score, drop_intermediate=False)
    ok = np.flatnonzero(fpr <= target)
    best = ok[np.argmax(tpr[ok])]  # fpr[0] == 0 always, so ok is never empty
    threshold = float(min(thr[best], np.finfo(np.float64).max))  # roc_curve's first thr is inf
    return out | {
        "recall": float(tpr[best]),
        "achieved_fpr": float(fpr[best]),
        "threshold": threshold,
    }


def at_threshold(y: np.ndarray, score: np.ndarray, threshold: float) -> dict:
    """Recall, FPR, precision and F1 when ``score >= threshold`` is called phishing."""
    y = np.asarray(y).astype(int)
    pred = np.asarray(score) >= threshold
    tp = int((pred & (y == 1)).sum())
    fp = int((pred & (y == 0)).sum())
    n_pos, n_neg = int((y == 1).sum()), int((y == 0).sum())
    recall = tp / n_pos if n_pos else math.nan
    precision = tp / (tp + fp) if tp + fp else math.nan
    f1 = 2 * precision * recall / (precision + recall) if tp else 0.0
    return {
        "recall": recall,
        "fpr": fp / n_neg if n_neg else math.nan,
        "precision": precision,
        "f1": f1,
    }


def curve_metrics(y: np.ndarray, score: np.ndarray) -> dict:
    y = np.asarray(y).astype(int)
    if len(np.unique(y)) < 2:
        return {"roc_auc": math.nan, "pr_auc": math.nan}
    return {"roc_auc": roc_auc_score(y, score), "pr_auc": average_precision_score(y, score)}


def evaluate(
    y: np.ndarray,
    score: np.ndarray,
    targets: list[float],
    min_negatives: int,
    cal_thresholds: dict[float, float] | None = None,
) -> dict:
    """Every metric for one scored set, flattened into one row.

    ``op_<tag>_*`` is the operating point measured on this set itself. ``cal_<tag>_*`` applies
    the threshold chosen on the calibration slice, which is what a deployed model would do.
    """
    y = np.asarray(y).astype(int)
    row: dict = {"n_urls": len(y), "n_pos": int(y.sum()), "n_neg": int((y == 0).sum())}
    row |= curve_metrics(y, score)
    for t in targets:
        tag = fpr_tag(t)
        op = operating_point(y, score, t, min_negatives)
        row |= {f"op_{tag}_{k}": v for k, v in op.items() if k != "n_neg"}
        if cal_thresholds is not None and t in cal_thresholds:
            res = at_threshold(y, score, cal_thresholds[t])
            row |= {f"cal_{tag}_{k}": v for k, v in res.items()}
    return row
