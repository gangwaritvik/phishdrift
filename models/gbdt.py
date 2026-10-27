"""Gradient-boosted trees on the tier A feature table (LightGBM, XGBoost, CatBoost).

NaN stays NaN: all three libraries handle missing values themselves, so a missing feature is
never silently turned into 0.
"""

from __future__ import annotations

import os

import numpy as np
import pandas as pd

# Threads per booster: all cores by default; set PHISHDRIFT_THREADS=1 to run several
# experiment processes side by side without oversubscribing the CPUs.
THREADS = int(os.environ.get("PHISHDRIFT_THREADS", "-1"))


class GBDT:
    """One booster on a fixed list of feature columns; ``score`` is P(phishing)."""

    def __init__(self, kind: str, params: dict, columns: list[str], seed: int):
        self.kind, self.columns = kind, list(columns)
        params = dict(params)
        if kind == "lightgbm":
            import lightgbm as lgb

            self.model = lgb.LGBMClassifier(**params, random_state=seed, n_jobs=THREADS, verbose=-1)
        elif kind == "xgboost":
            import xgboost as xgb

            self.model = xgb.XGBClassifier(**params, random_state=seed, n_jobs=THREADS)
        elif kind == "catboost":
            from catboost import CatBoostClassifier

            self.model = CatBoostClassifier(
                **params,
                random_seed=seed,
                thread_count=THREADS,
                verbose=0,
                allow_writing_files=False,
            )
        else:
            raise ValueError(f"unknown booster {kind!r}")

    def _x(self, frame: pd.DataFrame) -> np.ndarray:
        return frame[self.columns].to_numpy(dtype=np.float32)

    def fit(self, frame: pd.DataFrame, y: np.ndarray, weight: np.ndarray | None = None) -> GBDT:
        self.model.fit(self._x(frame), y, sample_weight=weight)
        return self

    def score(self, frame: pd.DataFrame) -> np.ndarray:
        return self.model.predict_proba(self._x(frame))[:, 1]
