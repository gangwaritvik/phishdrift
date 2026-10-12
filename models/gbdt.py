"""Gradient-boosted trees on the tier A feature table (LightGBM and XGBoost).

NaN stays NaN: both libraries learn a direction for missing values, so a missing feature is
never silently turned into 0.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


class GBDT:
    """One booster on a fixed list of feature columns; ``score`` is P(phishing)."""

    def __init__(self, kind: str, params: dict, columns: list[str], seed: int):
        self.kind, self.columns = kind, list(columns)
        params = dict(params)
        if kind == "lightgbm":
            import lightgbm as lgb

            self.model = lgb.LGBMClassifier(**params, random_state=seed, n_jobs=-1, verbose=-1)
        elif kind == "xgboost":
            import xgboost as xgb

            self.model = xgb.XGBClassifier(**params, random_state=seed, n_jobs=-1)
        else:
            raise ValueError(f"unknown booster {kind!r}")

    def _x(self, frame: pd.DataFrame) -> np.ndarray:
        return frame[self.columns].to_numpy(dtype=np.float32)

    def fit(self, frame: pd.DataFrame, y: np.ndarray, weight: np.ndarray | None = None) -> GBDT:
        self.model.fit(self._x(frame), y, sample_weight=weight)
        return self

    def score(self, frame: pd.DataFrame) -> np.ndarray:
        return self.model.predict_proba(self._x(frame))[:, 1]
