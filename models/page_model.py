"""Page model (tier B) that shares the address model's text scorers.

LightGBM on the 99 tier A features, the 84 tier B page features and the text scores of a fitted
``HybridA`` address model. On the training rows the text scores are that model's out-of-fold
scores (``HybridA.oof``), so the trees never learn from a score that saw its own row's label; at
inference they come from the address model's text scorers fitted on all training rows, exactly
as ``HybridA.score`` does. The browser therefore needs no second set of vocabularies: one bundle
holds the address model and the page model's trees (``models.export_page``).

``experiments.tier_b``'s ``ab_hybrid2`` fits its own scorers on the HTML rows only; this model
fits them on every training row, which is also what the extension can afford to ship.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from features.registry import NAMES, NAMES_B
from models.gbdt import GBDT
from models.hybrid import HybridA


class PageModel:
    def __init__(self, address: HybridA, gbdt_params: dict, seed: int):
        self.address = address
        self.columns = list(NAMES) + list(NAMES_B) + address.scorer_names
        self.gbdt = GBDT("lightgbm", gbdt_params, self.columns, seed)

    def fit(
        self,
        train: pd.DataFrame,
        y: np.ndarray,
        weight: np.ndarray | None,
        rows: np.ndarray,
    ) -> PageModel:
        """Fit on ``train[rows]``; ``train`` is the frame the address model was fitted on."""
        rows = np.asarray(rows, dtype=bool)
        oof = {name: np.asarray(v)[rows] for name, v in self.address.oof.items()}
        w = None if weight is None else np.asarray(weight)[rows]
        self.gbdt.fit(train[rows].assign(**oof), np.asarray(y)[rows], w)
        return self

    def score(self, frame: pd.DataFrame, text: dict | None = None) -> np.ndarray:
        """``text``: the address model's ``text_scores(frame)`` if already computed."""
        text = text if text is not None else self.address.text_scores(frame)
        return self.gbdt.score(frame.assign(**text))
