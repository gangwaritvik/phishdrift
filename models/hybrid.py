"""Hybrid tier A model: LightGBM on the URL features plus two char n-gram scores.

The char n-gram models (one on the masked URL, one on the host alone) see letter patterns the
hand-made features miss; LightGBM sees structure the n-grams miss. Their scores enter
LightGBM as two extra features (log-odds). On the training rows those features are
out-of-fold scores from domain-grouped folds, so LightGBM never learns from a score that saw
its own row's label; at inference they come from char models fitted on all training rows.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from models.char_ngram import CharNgramLR
from models.gbdt import GBDT
from models.stack import grouped_folds, logit

TEXTS = {"char_url": "_text", "char_host": "_host"}


def host_texts(frame: pd.DataFrame) -> list[str]:
    return [p.host if p is not None else "" for p in frame["_parts"]]


def texts(frame: pd.DataFrame, name: str) -> list[str]:
    return host_texts(frame) if TEXTS[name] == "_host" else frame["_text"].tolist()


class HybridA:
    def __init__(
        self, gbdt_params: dict, char_params: dict, columns: list[str], n_folds: int, seed: int
    ):
        self.gbdt_params, self.char_params = gbdt_params, char_params
        self.columns, self.n_folds, self.seed = list(columns), n_folds, seed

    def _char(self) -> CharNgramLR:
        return CharNgramLR(self.char_params, self.seed)

    def fit(self, train: pd.DataFrame, y: np.ndarray, weight: np.ndarray | None = None) -> HybridA:
        w = np.ones(len(train)) if weight is None else np.asarray(weight)
        folds = grouped_folds(train["domain"], self.n_folds, self.seed)
        extra = {}
        self.chars = {}
        for name in TEXTS:
            t = np.array(texts(train, name), dtype=object)
            oof = np.zeros(len(train))
            for f in range(self.n_folds):
                a, b = folds != f, folds == f
                oof[b] = self._char().fit(list(t[a]), y[a], w[a]).score(list(t[b]))
            extra[name] = logit(oof)
            self.chars[name] = self._char().fit(list(t), y, w)
        cols = self.columns + list(TEXTS)
        self.gbdt = GBDT("lightgbm", self.gbdt_params, cols, self.seed)
        self.gbdt.fit(train.assign(**extra), y, w)
        return self

    def char_scores(self, frame: pd.DataFrame) -> dict[str, np.ndarray]:
        return {n: logit(m.score(texts(frame, n))) for n, m in self.chars.items()}

    def score(self, frame: pd.DataFrame) -> np.ndarray:
        return self.gbdt.score(frame.assign(**self.char_scores(frame)))
