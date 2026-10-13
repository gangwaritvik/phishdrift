"""Hybrid tier A model: LightGBM on the URL features plus text-model scores.

The text models (``models.text_scorers``) read the masked URL, its host, its path or its words
and see patterns the hand-made features miss; LightGBM sees structure they miss. Their scores
enter LightGBM as extra features (log-odds). On the training rows those features are
out-of-fold scores from domain-grouped folds, so LightGBM never learns from a score that saw
its own row's label; at inference they come from text models fitted on all training rows.

``DEFAULT_SCORERS`` is the first version (URL and host character models, 2 extra inputs);
``configs/models.yaml`` ``hybrid2.scorers`` adds path and word models.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from models.gbdt import GBDT
from models.stack import grouped_folds, logit
from models.text_scorers import make_text_model, piece_texts

DEFAULT_SCORERS = (
    {"name": "char_url", "piece": "url", "kind": "char"},
    {"name": "char_host", "piece": "host", "kind": "char"},
)


class HybridA:
    def __init__(
        self,
        gbdt_params: dict,
        char_params: dict,
        columns: list[str],
        n_folds: int,
        seed: int,
        scorers: tuple[dict, ...] | list[dict] = DEFAULT_SCORERS,
    ):
        self.gbdt_params, self.char_params = gbdt_params, char_params
        self.columns, self.n_folds, self.seed = list(columns), n_folds, seed
        self.scorers = list(scorers)

    @property
    def scorer_names(self) -> list[str]:
        return [s["name"] for s in self.scorers]

    def _text_model(self, spec: dict):
        return make_text_model(spec, self.char_params, self.seed)

    def fit(self, train: pd.DataFrame, y: np.ndarray, weight: np.ndarray | None = None) -> HybridA:
        w = np.ones(len(train)) if weight is None else np.asarray(weight)
        folds = grouped_folds(train["domain"], self.n_folds, self.seed)
        extra = {}
        self.models = {}
        for spec in self.scorers:
            t = np.array(piece_texts(train, spec["piece"]), dtype=object)
            oof = np.zeros(len(train))
            for f in range(self.n_folds):
                a, b = folds != f, folds == f
                oof[b] = self._text_model(spec).fit(list(t[a]), y[a], w[a]).score(list(t[b]))
            extra[spec["name"]] = logit(oof)
            self.models[spec["name"]] = self._text_model(spec).fit(list(t), y, w)
        self.oof = extra  # out-of-fold text scores of the training rows (reused by PageModel)
        cols = self.columns + self.scorer_names
        self.gbdt = GBDT("lightgbm", self.gbdt_params, cols, self.seed)
        self.gbdt.fit(train.assign(**extra), y, w)
        return self

    def text_scores(self, frame: pd.DataFrame) -> dict[str, np.ndarray]:
        return {
            spec["name"]: logit(self.models[spec["name"]].score(piece_texts(frame, spec["piece"])))
            for spec in self.scorers
        }

    def score(self, frame: pd.DataFrame) -> np.ndarray:
        return self.gbdt.score(frame.assign(**self.text_scores(frame)))
