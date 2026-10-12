"""Stacked tier A model: out-of-fold base-learner scores feed a logistic-regression meta model.

The base learners' out-of-fold scores come from domain-grouped folds of the training rows, so
the meta model only ever sees scores for URLs whose domain the base model did not train on
(the situation at inference). The two fitted tier A features (``tld_risk``,
``bigram_loglik_domain``) are refitted inside every fold for the same reason.
"""

from __future__ import annotations

from collections.abc import Callable

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

EPS = 1e-6


def grouped_folds(domains: pd.Series, n_folds: int, seed: int) -> np.ndarray:
    """Fold id per row; all rows of a registrable domain share one fold."""
    uniq = domains.unique()
    rng = np.random.default_rng(seed)
    fold_of = dict(zip(uniq, rng.integers(0, n_folds, len(uniq)), strict=True))
    return domains.map(fold_of).to_numpy()


def logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(p, EPS, 1 - EPS)
    return np.log(p / (1 - p))


class Stack:
    """``bases`` maps a name to a factory returning an unfitted model with fit/score;
    ``inputs`` maps the name to a function turning a frame into that model's input;
    ``refit`` re-derives the fitted features of frames from a training frame."""

    def __init__(
        self,
        bases: dict[str, Callable[[], object]],
        inputs: dict[str, Callable[[pd.DataFrame], object]],
        refit: Callable[[pd.DataFrame, list[pd.DataFrame]], list[pd.DataFrame]],
        n_folds: int,
        seed: int,
        meta_c: float = 1.0,
    ):
        self.bases, self.inputs, self.refit = bases, inputs, refit
        self.n_folds, self.seed, self.meta_c = n_folds, seed, meta_c

    def _scores(self, models: dict, frame: pd.DataFrame) -> np.ndarray:
        cols = [logit(models[n].score(self.inputs[n](frame))) for n in self.bases]
        return np.column_stack(cols)

    def fit(self, train: pd.DataFrame, weight: np.ndarray | None = None) -> Stack:
        y = train["label"].to_numpy()
        w = np.ones(len(train)) if weight is None else np.asarray(weight)
        folds = grouped_folds(train["domain"], self.n_folds, self.seed)
        oof = np.zeros((len(train), len(self.bases)))
        for f in range(self.n_folds):
            inner, outer = train[folds != f], train[folds == f]
            inner, outer = self.refit(inner, [inner, outer])
            models = {
                n: make().fit(self.inputs[n](inner), inner["label"].to_numpy(), w[folds != f])
                for n, make in self.bases.items()
            }
            oof[folds == f] = self._scores(models, outer)
        self.meta = LogisticRegression(C=self.meta_c, max_iter=1000)
        self.meta.fit(oof, y, sample_weight=w)
        (full,) = self.refit(train, [train])
        self.models = {n: make().fit(self.inputs[n](full), y, w) for n, make in self.bases.items()}
        self.oof_ = oof
        return self

    def score(self, frame: pd.DataFrame) -> np.ndarray:
        """``frame`` must already carry fitted features derived from the full training rows."""
        return self.meta.predict_proba(self._scores(self.models, frame))[:, 1]

    @property
    def meta_weights(self) -> dict[str, float]:
        coef = dict(zip(self.bases, self.meta.coef_[0], strict=True))
        return coef | {"intercept": float(self.meta.intercept_[0])}
