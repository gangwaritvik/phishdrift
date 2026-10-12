"""Character n-gram TF-IDF of the masked canonical URL + logistic regression.

The vocabulary and IDF weights are fitted on the training rows only (report §9, L10/L15): the
model is a fresh pipeline per split and never sees calibration, test or holdout text in ``fit``.
"""

from __future__ import annotations

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression


class CharNgramLR:
    def __init__(self, params: dict, seed: int):
        self.vectorizer = TfidfVectorizer(
            analyzer="char",
            ngram_range=tuple(params["ngram_range"]),
            min_df=params["min_df"],
            max_features=params["max_features"],
            sublinear_tf=params["sublinear_tf"],
            lowercase=False,  # the canonical URL is already lowercased where it matters (host)
            dtype=np.float32,
        )
        self.model = LogisticRegression(
            C=params["C"], max_iter=params["max_iter"], solver="liblinear", random_state=seed
        )

    def fit(self, texts: list[str], y: np.ndarray, weight: np.ndarray | None = None):
        self.model.fit(self.vectorizer.fit_transform(texts), y, sample_weight=weight)
        return self

    def score(self, texts: list[str]) -> np.ndarray:
        return self.model.predict_proba(self.vectorizer.transform(texts))[:, 1]
