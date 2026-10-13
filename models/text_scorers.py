"""Text models on one piece of the URL, used as extra inputs of the hybrid tier A model.

A scorer spec is ``{"name", "piece", "kind", "params"}``. ``piece`` is the part of the masked
URL the model reads (``url`` = canonical masked URL, ``host``, ``domain`` = registrable domain,
``path`` = path plus ``?query``); ``kind`` is ``char`` (character n-gram TF-IDF + logistic
regression, ``models.char_ngram``) or ``word`` (TF-IDF of lowercase alphanumeric tokens and token
pairs + logistic regression). Vocabulary, IDF and weights are fitted on training rows only.
``js/src/chargram.js`` scores both kinds in the browser.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from models.char_ngram import CharNgramLR

PIECES = {
    "url": lambda p: p.canon,
    "host": lambda p: p.host,
    "domain": lambda p: p.domain,
    "path": lambda p: p.path + ("?" + p.query if p.query else ""),
}
WORD_TOKEN = r"[a-z0-9]+"
WORD_NGRAMS = (1, 2)


class WordLR:
    """TF-IDF of lowercase alphanumeric tokens (1-2 grams) + logistic regression."""

    def __init__(self, params: dict, seed: int):
        self.vectorizer = TfidfVectorizer(
            token_pattern=WORD_TOKEN,
            ngram_range=WORD_NGRAMS,
            min_df=params["min_df"],
            max_features=params.get("max_features"),
            sublinear_tf=True,
            dtype=np.float32,
        )
        self.model = LogisticRegression(
            C=params["C"],
            max_iter=params.get("max_iter", 1000),
            solver="liblinear",
            random_state=seed,
        )

    def fit(self, texts: list[str], y: np.ndarray, weight: np.ndarray | None = None):
        self.model.fit(self.vectorizer.fit_transform(texts), y, sample_weight=weight)
        return self

    def score(self, texts: list[str]) -> np.ndarray:
        return self.model.predict_proba(self.vectorizer.transform(texts))[:, 1]


def make_text_model(spec: dict, base_char: dict, seed: int):
    """Unfitted model for a scorer spec; ``base_char`` is config's ``char_ngram`` block."""
    params = spec.get("params") or {}
    if spec["kind"] == "char":
        return CharNgramLR({**base_char, **params}, seed)
    if spec["kind"] == "word":
        return WordLR(params, seed)
    raise ValueError(f"unknown scorer kind {spec['kind']!r}")


def piece_texts(frame: pd.DataFrame, piece: str) -> list[str]:
    get = PIECES[piece]
    return [get(p) if p is not None else "" for p in frame["_parts"]]
