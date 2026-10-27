"""Frozen pretrained text embeddings of the host or path words, with a logistic-regression head.

A text scorer for the hybrid tier A model with the same interface as the others
(``fit(texts, y, weight)`` / ``score(texts)``). The pretrained model has seen real words and brand
names, which a scorer trained on our URLs alone has not; only the small head is fitted, on
training rows. Each distinct text is embedded once and cached on disk in shards (resumable, and
the out-of-fold refits reuse them). ``set_deadline`` of ``models.char_cnn`` stops embedding at the
next chunk. The model name ``hash`` is a deterministic offline stand-in for tests and smoke runs.
``sentence-transformers`` is imported on first use, so the rest of the repository does not need it.
"""

from __future__ import annotations

import logging
import os
import re
import time
import zlib
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression

from models import char_cnn

log = logging.getLogger("embed_scorer")
THREADS = int(os.environ.get("PHISHDRIFT_THREADS", "-1"))
HASH_DIM = 64


def words(text: str) -> str:
    """Lowercase alphanumeric tokens joined by spaces: ``A-b.c`` -> ``a b c``."""
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def _hash_vectors(texts: list[str]) -> np.ndarray:
    """Offline stand-in: hashed character trigrams, L2-normalised."""
    out = np.zeros((len(texts), HASH_DIM), dtype=np.float32)
    for i, t in enumerate(texts):
        padded = f"^{t}$"
        for j in range(len(padded) - 2):
            out[i, zlib.crc32(padded[j : j + 3].encode()) % HASH_DIM] += 1.0
    norm = np.linalg.norm(out, axis=1, keepdims=True)
    return out / np.maximum(norm, 1.0)


class Embedder:
    def __init__(
        self,
        name: str,
        cache_dir: Path | str,
        batch_size: int = 256,
        max_len: int = 32,
        chunk: int = 20000,
    ):
        self.name, self.batch_size, self.max_len, self.chunk = name, batch_size, max_len, chunk
        safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", name)
        self.dir = Path(cache_dir) / safe
        self.dir.mkdir(parents=True, exist_ok=True)
        self.model = None
        self.index: dict[str, int] = {}
        self.vectors: list[np.ndarray] = []  # one float16 block per shard
        self._rows: list[tuple[int, int]] = []  # text id -> (block, row)
        for shard in sorted(self.dir.glob("shard_*.npz")):
            with np.load(shard) as z:
                self._add(list(z["texts"]), z["vecs"])

    def _add(self, texts: list[str], vecs: np.ndarray) -> None:
        block = len(self.vectors)
        self.vectors.append(vecs)
        for row, t in enumerate(texts):
            self.index[t] = len(self._rows)
            self._rows.append((block, row))

    def _embed(self, texts: list[str]) -> np.ndarray:
        if self.name == "hash":
            return _hash_vectors(texts)
        if self.model is None:
            import torch
            from sentence_transformers import SentenceTransformer

            torch.set_num_threads(THREADS if THREADS > 0 else (os.cpu_count() or 1))
            self.model = SentenceTransformer(self.name, device="cpu")
            self.model.max_seq_length = self.max_len
        return self.model.encode(
            texts,
            batch_size=self.batch_size,
            show_progress_bar=False,
            convert_to_numpy=True,
            normalize_embeddings=True,
        )

    def encode(self, texts: list[str]) -> np.ndarray:
        """Embeddings (float32) of ``texts``; only texts not yet cached are computed."""
        missing = [t for t in dict.fromkeys(texts) if t not in self.index]
        for start in range(0, len(missing), self.chunk):
            part = missing[start : start + self.chunk]
            t0 = time.monotonic()
            vecs = self._embed(part).astype(np.float16)
            tmp = self.dir / f"shard_{len(self.vectors):06d}.tmp.npz"
            np.savez(tmp, texts=np.array(part, dtype=str), vecs=vecs)
            tmp.replace(self.dir / f"shard_{len(self.vectors):06d}.npz")
            self._add(part, vecs)
            log.info(
                "embedded %d of %d new texts (%.0fs)",
                min(start + self.chunk, len(missing)),
                len(missing),
                time.monotonic() - t0,
            )
            if char_cnn.deadline_passed() and start + self.chunk < len(missing):
                raise char_cnn.TimeLimit("time limit reached while embedding; rerun to continue")
        if not texts:
            return np.zeros((0, 0), dtype=np.float32)
        ids = [self.index[t] for t in texts]
        return np.stack([self.vectors[self._rows[i][0]][self._rows[i][1]] for i in ids]).astype(
            np.float32
        )


class EmbedLR:
    """Logistic regression on the frozen embedding of ``words(text)``."""

    def __init__(self, embedder: Embedder, params: dict, seed: int):
        self.embedder = embedder
        self.model = LogisticRegression(
            C=params.get("C", 1.0), max_iter=params.get("max_iter", 300), random_state=seed
        )

    def _x(self, texts: list[str]) -> np.ndarray:
        return self.embedder.encode([words(t) for t in texts])

    def fit(self, texts: list[str], y: np.ndarray, weight: np.ndarray | None = None) -> EmbedLR:
        self.model.fit(self._x(texts), y, sample_weight=weight)
        return self

    def score(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros(0)
        return self.model.predict_proba(self._x(texts))[:, 1]
