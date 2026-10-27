"""Source-adversarial text scorer: hashed character n-grams, a small encoder and two heads.

The label head predicts phishing; a second head tries to predict the data source from the same
encoding, and a gradient-reversal layer pushes the encoder to carry less source information
(domain-adversarial training, Ganin and Lempitsky 2015). ``lam=0`` turns the adversary off and
leaves the same network, so the effect of the adversary is separable from the effect of the net.
Interface matches the other text scorers except that ``fit`` also takes the source of each row.
"""

from __future__ import annotations

import os

import numpy as np

from models import char_cnn


def _hash(texts, params: dict):
    from sklearn.feature_extraction.text import HashingVectorizer

    hv = HashingVectorizer(
        analyzer="char",
        ngram_range=tuple(params["ngram_range"]),
        n_features=params["n_features"],
        alternate_sign=False,
        norm="l2",
        lowercase=False,
    )
    return hv.transform(list(texts)).tocsr()


def _net(params: dict, n_sources: int):
    import torch
    from torch import nn

    class Reverse(torch.autograd.Function):
        @staticmethod
        def forward(ctx, x, lam):
            ctx.lam = lam
            return x.view_as(x)

        @staticmethod
        def backward(ctx, g):
            return -ctx.lam * g, None

    class Net(nn.Module):
        def __init__(self):
            super().__init__()
            d = params["embed_dim"]
            self.bag = nn.EmbeddingBag(params["n_features"], d, mode="sum")
            self.hidden = nn.Linear(d, d)
            self.label = nn.Linear(d, 1)
            self.source = nn.Linear(d, n_sources)

        def encode(self, idx, off, wt):
            return torch.relu(self.hidden(self.bag(idx, off, per_sample_weights=wt)))

        def forward(self, idx, off, wt, lam=0.0):
            z = self.encode(idx, off, wt)
            return self.label(z).squeeze(1), self.source(Reverse.apply(z, lam))

    return Net()


def _batch(x, rows):
    import torch

    sub = x[rows]
    return (
        torch.from_numpy(sub.indices.astype(np.int64)),
        torch.from_numpy(sub.indptr[:-1].astype(np.int64)),
        torch.from_numpy(sub.data.astype(np.float32)),
    )


class AdvText:
    def __init__(self, params: dict, seed: int, lam: float | None = None):
        self.params, self.seed = dict(params), seed
        self.lam = params["lam"] if lam is None else lam
        self.net = None

    def fit(self, texts, y, weight, source) -> AdvText:
        import torch

        p = self.params
        torch.set_num_threads(char_cnn.THREADS if char_cnn.THREADS > 0 else (os.cpu_count() or 1))
        torch.manual_seed(self.seed)
        x = _hash(texts, p)
        y = np.asarray(y, dtype=np.float32)
        w = np.ones(len(y)) if weight is None else np.asarray(weight, dtype=np.float64)
        w = (w / w.mean()).astype(np.float32)
        names = sorted(set(source))
        self.sources = names
        s = np.array([names.index(v) for v in source], dtype=np.int64)
        net = _net(p, len(names))
        opt = torch.optim.Adam(net.parameters(), lr=p["lr"])
        yt, wt, st = torch.from_numpy(y), torch.from_numpy(w), torch.from_numpy(s)
        bce = torch.nn.BCEWithLogitsLoss(reduction="none")
        ce = torch.nn.CrossEntropyLoss(reduction="none")
        steps = p["epochs"] * ((len(y) + p["batch_size"] - 1) // p["batch_size"])
        step = 0
        for epoch in range(p["epochs"]):
            net.train()
            order = np.random.default_rng(self.seed + epoch).permutation(len(y))
            for b in range(0, len(y), p["batch_size"]):
                rows = order[b : b + p["batch_size"]]
                # the reversal strength ramps up over training (as in the original method)
                lam = self.lam * (2 / (1 + np.exp(-10 * step / steps)) - 1)
                out, src = net(*_batch(x, rows), lam=lam)
                r = torch.from_numpy(rows)
                loss = ((bce(out, yt[r]) + p["source_weight"] * ce(src, st[r])) * wt[r]).mean()
                opt.zero_grad()
                loss.backward()
                opt.step()
                step += 1
            if char_cnn.deadline_passed():
                raise char_cnn.TimeLimit("time limit reached in the adversarial scorer")
        self.net = net
        return self

    def _logits(self, texts) -> tuple[np.ndarray, np.ndarray]:
        import torch

        if len(texts) == 0:
            return np.zeros(0), np.zeros((0, len(self.sources)))
        x = _hash(texts, self.params)
        self.net.eval()
        lab, src = [], []
        with torch.no_grad():
            for b in range(0, x.shape[0], 4096):
                o, s = self.net(*_batch(x, np.arange(b, min(b + 4096, x.shape[0]))))
                lab.append(o.numpy())
                src.append(s.numpy())
        return np.concatenate(lab), np.concatenate(src)

    def score(self, texts) -> np.ndarray:
        return 1 / (1 + np.exp(-self._logits(texts)[0]))

    def source_accuracy(self, texts, source) -> float:
        """How well the encoder still tells the sources apart (lower = more source-blind)."""
        names = {n: i for i, n in enumerate(self.sources)}
        keep = np.array([v in names for v in source])
        _, logits = self._logits([t for t, k in zip(texts, keep, strict=True) if k])
        truth = np.array([names[v] for v, k in zip(source, keep, strict=True) if k])
        return float((logits.argmax(1) == truth).mean()) if len(truth) else float("nan")
