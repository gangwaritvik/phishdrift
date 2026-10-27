"""Character CNN on the masked canonical URL (a deep text scorer for the hybrid tier A model).

Same interface as the other text scorers (``fit(texts, y, weight)`` / ``score(texts)``), so it can
be an extra out-of-fold input of ``models.hybrid.HybridA`` or be evaluated on its own.
Architecture: character embedding, parallel 1-D convolutions of several widths, global max pool,
one dense layer. Training is resumable: a checkpoint is written after every epoch under
``cache_dir`` (named by a hash of the training data and settings), and a finished model is loaded
instead of retrained. ``set_deadline`` stops training cleanly at the next epoch end.
PyTorch is imported on first use, so the rest of the repository does not need it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path

import numpy as np

log = logging.getLogger("char_cnn")
THREADS = int(os.environ.get("PHISHDRIFT_THREADS", "-1"))
_deadline: float | None = None  # time.monotonic() value after which training stops


class TimeLimit(RuntimeError):
    """Raised at an epoch end after the deadline; the checkpoint is saved, rerun to continue."""


def set_deadline(hours: float | None) -> None:
    global _deadline
    _deadline = None if hours is None else time.monotonic() + hours * 3600


# printable ASCII 32..126 -> ids 1..95, anything else -> 96, padding 0
VOCAB = 97


def encode(texts: list[str], max_len: int) -> np.ndarray:
    out = np.zeros((len(texts), max_len), dtype=np.int64)
    for i, t in enumerate(texts):
        codes = [c - 31 if 32 <= c <= 126 else 96 for c in t[:max_len].encode("utf-8", "replace")]
        out[i, : len(codes)] = codes
    return out


def _net(params: dict):
    import torch
    from torch import nn

    class Net(nn.Module):
        def __init__(self):
            super().__init__()
            d, f = params["embed_dim"], params["filters"]
            self.embed = nn.Embedding(VOCAB, d, padding_idx=0)
            self.convs = nn.ModuleList(nn.Conv1d(d, f, w, padding=w // 2) for w in params["widths"])
            self.drop = nn.Dropout(params["dropout"])
            self.dense = nn.Linear(f * len(params["widths"]), params["hidden"])
            self.out = nn.Linear(params["hidden"], 1)

        def forward(self, x):
            h = self.embed(x).transpose(1, 2)
            pooled = [torch.relu(c(h)).amax(dim=2) for c in self.convs]
            z = self.drop(torch.relu(self.dense(torch.cat(pooled, dim=1))))
            return self.out(z).squeeze(1)

    return Net()


class CharCNN:
    def __init__(self, params: dict, seed: int, cache_dir: Path | str | None = None):
        self.params, self.seed = dict(params), seed
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.net = None

    def _key(self, x: np.ndarray, y: np.ndarray, w: np.ndarray) -> str:
        h = hashlib.sha1(json.dumps(self.params, sort_keys=True).encode())
        for a in (x, y.astype(np.int8), np.round(w, 4)):
            h.update(np.ascontiguousarray(a).tobytes())
        return h.hexdigest()[:16] + f"_s{self.seed}"

    def fit(self, texts, y, weight=None, watch=None):
        """Train on ``texts``. ``watch`` = (texts, y) is only scored each epoch for the log."""
        import torch
        from sklearn.metrics import roc_auc_score

        p = self.params
        torch.set_num_threads(THREADS if THREADS > 0 else (os.cpu_count() or 1))
        torch.manual_seed(self.seed)
        x = encode(list(texts), p["max_len"])
        y = np.asarray(y, dtype=np.float32)
        w = np.ones(len(y)) if weight is None else np.asarray(weight, dtype=np.float64)
        w = (w / w.mean()).astype(np.float32)  # mean 1 so the learning rate does not depend on it
        net = _net(p)
        opt = torch.optim.Adam(net.parameters(), lr=p["lr"])
        ckpt = None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            ckpt = self.cache_dir / f"{self._key(x, y, w)}.pt"
        start = 0
        if ckpt is not None and ckpt.exists():
            state = torch.load(ckpt, map_location="cpu")
            net.load_state_dict(state["model"])
            opt.load_state_dict(state["opt"])
            start = state["epoch"]
            log.info("resumed %s at epoch %d of %d", ckpt.name, start, p["epochs"])
        xt, yt, wt = torch.from_numpy(x), torch.from_numpy(y), torch.from_numpy(w)
        loss_fn = torch.nn.BCEWithLogitsLoss(reduction="none")
        for epoch in range(start, p["epochs"]):
            t0 = time.monotonic()
            net.train()
            order = torch.from_numpy(np.random.default_rng(self.seed + epoch).permutation(len(y)))
            total, n_batches = 0.0, 0
            for b in range(0, len(y), p["batch_size"]):
                idx = order[b : b + p["batch_size"]]
                loss = (loss_fn(net(xt[idx]), yt[idx]) * wt[idx]).mean()
                opt.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(net.parameters(), 1.0)
                opt.step()
                total, n_batches = total + loss.item(), n_batches + 1
                if n_batches % 200 == 0:
                    log.info("epoch %d batch %d loss %.4f", epoch + 1, n_batches, total / n_batches)
            self.net = net
            msg = f"epoch {epoch + 1}/{p['epochs']} loss {total / n_batches:.4f}"
            if watch is not None:
                msg += f" watch ROC-AUC {roc_auc_score(watch[1], self.score(watch[0])):.4f}"
            log.info("%s (%.0fs)", msg, time.monotonic() - t0)
            if ckpt is not None:
                tmp = ckpt.with_suffix(".tmp")
                torch.save(
                    {"epoch": epoch + 1, "model": net.state_dict(), "opt": opt.state_dict()}, tmp
                )
                tmp.replace(ckpt)
            if _deadline is not None and time.monotonic() > _deadline and epoch + 1 < p["epochs"]:
                raise TimeLimit(f"time limit reached after epoch {epoch + 1}; rerun to continue")
        self.net = net
        return self

    def score(self, texts) -> np.ndarray:
        import torch

        self.net.eval()
        x = torch.from_numpy(encode(list(texts), self.params["max_len"]))
        out = []
        with torch.no_grad():
            for b in range(0, len(x), 2048):
                out.append(torch.sigmoid(self.net(x[b : b + 2048])).numpy())
        return np.concatenate(out) if out else np.zeros(0)
