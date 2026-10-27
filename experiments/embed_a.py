"""One-split test of pretrained text embeddings (host and path words) as extra hybrid scorers.

python -m experiments.embed_a [--processed data/processed] [--reports reports/embed_split0]
                              [--max-hours 3] [--smoke 2000] [--embedder hash]

Same domain-grouped split, fitted features and metrics as ``experiments.hybrid_a`` and
``experiments.char_cnn_a``; nothing shipped is changed and nothing is tuned on test. Two stages
(a finished stage is skipped on a rerun; embeddings are cached on disk and resume):

1. ``alone``: the embedding scorers against the character n-gram scorer on the same piece, a
   shuffled-label control, and a ``test:depth0`` set (bare domains, where today's model is weakest).
2. ``hybrid``: today's hybrid2 against the same model with ``embed_host`` and ``embed_path`` as two
   more out-of-fold scorers.

``SUMMARY.md`` is built only from the tables. The 2-point bar is a proposal, not an agreed rule.
"""

from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

import numpy as np
import pandas as pd

from experiments.char_cnn_a import _get, _rows, _table, _thresholds, build_ctx
from experiments.hybrid_a import make_hybrid
from experiments.metrics import evaluate
from features.lists import Lists, load_lists
from models import char_cnn
from models.embed_scorer import Embedder, EmbedLR
from models.hybrid import HybridA
from models.text_scorers import make_text_model, piece_texts
from phishdrift.config import load_config

log = logging.getLogger("embed_a")
SPECS = (
    {"name": "embed_host", "piece": "host", "kind": "embed"},
    {"name": "embed_path", "piece": "path", "kind": "embed"},
)


class HybridEmbed(HybridA):
    """HybridA that also builds the ``embed`` scorer kind (no change to the shipped class)."""

    embedder: Embedder | None = None
    embed_params: dict = {}

    def _text_model(self, spec: dict):
        if spec["kind"] == "embed":
            return EmbedLR(self.embedder, self.embed_params, self.seed)
        return super()._text_model(spec)


def stage_alone(ctx: dict) -> None:
    out = ctx["tables"] / "alone_runs.csv"
    if out.exists():
        return
    cfg, train, cal, test = ctx["cfg"], ctx["train"], ctx["cal"], ctx["test"]
    targets, min_neg = ctx["targets"], ctx["min_neg"]
    y, w = train["label"].to_numpy(), train["weight"].to_numpy()
    rows, models, control = [], {}, None
    for spec in SPECS:
        piece = spec["piece"]
        char_spec = next(
            (s for s in cfg["hybrid2"]["scorers"] if s["piece"] == piece and s["kind"] == "char"),
            None,
        )
        texts = piece_texts(train, piece)
        models[spec["name"]] = (
            piece,
            EmbedLR(ctx["embedder"], ctx["embed"], cfg["seed"]).fit(texts, y, w),
        )
        if char_spec is not None:
            ngram = make_text_model(char_spec, cfg["char_ngram"], cfg["seed"]).fit(texts, y, w)
            models[f"{char_spec['name']}_lr"] = (piece, ngram)
        if control is None:  # shuffled-label control, unweighted like experiments.tier_a
            shuffled = np.random.default_rng(cfg["seed"] + ctx["k"]).permutation(y)
            m = EmbedLR(ctx["embedder"], ctx["embed"], cfg["seed"]).fit(texts, shuffled)
            r = evaluate(test["label"], m.score(piece_texts(test, piece)), targets, min_neg)
            control = pd.DataFrame([{"split": ctx["k"], "model": spec["name"]} | r])
    for name, (piece, model) in models.items():
        thr = _thresholds(cal["label"], model.score(piece_texts(cal, piece)), targets, min_neg)
        rows += _rows(
            {"split": ctx["k"], "model": name},
            ctx["sets"],
            lambda f, m=model, p=piece: m.score(piece_texts(f, p)),
            targets,
            min_neg,
            thr,
        )
    control.to_csv(ctx["tables"] / "control.csv", index=False)
    pd.DataFrame(rows).to_csv(out, index=False)
    log.info("stage alone done")


def stage_hybrid(ctx: dict) -> None:
    out = ctx["tables"] / "hybrid_runs.csv"
    if out.exists():
        return
    cfg, train, cal = ctx["cfg"], ctx["train"], ctx["cal"]
    targets, min_neg = ctx["targets"], ctx["min_neg"]
    y, w = train["label"].to_numpy(), train["weight"].to_numpy()
    base_model = make_hybrid(cfg, "hybrid2")
    embed_model = HybridEmbed(
        cfg["lightgbm"],
        cfg["char_ngram"],
        base_model.columns,
        cfg["stack"]["n_folds"],
        cfg["seed"],
        scorers=[*cfg["hybrid2"]["scorers"], *SPECS],
    )
    embed_model.embedder, embed_model.embed_params = ctx["embedder"], ctx["embed"]
    rows = []
    for name, model in (("hybrid2", base_model), ("hybrid2+embed", embed_model)):
        t0 = time.monotonic()
        model.fit(train, y, w)
        thr = _thresholds(cal["label"], model.score(cal), targets, min_neg)
        rows += _rows(
            {"split": ctx["k"], "model": name}, ctx["sets_f"], model.score, targets, min_neg, thr
        )
        log.info("%s fitted and scored (%.0fs)", name, time.monotonic() - t0)
    pd.DataFrame(rows).to_csv(out, index=False)
    log.info("stage hybrid done")


def _depth0_line(runs: pd.DataFrame, ref: str, new: str, bar: float) -> list[str]:
    d = 100 * (
        _get(runs, new, "test:depth0", "op_1pct_recall")
        - _get(runs, ref, "test:depth0", "op_1pct_recall")
    )
    if np.isnan(d):
        return []
    verdict = "above the bar" if d > bar else ("worse" if d < -bar else "within the spread")
    return [f"- test:depth0 (bare domains): {d:+.1f} points ({verdict})", ""]


def render(ctx: dict) -> str:
    cfg, bar, tables = ctx["cfg"], ctx["bar"], ctx["tables"]
    lines = [
        f"# Pretrained text embeddings, split {ctx['k']}",
        "",
        "Generated by `python -m experiments.embed_a`. Do not edit by hand. One split only,",
        "so the 2-point bar (a proposal, not yet approved) stands in for the split spread.",
        f"Embedder: `{ctx['embedder'].name}` (frozen); settings `configs/embed.yaml`; "
        f"seed {cfg['seed']}.",
        "",
    ]
    flag = cfg["eval"]["shuffled_label_flag"]
    if (tables / "alone_runs.csv").exists():
        runs = pd.read_csv(tables / "alone_runs.csv")
        lines += ["## Embedding scorers against the n-gram scorer on the same piece", ""]
        lines += _table(
            runs, list(runs["model"].drop_duplicates()), bar, "char_host_lr", "embed_host"
        )
        lines += _depth0_line(runs, "char_host_lr", "embed_host", bar)
        c = pd.read_csv(tables / "control.csv")
        auc = float(c["roc_auc"].iloc[0])
        lines += [
            f"Shuffled-label control (embed_host, test ROC-AUC): {auc:.4f} "
            f"({'FLAGGED' if abs(auc - 0.5) > flag else 'not flagged'}, limit {flag}).",
            "",
        ]
    if (tables / "hybrid_runs.csv").exists():
        runs = pd.read_csv(tables / "hybrid_runs.csv")
        lines += ["## Hybrid with and without the embedding scorers", ""]
        lines += _table(runs, ["hybrid2", "hybrid2+embed"], bar, "hybrid2", "hybrid2+embed")
        lines += _depth0_line(runs, "hybrid2", "hybrid2+embed", bar)
        lines += ["Shuffled-label control for the hybrid was not run in this first test.", ""]
    trip = cfg["eval"]["leakage_tripwire"]
    hot = []
    for f in ("alone_runs.csv", "hybrid_runs.csv"):
        if (tables / f).exists():
            r = pd.read_csv(tables / f)
            r = r[r["eval_set"].isin(["heldout_source", "time_slice"])]
            hot += list(r[(r["roc_auc"] > trip) | (r["op_1pct_recall"] > trip)]["model"].unique())
    lines.append(
        f"**Leakage tripwire:** {sorted(set(hot))} above {trip:.0%} on a held-out set; investigate."
        if hot
        else f"Leakage tripwire (held-out source or time slice above {trip:.0%}): not triggered."
    )
    lines += ["", "`*` = the 0.1% point rests on fewer than 10 negatives.", ""]
    return "\n".join(lines)


def run(args, cfg: dict | None = None, lists: Lists | None = None) -> int:
    cfg = cfg or load_config("models")
    cc = load_config("embed")
    lists = lists or load_lists(args.lists_dir, args.platforms_file)
    char_cnn.set_deadline(args.max_hours)
    ctx = build_ctx(args, cfg, lists, cc)
    ctx["embed"] = cc["embed"]
    ctx["embedder"] = Embedder(
        args.embedder or cc["embed"]["model"],
        args.cache_dir,
        cc["embed"]["batch_size"],
        cc["embed"]["max_len"],
        cc["embed"]["chunk"],
    )
    test = ctx["test"]
    if (test["depth"] == 0).any():  # same dict as ctx["sets"]
        ctx["sets_f"]["test:depth0"] = test[test["depth"] == 0]
    status = 0
    try:
        stage_alone(ctx)
        stage_hybrid(ctx)
    except char_cnn.TimeLimit as e:
        log.warning("%s", e)
        status = 3
    (args.reports / "SUMMARY.md").write_text(render(ctx), encoding="utf-8")
    print((args.reports / "SUMMARY.md").read_text(encoding="utf-8"))
    return status


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.embed_a")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--reports", type=Path, default=Path("reports/embed_split0"))
    ap.add_argument("--cache-dir", type=Path, default=Path("data/interim/embeddings"))
    ap.add_argument("--split", type=int, default=None)
    ap.add_argument("--max-hours", type=float, default=3.0)
    ap.add_argument("--smoke", type=int, default=0, help="rows of train for a tiny test run")
    ap.add_argument(
        "--embedder", default=None, help="override the model name; 'hash' = offline stand-in"
    )
    ap.add_argument("--lists-dir", default=None)
    ap.add_argument("--platforms-file", default=None)
    a = ap.parse_args(argv)
    a.reports.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(a.reports / "run.log", encoding="utf-8"),
        ],
    )
    return run(a)


if __name__ == "__main__":
    raise SystemExit(main())
