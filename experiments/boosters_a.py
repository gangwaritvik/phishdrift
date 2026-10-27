"""One-split test of other boosters and of a source-adversarial text scorer for the tier A hybrid.

python -m experiments.boosters_a [--processed data/processed] [--reports reports/boosters_split0]
                                 [--max-hours 3] [--smoke 2000]

Same domain-grouped split, fitted features and metrics as ``experiments.hybrid_a``; nothing shipped
changes and nothing is tuned on test. One pass of out-of-fold text scores feeds every final model:

- ``lightgbm`` (today's hybrid2), ``catboost``, ``xgboost`` and ``avg_lgbm_cat`` (mean log-odds)
  on the same inputs;
- ``lightgbm+adv`` (a source-adversarial scorer on the URL as an extra input) and
  ``lightgbm+plain`` (the same network with the adversary off, so the adversary's own effect shows).

``alone`` also compares the two networks and the n-gram model on the URL by themselves, with the
share of rows whose source the network can still tell. ``SUMMARY.md`` is built from the tables only.
The 2-point bar is a proposal, not an agreed rule.
"""

from __future__ import annotations

import argparse
import logging
import math
import time
from pathlib import Path

import numpy as np
import pandas as pd

from experiments.char_cnn_a import _get, _rows, _table, _thresholds, build_ctx
from experiments.hybrid_a import make_hybrid
from features.lists import Lists, load_lists
from models import char_cnn
from models.adv_text import AdvText
from models.gbdt import GBDT
from models.hybrid import HybridA
from models.stack import logit
from models.text_scorers import make_text_model, piece_texts
from phishdrift.config import load_config

log = logging.getLogger("boosters_a")
ADV_SPECS = (
    {"name": "adv_url", "piece": "url", "kind": "adv", "lam": None},
    {"name": "plain_url", "piece": "url", "kind": "adv", "lam": 0.0},
)


class HybridMulti(HybridA):
    """HybridA with one pass of out-of-fold scores and several final models on top of it."""

    adv_params: dict = {}

    def fit(self, train: pd.DataFrame, y: np.ndarray, weight: np.ndarray | None = None):
        from models.stack import grouped_folds

        w = np.ones(len(train)) if weight is None else np.asarray(weight)
        folds = grouped_folds(train["domain"], self.n_folds, self.seed)
        src = train["source"].to_numpy()
        self.models, self.extra, self.finals = {}, {}, {}
        for spec in self.scorers:
            t = np.array(piece_texts(train, spec["piece"]), dtype=object)
            oof = np.zeros(len(train))
            for f in range(self.n_folds):
                a, b = folds != f, folds == f
                oof[b] = self._fit_one(spec, t[a], y[a], w[a], src[a]).score(list(t[b]))
            self.extra[spec["name"]] = logit(oof)
            self.models[spec["name"]] = self._fit_one(spec, t, y, w, src)
        self.train, self.y, self.w = train.assign(**self.extra), y, w
        return self

    def _fit_one(self, spec, texts, y, w, src):
        if spec["kind"] == "adv":
            return AdvText(self.adv_params, self.seed, spec["lam"]).fit(list(texts), y, w, src)
        return self._text_model(spec).fit(list(texts), y, w)

    def add_final(self, name: str, kind: str, params: dict, scorers: list[str]) -> None:
        gb = GBDT(kind, params, self.columns + scorers, self.seed)
        self.finals[name] = (gb, scorers)
        gb.fit(self.train, self.y, self.w)

    def scores(self, name: str, frame: pd.DataFrame) -> np.ndarray:
        gb, names = self.finals[name]
        have = {
            n: logit(self.models[n].score(piece_texts(frame, s["piece"])))
            for s in self.scorers
            if (n := s["name"]) in names
        }
        return gb.score(frame.assign(**have))


def stage_alone(ctx: dict) -> None:
    out = ctx["tables"] / "alone_runs.csv"
    if out.exists():
        return
    cfg, train, cal, test = ctx["cfg"], ctx["train"], ctx["cal"], ctx["test"]
    targets, min_neg = ctx["targets"], ctx["min_neg"]
    y, w = train["label"].to_numpy(), train["weight"].to_numpy()
    texts = piece_texts(train, "url")
    models = {
        "char_url_lr": make_text_model(
            cfg["hybrid2"]["scorers"][0], cfg["char_ngram"], cfg["seed"]
        ).fit(texts, y, w)
    }
    for spec in ADV_SPECS:
        models[spec["name"]] = AdvText(ctx["adv"], cfg["seed"], spec["lam"]).fit(
            texts, y, w, train["source"].to_numpy()
        )
    rows, leak = [], []
    for name, model in models.items():
        thr = _thresholds(cal["label"], model.score(piece_texts(cal, "url")), targets, min_neg)
        rows += _rows(
            {"split": ctx["k"], "model": name},
            ctx["sets"],
            lambda f, m=model: m.score(piece_texts(f, "url")),
            targets,
            min_neg,
            thr,
        )
        if isinstance(model, AdvText):
            acc = model.source_accuracy(piece_texts(test, "url"), test["source"].to_numpy())
            leak.append({"model": name, "source_accuracy_test": acc})
    pd.DataFrame(leak).to_csv(ctx["tables"] / "source_accuracy.csv", index=False)
    pd.DataFrame(rows).to_csv(out, index=False)
    log.info("stage alone done")


def stage_hybrid(ctx: dict) -> None:
    out = ctx["tables"] / "hybrid_runs.csv"
    if out.exists():
        return
    cfg, train, cal = ctx["cfg"], ctx["train"], ctx["cal"]
    targets, min_neg = ctx["targets"], ctx["min_neg"]
    base = make_hybrid(cfg, "hybrid2")
    model = HybridMulti(
        cfg["lightgbm"],
        cfg["char_ngram"],
        base.columns,
        cfg["stack"]["n_folds"],
        cfg["seed"],
        scorers=[*cfg["hybrid2"]["scorers"], *ADV_SPECS],
    )
    model.adv_params = ctx["adv"]
    t0 = time.monotonic()
    model.fit(train, train["label"].to_numpy(), train["weight"].to_numpy())
    log.info("out-of-fold scores done (%.0fs)", time.monotonic() - t0)
    names = base.scorer_names
    for name, kind, params, extra in (
        ("lightgbm", "lightgbm", cfg["lightgbm"], []),
        ("catboost", "catboost", ctx["catboost"], []),
        ("xgboost", "xgboost", cfg["xgboost"], []),
        ("lightgbm+adv", "lightgbm", cfg["lightgbm"], ["adv_url"]),
        ("lightgbm+plain", "lightgbm", cfg["lightgbm"], ["plain_url"]),
    ):
        t0 = time.monotonic()
        model.add_final(name, kind, params, names + extra)
        log.info("%s fitted (%.0fs)", name, time.monotonic() - t0)
    fns = {n: (lambda f, n=n: model.scores(n, f)) for n in model.finals}
    fns["avg_lgbm_cat"] = lambda f: (logit(fns["lightgbm"](f)) + logit(fns["catboost"](f))) / 2
    rows = []
    for name, fn in fns.items():
        thr = _thresholds(cal["label"], fn(cal), targets, min_neg)
        rows += _rows({"split": ctx["k"], "model": name}, ctx["sets_f"], fn, targets, min_neg, thr)
    pd.DataFrame(rows).to_csv(out, index=False)
    log.info("stage hybrid done")


def _deltas(runs: pd.DataFrame, ref: str, models: list[str], bar: float) -> list[str]:
    lines = [f"Change in recall at 1% FPR against `{ref}` (points; bar {bar:g}):", ""]
    sets = [s for s in runs["eval_set"].drop_duplicates() if not s.startswith("test:")]
    lines += ["| model | " + " | ".join(sets) + " |", "|---|" + "---|" * len(sets)]
    for m in models:
        cells = []
        for s in sets:
            d = 100 * (_get(runs, m, s, "op_1pct_recall") - _get(runs, ref, s, "op_1pct_recall"))
            if math.isnan(d):
                cells.append("-")
            else:
                mark = "**" if d > bar else ""
                cells.append(f"{mark}{d:+.1f}{mark}")
        lines.append(f"| {m} | " + " | ".join(cells) + " |")
    return lines + ["", "Bold = above the bar.", ""]


def render(ctx: dict) -> str:
    cfg, bar, tables = ctx["cfg"], ctx["bar"], ctx["tables"]
    lines = [
        f"# Other boosters and a source-adversarial scorer, split {ctx['k']}",
        "",
        "Generated by `python -m experiments.boosters_a`. Do not edit by hand. One split only,",
        "so the 2-point bar (a proposal, not yet approved) stands in for the split spread.",
        f"Settings: `configs/boosters.yaml`; seed {cfg['seed']}.",
        "",
    ]
    if (tables / "alone_runs.csv").exists():
        runs = pd.read_csv(tables / "alone_runs.csv")
        lines += ["## URL text models alone", ""]
        lines += _table(runs, list(runs["model"].drop_duplicates()), bar, "plain_url", "adv_url")
        s = pd.read_csv(tables / "source_accuracy.csv")
        lines += ["Share of test rows whose source the network's source head still names:", ""]
        lines += [f"- {r.model}: {r.source_accuracy_test:.1%}" for r in s.itertuples()] + [""]
    if (tables / "hybrid_runs.csv").exists():
        runs = pd.read_csv(tables / "hybrid_runs.csv")
        models = list(runs["model"].drop_duplicates())
        lines += ["## Hybrid: final models on the same out-of-fold inputs", ""]
        lines += _table(runs, models, bar, "lightgbm", "catboost")
        lines += _deltas(runs, "lightgbm", [m for m in models if m != "lightgbm"], bar)
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
    cc = load_config("boosters")
    lists = lists or load_lists(args.lists_dir, args.platforms_file)
    char_cnn.set_deadline(args.max_hours)
    ctx = build_ctx(args, cfg, lists, cc)
    ctx["adv"] = dict(cc["adv"], **({"epochs": 1} if args.smoke else {}))
    ctx["catboost"] = dict(cc["catboost"], **({"iterations": 30} if args.smoke else {}))
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
    ap = argparse.ArgumentParser(prog="experiments.boosters_a")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--reports", type=Path, default=Path("reports/boosters_split0"))
    ap.add_argument("--split", type=int, default=None)
    ap.add_argument("--max-hours", type=float, default=3.0)
    ap.add_argument("--smoke", type=int, default=0, help="rows of train for a tiny test run")
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
