"""One-split test of a deep (character CNN) member for the tier A hybrid.

python -m experiments.char_cnn_a [--processed data/processed] [--reports reports/char_cnn_split0]
                                 [--max-hours 3] [--smoke 2000]

Uses the same domain-grouped split, the same fitted features and the same metrics as
``experiments.hybrid_a``; nothing shipped is changed and nothing is tuned on test. Two stages
(a finished stage is skipped on a rerun; a stopped training resumes from its last epoch):

1. ``alone``: the CNN against the character n-gram + logistic-regression model it would sit
   next to (hybrid2's ``char_url`` scorer), plus a shuffled-label control for the CNN.
2. ``hybrid``: today's hybrid2 (LightGBM + four text scorers) against the same model with the
   CNN as a fifth out-of-fold scorer.

Both are scored on test (and per source), the held-out source, the newest time slice and the
test URLs rewritten to ``https://www.<registrable domain>``. ``SUMMARY.md`` is built only from
the tables. The 2-point bar is a proposal, not an agreed rule.
"""

from __future__ import annotations

import argparse
import logging
import math
import time
from pathlib import Path

import numpy as np
import pandas as pd

from data_pipeline.split import CAL, TEST, TRAIN
from experiments.hybrid_a import make_hybrid
from experiments.metrics import evaluate, operating_point
from experiments.tier_a import (
    PARTS,
    _fmt,
    apply_fitted,
    assert_no_overlap,
    load_part,
    normalised_features,
    refit,
)
from features.lists import Lists, load_lists
from models import char_cnn
from models.char_cnn import CharCNN, TimeLimit
from models.hybrid import HybridA
from models.text_scorers import make_text_model, piece_texts
from phishdrift.config import load_config

log = logging.getLogger("char_cnn_a")
CNN_SPEC = {"name": "cnn_url", "piece": "url", "kind": "cnn"}


class HybridCNN(HybridA):
    """HybridA that also builds the ``cnn`` scorer kind (no change to the shipped class)."""

    cnn_params: dict = {}
    cache_dir: Path | None = None

    def _text_model(self, spec: dict):
        if spec["kind"] == "cnn":
            return CharCNN(self.cnn_params, self.seed, self.cache_dir)
        return super()._text_model(spec)


def _sets(test, holdouts, test_norm):
    sets = {"test": test, **holdouts, "test_normalised": test_norm}
    for src in sorted(test["source"].unique()):
        sets[f"test:{src}"] = test[test["source"] == src]
    return sets


def _rows(base: dict, sets: dict, score, targets, min_neg, thresholds) -> list[dict]:
    rows = []
    for name, frame in sets.items():
        row = evaluate(frame["label"].to_numpy(), score(frame), targets, min_neg, thresholds)
        rows.append(base | {"eval_set": name, "n_domains": frame["domain"].nunique()} | row)
    return rows


def _thresholds(y_cal, s_cal, targets, min_neg) -> dict:
    return {t: operating_point(y_cal, s_cal, t, min_neg)["threshold"] for t in targets}


def stage_alone(ctx: dict) -> None:
    out = ctx["tables"] / "alone_runs.csv"
    if out.exists():
        return
    cfg, train, cal, test = ctx["cfg"], ctx["train"], ctx["cal"], ctx["test"]
    targets, min_neg = ctx["targets"], ctx["min_neg"]
    y, w = train["label"].to_numpy(), train["weight"].to_numpy()
    texts = {n: piece_texts(f, "url") for n, f in (("train", train), ("cal", cal))}
    rows = []

    cnn = CharCNN(ctx["cnn"], cfg["seed"], ctx["ckpt"] / "alone")
    cnn.fit(texts["train"], y, w, watch=(texts["cal"], cal["label"].to_numpy()))
    ngram = make_text_model(cfg["hybrid2"]["scorers"][0], cfg["char_ngram"], cfg["seed"])
    ngram.fit(texts["train"], y, w)
    for name, model in (("cnn_url", cnn), ("char_url_lr", ngram)):
        thr = _thresholds(cal["label"], model.score(texts["cal"]), targets, min_neg)
        base = {"split": ctx["k"], "model": name}
        rows += _rows(
            base,
            ctx["sets"],
            lambda f, m=model: m.score(piece_texts(f, "url")),
            targets,
            min_neg,
            thr,
        )
    pd.DataFrame(rows).to_csv(out, index=False)

    # shuffled-label control, unweighted like experiments.tier_a
    y_shuffled = np.random.default_rng(cfg["seed"] + ctx["k"]).permutation(y)
    control = CharCNN(ctx["cnn"], cfg["seed"], ctx["ckpt"] / "control")
    control.fit(texts["train"], y_shuffled)
    row = evaluate(test["label"], control.score(piece_texts(test, "url")), targets, min_neg)
    pd.DataFrame([{"split": ctx["k"], "model": "cnn_url"} | row]).to_csv(
        ctx["tables"] / "control.csv", index=False
    )
    log.info("stage alone done")


def stage_hybrid(ctx: dict) -> None:
    out = ctx["tables"] / "hybrid_runs.csv"
    if out.exists():
        return
    cfg, train, cal = ctx["cfg"], ctx["train"], ctx["cal"]
    targets, min_neg = ctx["targets"], ctx["min_neg"]
    y, w = train["label"].to_numpy(), train["weight"].to_numpy()
    rows = []
    base_model = make_hybrid(cfg, "hybrid2")
    cnn_model = HybridCNN(
        cfg["lightgbm"],
        cfg["char_ngram"],
        base_model.columns,
        cfg["stack"]["n_folds"],
        cfg["seed"],
        scorers=[*cfg["hybrid2"]["scorers"], CNN_SPEC],
    )
    cnn_model.cnn_params, cnn_model.cache_dir = ctx["cnn"], ctx["ckpt"] / "hybrid"
    for name, model in (("hybrid2", base_model), ("hybrid2+cnn", cnn_model)):
        t0 = time.monotonic()
        model.fit(train, y, w)
        thr = _thresholds(cal["label"], model.score(cal), targets, min_neg)
        base = {"split": ctx["k"], "model": name}
        rows += _rows(base, ctx["sets_f"], model.score, targets, min_neg, thr)
        log.info("%s fitted and scored (%.0fs)", name, time.monotonic() - t0)
    pd.DataFrame(rows).to_csv(out, index=False)
    log.info("stage hybrid done")


def _get(runs: pd.DataFrame, model: str, eval_set: str, col: str) -> float:
    r = runs[(runs["model"] == model) & (runs["eval_set"] == eval_set)]
    return float(r[col].iloc[0]) if len(r) else math.nan


def _table(runs: pd.DataFrame, models: list[str], bar: float, ref: str, new: str) -> list[str]:
    lines = [
        "| set | model | URLs | domains | ROC-AUC | recall @1% FPR | recall @0.1% FPR "
        "| cal 1%: recall / FPR | cal 0.1%: recall / FPR |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for set_name in runs["eval_set"].drop_duplicates():
        for m in models:
            r = runs[(runs["model"] == m) & (runs["eval_set"] == set_name)]
            if r.empty:
                continue
            r = r.iloc[0]
            gl = "*" if r.get("op_0p1pct_granularity_limited", False) else ""
            lines.append(
                f"| {set_name} | {m} | {int(r['n_urls']):,} | {int(r['n_domains']):,} "
                f"| {_fmt(r['roc_auc'], False)} | {_fmt(r['op_1pct_recall'])} "
                f"| {_fmt(r['op_0p1pct_recall'])}{gl} "
                f"| {_fmt(r['cal_1pct_recall'])} / {_fmt(r['cal_1pct_fpr'])} "
                f"| {_fmt(r['cal_0p1pct_recall'])} / {_fmt(r['cal_0p1pct_fpr'])} |"
            )
    lines += ["", f"Change in recall at 1% FPR, `{new}` minus `{ref}` (points; bar {bar:g}):", ""]
    for set_name in ("test", "heldout_source", "time_slice", "test_normalised"):
        if set_name not in set(runs["eval_set"]):
            continue
        d = 100 * (
            _get(runs, new, set_name, "op_1pct_recall")
            - _get(runs, ref, set_name, "op_1pct_recall")
        )
        if math.isnan(d):
            continue
        verdict = "above the bar" if d > bar else ("worse" if d < -bar else "within the spread")
        lines.append(f"- {set_name}: {d:+.1f} points ({verdict})")
    return lines + [""]


def render(ctx: dict) -> str:
    cfg, bar, tables = ctx["cfg"], ctx["bar"], ctx["tables"]
    lines = [
        "# CharCNN test on split " + str(ctx["k"]),
        "",
        "Generated by `python -m experiments.char_cnn_a`. Do not edit by hand. One split only,",
        "so the 2-point bar (a proposal, not yet approved) stands in for the split spread.",
        f"Settings: `configs/char_cnn.yaml` (epochs {ctx['cnn']['epochs']}); seed {cfg['seed']}.",
        "",
    ]
    flag = cfg["eval"]["shuffled_label_flag"]
    if (tables / "alone_runs.csv").exists():
        runs = pd.read_csv(tables / "alone_runs.csv")
        lines += ["## CNN alone against the n-gram model it would sit next to", ""]
        lines += _table(runs, ["cnn_url", "char_url_lr"], bar, "char_url_lr", "cnn_url")
        c = pd.read_csv(tables / "control.csv")
        auc = float(c["roc_auc"].iloc[0])
        lines += [
            f"Shuffled-label control (CNN, test ROC-AUC): {auc:.4f} "
            f"({'FLAGGED' if abs(auc - 0.5) > flag else 'not flagged'}, limit {flag}).",
            "",
        ]
    if (tables / "hybrid_runs.csv").exists():
        runs = pd.read_csv(tables / "hybrid_runs.csv")
        lines += ["## Hybrid with and without the CNN scorer", ""]
        lines += _table(runs, ["hybrid2", "hybrid2+cnn"], bar, "hybrid2", "hybrid2+cnn")
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
    cc = load_config("char_cnn")
    cnn = dict(cc["char_cnn"])
    reports = args.reports
    reports.mkdir(parents=True, exist_ok=True)
    tables = reports / "tables"
    tables.mkdir(exist_ok=True)
    k = cc["split"] if args.split is None else args.split
    lists = lists or load_lists(args.lists_dir, args.platforms_file)
    char_cnn.set_deadline(args.max_hours)

    # time_slice and natural are optional parts: a staged sample may have neither
    parts = [p for p in (*PARTS, "natural") if (args.processed / f"meta_{p}.parquet").exists()]
    frames = {p: load_part(args.processed, p, lists) for p in parts}
    pool = frames.pop("pool")
    splits = pd.read_parquet(args.processed / "splits.parquet")
    splits = pool[["uid"]].merge(splits, on="uid", how="left", validate="one_to_one")
    side = splits[f"split_{k}"].to_numpy()
    train, cal, test = (pool[side == s] for s in (TRAIN, CAL, TEST))
    if args.smoke:  # tiny run through every code path; results go to a separate folder
        n = args.smoke
        pick = lambda f, m: f.sample(min(m, len(f)), random_state=0)  # noqa: E731
        train, cal, test = pick(train, n), pick(cal, n // 2), pick(test, n // 2)
        frames = {name: pick(f, n // 2) for name, f in frames.items()}
        cnn["epochs"] = 1
    for name, other in {"cal": cal, "test": test, **frames}.items():
        assert_no_overlap(train, other, "train", name)
    for name, other in frames.items():
        assert_no_overlap(cal, other, "cal", name)

    fitted = refit(train, lists)
    train, cal, test = (apply_fitted(f, fitted) for f in (train, cal, test))
    holdouts = {n: apply_fitted(h, fitted) for n, h in frames.items()}
    td = test.drop_duplicates(["domain", "label"])[["domain", "label", "depth", "source"]]
    norm = normalised_features(td["domain"], lists)
    nf = apply_fitted(norm.loc[td["domain"]].reset_index(drop=True), fitted)
    test_norm = pd.concat([td.reset_index(drop=True), nf], axis=1)
    sets_f = _sets(test, holdouts, test_norm)  # frames with all features (hybrid stage)
    ctx = {
        "cfg": cfg,
        "cnn": cnn,
        "bar": cc["bar_points"],
        "k": k,
        "train": train,
        "cal": cal,
        "test": test,
        "sets": sets_f,
        "sets_f": sets_f,
        "targets": cfg["eval"]["target_fprs"],
        "min_neg": cfg["eval"]["min_negatives"],
        "tables": tables,
        "ckpt": reports / "ckpt",
    }
    status = 0
    try:
        stage_alone(ctx)
        stage_hybrid(ctx)
    except TimeLimit as e:
        log.warning("%s", e)
        status = 3
    (reports / "SUMMARY.md").write_text(render(ctx), encoding="utf-8")
    print((reports / "SUMMARY.md").read_text(encoding="utf-8"))
    return status


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.char_cnn_a")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--reports", type=Path, default=Path("reports/char_cnn_split0"))
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
