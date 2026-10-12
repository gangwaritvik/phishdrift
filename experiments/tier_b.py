"""Tier B (URL + HTML) models over the 10 domain-grouped splits, on samples that have HTML.

python -m experiments.tier_b [--processed data/processed] [--reports reports] [--splits ...]

Reads ``features_b[_<part>].parquet`` (``python -m features build --tier B``) and joins it to the
tier A table by ``uid``; rows without usable HTML have no tier B features and are left out, so
every comparison here is on the same rows. Variants per split (all trained on the train side
only, thresholds from the cal side of the same rows):

- ``a_hybrid2``     tier A hybrid2 model, no HTML features (the baseline on these rows);
- ``ab_lgbm``       LightGBM on the 99 tier A + 84 tier B features;
- ``ab_hybrid2``    the same plus out-of-fold text scores (hybrid2 scorers);
- ``ab_lgbm_nopp``  ``ab_lgbm`` trained without Phishpedia (phishing only, dated 2019-2020), to
  show whether the model learns "old page = phishing".

Eval sets: ``test``, ``test:<source>``, and ``time_slice`` (when ``features_b_time_slice`` is
present). The held-out source (PhishStorm) has no HTML, so it cannot be scored here.
One result file per split (``tables/tier_b_runs/split_<k>.csv``) so splits can run in parallel;
the top LightGBM gain features go to ``tables/tier_b_importance/split_<k>.csv``.
"""

from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

import pandas as pd

from data_pipeline.split import CAL, TEST, TRAIN
from experiments.hybrid_a import make_hybrid
from experiments.metrics import evaluate, operating_point
from experiments.tier_a import _fmt, apply_fitted, assert_no_overlap, load_part, refit
from features.lists import Lists, load_lists
from features.registry import NAMES, NAMES_B
from models.gbdt import GBDT
from models.hybrid import HybridA
from phishdrift.config import load_config

log = logging.getLogger("tier_b")

VARIANTS = ("a_hybrid2", "ab_lgbm", "ab_hybrid2", "ab_lgbm_nopp")
EXCLUDED_SOURCE = "phishpedia"


def load_b(processed: Path, part: str, lists: Lists) -> pd.DataFrame | None:
    """Tier A table joined to the tier B features (inner join: only rows with usable HTML)."""
    feat = processed / ("features_b.parquet" if part == "pool" else f"features_b_{part}.parquet")
    if not feat.exists():
        return None
    base = load_part(processed, part, lists)
    b = pd.read_parquet(feat)
    missing = set(NAMES_B) - set(b.columns)
    if missing:
        raise ValueError(f"{feat.name} lacks tier B columns: {sorted(missing)[:5]}")
    return base.merge(b[["uid", *NAMES_B]], on="uid", how="inner", validate="one_to_one")


def _model(variant: str, cfg: dict, train: pd.DataFrame, y, w):
    cols = list(NAMES) + list(NAMES_B)
    if variant == "a_hybrid2":
        return make_hybrid(cfg, "hybrid2").fit(train, y, w)
    if variant in ("ab_lgbm", "ab_lgbm_nopp"):
        return GBDT("lightgbm", cfg["lightgbm"], cols, cfg["seed"]).fit(train, y, w)
    return HybridA(
        cfg["lightgbm"],
        cfg["char_ngram"],
        cols,
        cfg["stack"]["n_folds"],
        cfg["seed"],
        scorers=cfg["hybrid2"]["scorers"],
    ).fit(train, y, w)


def run_split(k, pool, splits, time_slice, lists, cfg) -> tuple[list[dict], list[dict]]:
    targets, min_neg = cfg["eval"]["target_fprs"], cfg["eval"]["min_negatives"]
    side = splits[f"split_{k}"].to_numpy()
    train, cal, test = (pool[side == s] for s in (TRAIN, CAL, TEST))
    assert_no_overlap(train, test, "train", "test")
    assert_no_overlap(train, cal, "train", "cal")
    sets = {"test": test}
    if time_slice is not None:
        assert_no_overlap(train, time_slice, "train", "time_slice")
        assert_no_overlap(cal, time_slice, "cal", "time_slice")
        sets["time_slice"] = time_slice
    fitted = refit(train, lists)
    train, cal = (apply_fitted(f, fitted) for f in (train, cal))
    sets = {n: apply_fitted(f, fitted) for n, f in sets.items()}
    rows, importance = [], []
    for variant in VARIANTS:
        t0 = time.monotonic()
        tr = train[train["source"] != EXCLUDED_SOURCE] if variant.endswith("_nopp") else train
        model = _model(variant, cfg, tr, tr["label"].to_numpy(), tr["weight"].to_numpy())
        s_cal = model.score(cal)
        thr = {t: operating_point(cal["label"], s_cal, t, min_neg)["threshold"] for t in targets}
        base = {"split": k, "model": variant}
        for set_name, frame in sets.items():
            s = model.score(frame)
            y = frame["label"].to_numpy()
            n_dom = frame["domain"].nunique()
            r = evaluate(y, s, targets, min_neg, thr)
            rows.append(base | {"eval_set": set_name, "n_domains": n_dom} | r)
            for src in sorted(frame["source"].unique()):
                m = (frame["source"] == src).to_numpy()
                r = evaluate(y[m], s[m], targets, min_neg, thr)
                n_dom = frame.loc[m, "domain"].nunique()
                rows.append(base | {"eval_set": f"{set_name}:{src}", "n_domains": n_dom} | r)
        gbdt = getattr(model, "gbdt", model)
        gain = gbdt.model.booster_.feature_importance(importance_type="gain")
        top = pd.Series(gain, index=gbdt.columns).sort_values(ascending=False).head(25)
        importance += [
            {"split": k, "model": variant, "feature": n, "gain": g} for n, g in top.items()
        ]
        log.info("split %d %s: %.0fs", k, variant, time.monotonic() - t0)
    return rows, importance


def render(runs: pd.DataFrame, imp: pd.DataFrame) -> str:
    lines = [
        "# Tier B (URL + HTML) vs tier A on the same rows",
        "",
        "Generated by `python -m experiments.tier_b`. Do not edit by hand.",
        "Only rows with usable HTML. Median over splits [min, max]; thresholds from the cal side",
        "of the same rows. `a_hybrid2` is the address-only model; `ab_*` add the 84 HTML features;",
        "`ab_lgbm_nopp` leaves out Phishpedia (phishing only, 2019-2020) in training.",
        "",
        "| set | model | splits | URLs | domains | ROC-AUC | recall @1% FPR | recall @0.1% FPR "
        "| cal 1%: recall / FPR |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for (set_name, model), g in runs.groupby(["eval_set", "model"], sort=False):

        def cell(m, pct=True, g=g):
            return f"{_fmt(g[m].median(), pct)} [{_fmt(g[m].min(), pct)}, {_fmt(g[m].max(), pct)}]"

        lines.append(
            f"| {set_name} | {model} | {len(g)} | {int(g['n_urls'].median()):,} "
            f"| {int(g['n_domains'].median()):,} | {cell('roc_auc', False)} "
            f"| {cell('op_1pct_recall')} | {cell('op_0p1pct_recall')} "
            f"| {_fmt(g['cal_1pct_recall'].median())} / {_fmt(g['cal_1pct_fpr'].median())} |"
        )
    if len(imp):
        lines += ["", "## Top LightGBM gain features (median rank share, `ab_lgbm`)", ""]
        g = imp[imp["model"] == "ab_lgbm"].copy()
        g["share"] = g["gain"] / g.groupby("split")["gain"].transform("sum")
        top = g.groupby("feature")["share"].median().sort_values(ascending=False).head(15)
        lines += ["| feature | share of top-25 gain |", "|---|---|"]
        lines += [f"| {n} | {v:.1%} |" for n, v in top.items()]
    return "\n".join(lines + [""])


def write_reports(reports: Path) -> Path:
    tables = reports / "tables"
    runs = pd.concat([pd.read_csv(p) for p in sorted((tables / "tier_b_runs").glob("split_*.csv"))])
    runs.to_csv(tables / "tier_b_runs.csv", index=False)
    imp_files = sorted((tables / "tier_b_importance").glob("split_*.csv"))
    imp = pd.concat([pd.read_csv(p) for p in imp_files]) if imp_files else pd.DataFrame()
    out = reports / "tier_b.md"
    out.write_text(render(runs, imp), encoding="utf-8")
    return out


def run(processed, reports, split_ids=None, cfg=None, lists=None) -> Path:
    cfg = cfg or load_config("models")
    lists = lists or load_lists()
    runs_dir = reports / "tables" / "tier_b_runs"
    imp_dir = reports / "tables" / "tier_b_importance"
    runs_dir.mkdir(parents=True, exist_ok=True)
    imp_dir.mkdir(parents=True, exist_ok=True)
    pool = load_b(processed, "pool", lists)
    if pool is None:
        raise SystemExit("features_b.parquet not found in the processed folder")
    time_slice = load_b(processed, "time_slice", lists)
    splits = pd.read_parquet(processed / "splits.parquet")
    splits = pool[["uid"]].merge(splits, on="uid", how="left", validate="one_to_one")
    log.info("tier B rows: %d (phishing %d)", len(pool), int(pool["label"].sum()))
    n_splits = sum(c.startswith("split_") for c in splits.columns)
    for k in split_ids if split_ids is not None else range(n_splits):
        out = runs_dir / f"split_{k}.csv"
        if out.exists():
            continue
        rows, importance = run_split(k, pool, splits, time_slice, lists, cfg)
        pd.DataFrame(importance).to_csv(imp_dir / f"split_{k}.csv", index=False)
        tmp = out.with_suffix(".tmp")
        pd.DataFrame(rows).to_csv(tmp, index=False)
        tmp.replace(out)
        write_reports(reports)
        log.info("split %d written", k)
    return write_reports(reports)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.tier_b")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--splits", type=int, nargs="*", default=None)
    ap.add_argument("--lists-dir", default=None)
    ap.add_argument("--platforms-file", default=None)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    lists = load_lists(a.lists_dir, a.platforms_file)
    print(run(a.processed, a.reports, a.splits, lists=lists))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
