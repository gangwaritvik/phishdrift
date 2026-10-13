"""Deployment-style blended detector: each URL goes to the model it would use in the browser.

python -m experiments.blend [--processed data/processed] [--reports reports] [--splits ...]

Per split k (train side only for fitting; thresholds from the cal side):
- ``a``     the tier A hybrid2 model, scoring every URL (all that is known without a page);
- ``b``     the tier B model (tier A + page features + text scores), for URLs whose page has
  usable HTML (they have a row in ``features_b``);
- each model's scores are made comparable with isotonic calibration fitted on the cal side
  (``b`` on the cal rows with HTML only), the blended score is the calibrated score of the model
  the URL is routed to, and the FPR thresholds (1%, 0.1%) are taken on the pooled blended cal
  scores, as one detector would use them.

Reported on ``test``, the newest ``time_slice`` and the ``heldout_source`` (no HTML there, so it
is scored by ``a`` alone), each split into the URLs with and without usable HTML, next to the
tier A model alone on the same URLs. Caveat: in this corpus, whether a URL has HTML depends on
its source (PhiUSIIL, URL-Phish and PhishStorm saved none), not on the live page, so the pooled
blend mixes a measured page-model gain on part of the URLs with address-only scores on the rest;
in the browser every page that loads has HTML. The ``html`` rows are the better guide to a
browsing situation and the pooled rows a lower bound.
One result file per split (``tables/blend_runs/split_<k>.csv``).
"""

from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression

from data_pipeline.split import CAL, TEST, TRAIN
from experiments.hybrid_a import make_hybrid
from experiments.metrics import evaluate, operating_point
from experiments.ood_fpr import load_ood
from experiments.ood_fpr_b import load_ood_b
from experiments.tier_a import _fmt, apply_fitted, assert_no_overlap, load_part, refit
from experiments.tier_b import _model
from features.lists import load_lists
from features.registry import NAMES_B
from phishdrift.config import load_config

log = logging.getLogger("blend")


def with_page_features(frame: pd.DataFrame, processed: Path, part: str) -> pd.DataFrame:
    """Left join of the tier B features; ``has_html`` marks the rows that have them."""
    name = "features_b.parquet" if part == "pool" else f"features_b_{part}.parquet"
    path = processed / name
    if path.exists():
        b = pd.read_parquet(path)
        frame = frame.merge(b[["uid", *NAMES_B]], on="uid", how="left", validate="one_to_one")
        frame["has_html"] = frame[list(NAMES_B)].notna().any(axis=1).to_numpy()
    else:
        for c in NAMES_B:
            frame[c] = np.nan
        frame["has_html"] = False
    return frame.reset_index(drop=True)


def run_split(k, pool, splits, extra, lists, cfg, ood=None) -> tuple[list[dict], list[dict]]:
    targets, min_neg = cfg["eval"]["target_fprs"], cfg["eval"]["min_negatives"]
    side = splits[f"split_{k}"].to_numpy()
    train, cal, test = (pool[side == s] for s in (TRAIN, CAL, TEST))
    for name, other in {"cal": cal, "test": test, **extra}.items():
        assert_no_overlap(train, other, "train", name)
    t0 = time.monotonic()
    fitted = refit(train, lists)
    train, cal, test = (apply_fitted(f, fitted) for f in (train, cal, test))
    sets = {"test": test} | {n: apply_fitted(f, fitted) for n, f in extra.items()}

    y, w = train["label"].to_numpy(), train["weight"].to_numpy()
    model_a = make_hybrid(cfg, "hybrid2").fit(train, y, w)
    htm = train["has_html"].to_numpy()
    model_b = _model("ab_hybrid2", cfg, train[htm], y[htm], w[htm])
    log.info("split %d fitted: %.0fs", k, time.monotonic() - t0)

    cal_a, cal_b = model_a.score(cal), model_b.score(cal)
    ch = cal["has_html"].to_numpy()
    iso_a = IsotonicRegression(out_of_bounds="clip").fit(cal_a, cal["label"])
    iso_b = IsotonicRegression(out_of_bounds="clip").fit(cal_b[ch], cal["label"].to_numpy()[ch])

    def blended(frame: pd.DataFrame, s_a: np.ndarray, s_b: np.ndarray | None) -> np.ndarray:
        out = iso_a.predict(s_a)
        if s_b is not None:
            m = frame["has_html"].to_numpy()
            out[m] = iso_b.predict(s_b[m])
        return out

    cal_blend = blended(cal, cal_a, cal_b)
    cal_only_a = iso_a.predict(cal_a)
    yc = cal["label"].to_numpy()
    thr = {
        "blend": {t: operating_point(yc, cal_blend, t, min_neg)["threshold"] for t in targets},
        "a_only": {t: operating_point(yc, cal_only_a, t, min_neg)["threshold"] for t in targets},
    }
    rows = []
    for set_name, frame in sets.items():
        s_a = model_a.score(frame)
        s_b = model_b.score(frame) if frame["has_html"].any() else None
        scores = {"blend": blended(frame, s_a, s_b), "a_only": iso_a.predict(s_a)}
        yy, html = frame["label"].to_numpy(), frame["has_html"].to_numpy()
        for model, s in scores.items():
            for tag, m in (("", np.ones(len(frame), bool)), (":html", html), (":nohtml", ~html)):
                if not m.any():
                    continue
                r = evaluate(yy[m], s[m], targets, min_neg, thr[model])
                n_dom = frame.loc[m, "domain"].nunique()
                rows.append(
                    {"split": k, "model": model, "eval_set": set_name + tag, "n_domains": n_dom} | r
                )
    ood_rows = []
    for name, frame in (ood or {}).items():
        frame = apply_fitted(frame, fitted)
        assert_no_overlap(train, frame, "train", name)
        assert_no_overlap(cal, frame, "cal", name)
        s_a = model_a.score(frame)
        s_b = model_b.score(frame) if frame["has_html"].any() else None
        scores = {"blend": blended(frame, s_a, s_b), "a_only": iso_a.predict(s_a)}
        for model, s in scores.items():
            for t in targets:
                ood_rows.append(
                    {
                        "split": k,
                        "model": model,
                        "ood_set": name,
                        "target_fpr": t,
                        "threshold": thr[model][t],
                        "n_urls": len(frame),
                        "n_domains": frame["domain"].nunique(),
                        "ood_fpr": float(np.mean(s >= thr[model][t])),
                    }
                )
    log.info("split %d done: %.0fs", k, time.monotonic() - t0)
    return rows, ood_rows


def render(runs: pd.DataFrame) -> str:
    lines = [
        "# Deployment-style blend: page model where the page has HTML, address model otherwise",
        "",
        "Generated by `python -m experiments.blend`. Do not edit by hand.",
        "`blend` routes each URL to the model it would use in the browser (tier B when the page",
        "has usable HTML, tier A hybrid2 otherwise) with isotonic calibration and one pair of",
        "FPR thresholds on the pooled cal scores; `a_only` is the address-only model with its own",
        "thresholds. `:html` / `:nohtml` split a set by whether the URL has usable HTML in this",
        "corpus (at least 200 characters of visible text and not a parked, takedown or error",
        "page; `features/build_b.py`). In the corpus that depends on the source (PhiUSIIL and",
        "URL-Phish saved no HTML of their own, only their crawled inner pages have it, and",
        "PhishStorm has none), not on the live page, so the pooled rows are a lower bound for",
        "browsing; the `:html` rows describe pages that load with content. Median over splits",
        "[min, max].",
        "",
        "| set | model | splits | URLs | domains | ROC-AUC | recall @1% FPR | recall @0.1% FPR "
        "| cal 1%: recall / FPR | cal 0.1%: recall / FPR |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for (set_name, model), g in runs.groupby(["eval_set", "model"], sort=False):

        def cell(m, pct=True, g=g):
            return f"{_fmt(g[m].median(), pct)} [{_fmt(g[m].min(), pct)}, {_fmt(g[m].max(), pct)}]"

        lines.append(
            f"| {set_name} | {model} | {len(g)} | {int(g['n_urls'].median()):,} "
            f"| {int(g['n_domains'].median()):,} | {cell('roc_auc', False)} "
            f"| {cell('op_1pct_recall')} | {cell('op_0p1pct_recall')} "
            f"| {_fmt(g['cal_1pct_recall'].median())} / {_fmt(g['cal_1pct_fpr'].median())} "
            f"| {_fmt(g['cal_0p1pct_recall'].median())} / {_fmt(g['cal_0p1pct_fpr'].median())} |"
        )
    return "\n".join(lines + [""])


def render_ood(runs: pd.DataFrame) -> str:
    lines = [
        "# Blend: false alarms on naturally browsed legitimate pages",
        "",
        "Generated by `python -m experiments.blend`. Do not edit by hand.",
        "Share of ordinary legitimate inner pages (Tranco sites outside every training, cal and",
        "held-out set, `collector crawl-ood`) scored as phishing at the cal-side threshold for the",
        "target FPR. `ood_urls`: all usable pages, address only (no HTML kept in that crawl), so",
        "`blend` and `a_only` give the same scores but use different thresholds (the blend's come",
        "from the pooled blended cal scores). `ood_html`: the pages of the second pass with usable",
        "HTML, where `blend` uses the page model. Median over splits [min, max].",
        "",
        "| set | URLs | domains | model | target FPR | splits | OOD FPR |",
        "|---|---|---|---|---|---|---|",
    ]
    for (name, model, t), g in runs.groupby(["ood_set", "model", "target_fpr"], sort=False):
        v = g["ood_fpr"]
        spread = f"{_fmt(v.median())} [{_fmt(v.min())}, {_fmt(v.max())}]"
        lines.append(
            f"| {name} | {int(g['n_urls'].median()):,} | {int(g['n_domains'].median()):,} "
            f"| {model} | {t:.1%} | {len(g)} | {spread} |"
        )
    return "\n".join(lines + [""])


def write_reports(reports: Path) -> Path:
    tables = reports / "tables"
    parts = sorted((tables / "blend_runs").glob("split_*.csv"))
    runs = pd.concat([pd.read_csv(p) for p in parts], ignore_index=True)
    runs.to_csv(tables / "blend_runs.csv", index=False)
    out = reports / "blend.md"
    out.write_text(render(runs), encoding="utf-8")
    ood_parts = sorted((tables / "blend_ood_runs").glob("split_*.csv"))
    if ood_parts:
        ood = pd.concat([pd.read_csv(p) for p in ood_parts], ignore_index=True)
        ood.to_csv(tables / "blend_ood_runs.csv", index=False)
        (reports / "blend_ood.md").write_text(render_ood(ood), encoding="utf-8")
    return out


def run(
    processed, reports, split_ids=None, cfg=None, lists=None, ood_csv=None, ood_html_dir=None
) -> Path:
    cfg = cfg or load_config("models")
    lists = lists or load_lists()
    per_split = reports / "tables" / "blend_runs"
    per_split.mkdir(parents=True, exist_ok=True)
    (reports / "tables" / "blend_ood_runs").mkdir(parents=True, exist_ok=True)
    ood = {}
    if ood_csv:
        urls = load_ood(ood_csv, lists)
        urls["has_html"] = False
        ood["ood_urls"] = urls.assign(**{c: np.nan for c in NAMES_B})
    if ood_html_dir:
        pages, _ = load_ood_b(ood_html_dir, lists)
        pages["has_html"] = True
        ood["ood_html"] = pages
    pool = with_page_features(load_part(processed, "pool", lists), processed, "pool")
    extra = {
        "time_slice": with_page_features(
            load_part(processed, "time_slice", lists), processed, "time_slice"
        ),
        "heldout_source": with_page_features(
            load_part(processed, "heldout_source", lists), processed, "heldout_source"
        ),
    }
    splits = pd.read_parquet(processed / "splits.parquet")
    splits = pool[["uid"]].merge(splits, on="uid", how="left", validate="one_to_one")
    log.info("pool %d rows, %d with HTML", len(pool), int(pool["has_html"].sum()))
    n_splits = sum(c.startswith("split_") for c in splits.columns)
    for k in split_ids if split_ids is not None else range(n_splits):
        out = per_split / f"split_{k}.csv"
        if out.exists():
            continue
        rows, ood_rows = run_split(k, pool, splits, extra, lists, cfg, ood)
        if ood_rows:
            ood_out = reports / "tables" / "blend_ood_runs" / f"split_{k}.csv"
            pd.DataFrame(ood_rows).to_csv(ood_out, index=False)
        tmp = out.with_suffix(".tmp")
        pd.DataFrame(rows).to_csv(tmp, index=False)
        tmp.replace(out)
        write_reports(reports)
        log.info("split %d written", k)
    return write_reports(reports)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.blend")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--splits", type=int, nargs="*", default=None)
    ap.add_argument("--ood-csv", type=Path, default=None, help="crawl-ood first pass ood_urls.csv")
    ap.add_argument("--ood-html-dir", type=Path, default=None, help="crawl-ood --html-pass folder")
    ap.add_argument("--lists-dir", default=None)
    ap.add_argument("--platforms-file", default=None)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    lists = load_lists(a.lists_dir, a.platforms_file)
    print(run(a.processed, a.reports, a.splits, None, lists, a.ood_csv, a.ood_html_dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
