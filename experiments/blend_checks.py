"""Shuffled-label control and address-normalisation check for the deployment-style blend.

python -m experiments.blend_checks [--processed data/processed] [--reports reports] [--splits ...]

The blend (``experiments.blend``) routes a URL with usable HTML to the tier B model and every
other URL to the tier A hybrid2 model, each calibrated on the cal side. Per split:

- ``blend``             the blend on the test side (reference);
- ``blend_normalised``  the same test rows with every tier A feature and text score computed from
  ``https://www.<registrable domain>`` instead of the real URL; the page (tier B) features are
  left as they were, since they describe the page, not the address. It shows how much of the
  blend survives when the address says nothing (``:html`` rows are the ones that carry page
  features);
- ``blend_shuffled``    both models trained on labels permuted within the train side (no sample
  weights) and calibrated on the cal side with the true labels, as in the real pipeline
  (flag rule: |mean test ROC-AUC - 0.5| > ``eval.shuffled_label_flag``).

One result file per split (``tables/blend_checks/split_<k>.csv``). Writes ``blend_checks.md``.
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
from experiments.blend import with_page_features
from experiments.hybrid_a import make_hybrid
from experiments.metrics import evaluate, operating_point
from experiments.tier_a import (
    apply_fitted,
    assert_no_overlap,
    load_part,
    normalised_features,
    refit,
)
from experiments.tier_b import _model
from features.lists import load_lists
from features.registry import NAMES
from phishdrift.config import load_config

log = logging.getLogger("blend_checks")


def fit_blend(train, cal, cfg, y, w):
    """Models a and b, their isotonic maps, and a ``blended(frame)`` scorer."""
    htm = train["has_html"].to_numpy()
    model_a = make_hybrid(cfg, "hybrid2").fit(train, y, w)
    model_b = _model("ab_hybrid2", cfg, train[htm], y[htm], None if w is None else w[htm])
    ch = cal["has_html"].to_numpy()
    yc = cal["label"].to_numpy()
    iso_a = IsotonicRegression(out_of_bounds="clip").fit(model_a.score(cal), yc)
    iso_b = IsotonicRegression(out_of_bounds="clip").fit(model_b.score(cal)[ch], yc[ch])

    def blended(frame: pd.DataFrame) -> np.ndarray:
        out = iso_a.predict(model_a.score(frame))
        m = frame["has_html"].to_numpy()
        if m.any():
            out[m] = iso_b.predict(model_b.score(frame)[m])
        return out

    return blended


def normalise_address(test: pd.DataFrame, lists) -> pd.DataFrame:
    """``test`` with the address-derived columns taken from ``https://www.<domain>``."""
    norm = normalised_features(test["domain"], lists).loc[test["domain"]].reset_index(drop=True)
    out = test.reset_index(drop=True).copy()
    for col in [*NAMES, "_parts", "_text"]:
        out[col] = norm[col].to_numpy()
    return out


def _rows(k, name, frame, score, targets, min_neg, thr) -> list[dict]:
    y, html = frame["label"].to_numpy(), frame["has_html"].to_numpy()
    rows = []
    for tag, m in (("", np.ones(len(frame), bool)), (":html", html), (":nohtml", ~html)):
        if m.any() and len(set(y[m])) == 2:
            r = evaluate(y[m], score[m], targets, min_neg, thr)
            n_dom = frame.loc[m, "domain"].nunique()
            rows.append(
                {"split": k, "model": name, "eval_set": "test" + tag, "n_domains": n_dom} | r
            )
    return rows


def run_split(k, pool, splits, lists, cfg) -> list[dict]:
    targets, min_neg = cfg["eval"]["target_fprs"], cfg["eval"]["min_negatives"]
    side = splits[f"split_{k}"].to_numpy()
    train, cal, test = (pool[side == s] for s in (TRAIN, CAL, TEST))
    assert_no_overlap(train, test, "train", "test")
    assert_no_overlap(train, cal, "train", "cal")
    t0 = time.monotonic()
    fitted = refit(train, lists)
    train, cal, test = (apply_fitted(f, fitted) for f in (train, cal, test))
    y, w = train["label"].to_numpy(), train["weight"].to_numpy()

    blended = fit_blend(train, cal, cfg, y, w)
    yc = cal["label"].to_numpy()
    thr = {t: operating_point(yc, blended(cal), t, min_neg)["threshold"] for t in targets}
    rows = _rows(k, "blend", test, blended(test), targets, min_neg, thr)
    test_norm = apply_fitted(normalise_address(test, lists), fitted)
    rows += _rows(k, "blend_normalised", test_norm, blended(test_norm), targets, min_neg, thr)
    log.info("split %d blend and normalised: %.0fs", k, time.monotonic() - t0)

    shuffled = np.random.default_rng(cfg["seed"] + k).permutation(y)
    control = fit_blend(train, cal, cfg, shuffled, None)
    rows += _rows(k, "blend_shuffled", test, control(test), targets, min_neg, None)
    log.info("split %d control: %.0fs", k, time.monotonic() - t0)
    return rows


def render(runs: pd.DataFrame, cfg: dict) -> str:
    flag = cfg["eval"]["shuffled_label_flag"]

    def cell(g, col, pct=False):
        v = g[col].dropna()
        if v.empty:
            return "n/a"
        k, d = (100, 1) if pct else (1, 4)
        return f"{v.median() * k:.{d}f} [{v.min() * k:.{d}f}, {v.max() * k:.{d}f}]"

    lines = [
        "# Blend: address-normalisation check and shuffled-label control",
        "",
        "Generated by `python -m experiments.blend_checks`. Do not edit by hand.",
        "Test side of each split. `:html` = URLs with usable HTML (routed to the tier B model), "
        "`:nohtml` = the rest (tier A hybrid2). Median [min, max] over splits; recall at the "
        "thresholds' operating points on the test side itself, in %.",
        "",
        "| model | rows | splits | URLs (median) | domains (median) | ROC-AUC | recall @1% FPR "
        "| recall @0.1% FPR |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for (model, ev), g in runs.groupby(["model", "eval_set"], sort=False):
        lines.append(
            f"| {model} | {ev} | {g['split'].nunique()} | {int(g['n_urls'].median()):,} "
            f"| {int(g['n_domains'].median()):,} | {cell(g, 'roc_auc')} "
            f"| {cell(g, 'op_1pct_recall', True)} | {cell(g, 'op_0p1pct_recall', True)} |"
        )
    ctrl = runs[(runs["model"] == "blend_shuffled") & (runs["eval_set"] == "test")]
    if len(ctrl):
        m = ctrl["roc_auc"].mean()
        verdict = "FLAGGED" if abs(m - 0.5) > flag else "not flagged"
        lines += [
            "",
            f"Shuffled-label control: mean test ROC-AUC {m:.4f} over {len(ctrl)} splits; "
            f"{verdict} (flag rule: |mean - 0.5| > {flag}). The control keeps the real "
            "pipeline's isotonic calibration, fitted on the cal side with the true labels, so a "
            "shuffled model's score that differs by source can be mapped onto the sources' "
            "phishing rates; this likely explains a mean slightly above 0.5 (inferred, not "
            "measured).",
        ]
    lines.append("")
    return "\n".join(lines)


def write_reports(reports: Path, cfg: dict) -> Path:
    files = sorted((reports / "tables" / "blend_checks").glob("split_*.csv"))
    runs = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)
    runs.to_csv(reports / "tables" / "blend_checks_runs.csv", index=False)
    out = reports / "blend_checks.md"
    out.write_text(render(runs, cfg), encoding="utf-8")
    return out


def run(processed: Path, reports: Path, split_ids=None, cfg=None, lists=None) -> Path:
    cfg = cfg or load_config("models")
    lists = lists or load_lists()
    out_dir = reports / "tables" / "blend_checks"
    out_dir.mkdir(parents=True, exist_ok=True)
    pool = with_page_features(load_part(processed, "pool", lists), processed, "pool")
    splits = pd.read_parquet(processed / "splits.parquet")
    splits = pool[["uid"]].merge(splits, on="uid", how="left", validate="one_to_one")
    n_splits = sum(c.startswith("split_") for c in splits.columns)
    for k in split_ids if split_ids is not None else range(n_splits):
        out = out_dir / f"split_{k}.csv"
        if out.exists():
            continue
        rows = run_split(k, pool, splits, lists, cfg)
        tmp = out.with_suffix(".tmp")
        pd.DataFrame(rows).to_csv(tmp, index=False)
        tmp.replace(out)
        log.info("split %d written", k)
    return write_reports(reports, cfg)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.blend_checks")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--splits", type=int, nargs="*", default=None)
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--lists-dir", default=None)
    ap.add_argument("--platforms-file", default=None)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    if a.report_only:
        print(write_reports(a.reports, load_config("models")))
        return 0
    lists = load_lists(a.lists_dir, a.platforms_file)
    print(run(a.processed, a.reports, a.splits, lists=lists))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
