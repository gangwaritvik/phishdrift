"""Leave-one-source-out (L9) and per-source results for tier A.

python -m experiments.loso [--processed data/processed] [--reports reports] [--splits 0 1 2]

For each listed split k and each source s of the pool:
- ``all_sources``: train on split k's train side (every source), thresholds from its cal side,
  metrics on the rows of s in its test side (per-source view of the main result);
- ``leave_out``: train and calibrate on the other sources only (train and cal sides of split k),
  metrics on every row of s, which the model never saw in any form.
Sources with one class (Phishpedia, Phish-Blitz) have no FPR; their recall at the thresholds
chosen on cal is reported. A ``tld_risk`` baseline (the fitted phishing rate of the public
suffix, nothing else) shows how much a trivial signal already explains.

Writes ``tables/loso.csv``, ``tables/loso_summary.csv`` and ``loso.md``. Finished splits are
skipped on a rerun.
"""

from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

import numpy as np
import pandas as pd

from data_pipeline.split import CAL, TEST, TRAIN
from experiments.metrics import evaluate, operating_point
from experiments.tier_a import (
    PARTS,
    Spec,
    _append,
    _fmt,
    apply_fitted,
    assert_no_overlap,
    load_part,
    make_model,
    model_input,
    refit,
)
from features.lists import Lists, load_lists
from phishdrift.config import load_config

log = logging.getLogger("loso")
LOSO_SPECS = (Spec("lightgbm", "all"), Spec("char_ngram", "url_text"), Spec("baseline", "tld_risk"))


class TldRiskBaseline:
    """Scores a URL by the training phishing rate of its public suffix (``tld_risk``)."""

    def fit(self, frame: pd.DataFrame, y: np.ndarray, weight: np.ndarray | None = None):
        self.default = float(np.average(y, weights=weight))
        return self

    def score(self, frame: pd.DataFrame) -> np.ndarray:
        return frame["tld_risk"].fillna(self.default).to_numpy(dtype=float)


def build(spec: Spec, cfg: dict):
    return TldRiskBaseline() if spec.name == "baseline" else make_model(spec, cfg)


def train_and_score(
    train: pd.DataFrame, cal: pd.DataFrame, tests: dict[str, pd.DataFrame], spec: Spec, cfg: dict
) -> list[dict]:
    ev = cfg["eval"]
    targets, min_neg = ev["target_fprs"], ev["min_negatives"]
    model = build(spec, cfg).fit(
        model_input(spec, train), train["label"].to_numpy(), train["weight"].to_numpy()
    )
    s_cal = model.score(model_input(spec, cal))
    thresholds = {t: operating_point(cal["label"], s_cal, t, min_neg)["threshold"] for t in targets}
    rows = []
    for source, frame in tests.items():
        if frame.empty:
            continue
        s = model.score(model_input(spec, frame))
        row = evaluate(frame["label"], s, targets, min_neg, thresholds)
        rows.append({"source": source, "n_domains": frame["domain"].nunique()} | row)
    return rows


def run_split(k: int, pool: pd.DataFrame, splits: pd.DataFrame, lists: Lists, cfg: dict):
    side = splits[f"split_{k}"].to_numpy()
    rows = []
    sources = sorted(pool["source"].unique())
    train_all, cal_all, test_all = (pool[side == s] for s in (TRAIN, CAL, TEST))
    fitted = refit(train_all, lists)
    train_f, cal_f, test_f = (apply_fitted(f, fitted) for f in (train_all, cal_all, test_all))
    tests = {s: test_f[test_f["source"] == s] for s in sources}
    for spec in LOSO_SPECS:
        for r in train_and_score(train_f, cal_f, tests, spec, cfg):
            rows.append({"split": k, "condition": "all_sources"} | spec_cols(spec) | r)
    for held in sources:
        t0 = time.monotonic()
        keep = pool["source"] != held
        train = pool[keep & (side == TRAIN)]
        cal = pool[keep & (side == CAL)]
        target = pool[~keep]
        assert_no_overlap(train, target, "train", held)
        assert_no_overlap(cal, target, "cal", held)
        fitted = refit(train, lists)
        train, cal, target = (apply_fitted(f, fitted) for f in (train, cal, target))
        for spec in LOSO_SPECS:
            for r in train_and_score(train, cal, {held: target}, spec, cfg):
                rows.append({"split": k, "condition": "leave_out"} | spec_cols(spec) | r)
        log.info("split %d leave out %s: %.0fs", k, held, time.monotonic() - t0)
    return rows


def spec_cols(spec: Spec) -> dict:
    return {"model": spec.name, "features": spec.features}


def summarise(rows: pd.DataFrame) -> pd.DataFrame:
    keys = ["condition", "source", "model", "features"]
    metrics = ["roc_auc", "op_1pct_recall", "op_0p1pct_recall", "cal_1pct_recall", "cal_1pct_fpr"]
    metrics += ["cal_0p1pct_recall", "cal_0p1pct_fpr"]
    g = rows.groupby(keys, sort=False)
    out = g[["n_urls", "n_domains", "n_pos", "n_neg"]].median()
    out["n_splits"] = g.size()
    for m in metrics:
        out[f"{m}_median"] = g[m].median()
        out[f"{m}_min"] = g[m].min()
        out[f"{m}_max"] = g[m].max()
    return out.reset_index()


def render(summary: pd.DataFrame, cfg: dict) -> str:
    lines = [
        "# Leave-one-source-out and per-source results (tier A)",
        "",
        "Generated by `python -m experiments.loso`. Do not edit by hand.",
        "Median over the listed splits [min, max]. `all_sources`: model trained on every pool",
        "source, scored on that source's rows in the test side. `leave_out`: model trained and",
        "calibrated without the source, scored on all of its rows. `cal` columns apply the",
        "thresholds chosen on the calibration side (1% and 0.1% FPR targets).",
        "Sources with only phishing rows have no FPR; read their `cal` recall.",
        "",
    ]
    for cond in ("all_sources", "leave_out"):
        part = summary[summary["condition"] == cond]
        lines += [
            f"## {cond}",
            "",
            "| source | model | URLs | domains | phishing | benign | ROC-AUC | recall @1% FPR "
            "| cal 1%: recall / FPR | cal 0.1%: recall / FPR |",
            "|---|---|---|---|---|---|---|---|---|---|",
        ]
        for _, r in part.iterrows():
            lines.append(
                f"| {r['source']} | {r['model']} | {int(r['n_urls']):,} | {int(r['n_domains']):,} "
                f"| {int(r['n_pos']):,} | {int(r['n_neg']):,} "
                f"| {_fmt(r['roc_auc_median'], False)} | {_fmt(r['op_1pct_recall_median'])} "
                f"| {_fmt(r['cal_1pct_recall_median'])} / {_fmt(r['cal_1pct_fpr_median'])} "
                f"| {_fmt(r['cal_0p1pct_recall_median'])} / {_fmt(r['cal_0p1pct_fpr_median'])} |"
            )
        lines.append("")
    trip = cfg["eval"]["leakage_tripwire"]
    hot = summary[
        (summary["condition"] == "leave_out")
        & ((summary["roc_auc_median"] > trip) | (summary["op_1pct_recall_median"] > trip))
    ]
    if not hot.empty:
        lines += [
            f"**Leakage tripwire:** {len(hot)} held-out source result(s) above {trip:.0%}: "
            + ", ".join(f"{r.source}/{r.model}" for r in hot.itertuples())
            + ". Investigate before reporting.",
            "",
        ]
    return "\n".join(lines)


def run(
    processed: Path,
    reports: Path,
    split_ids: list[int],
    cfg: dict | None = None,
    lists: Lists | None = None,
) -> Path:
    cfg = cfg or load_config("models")
    lists = lists or load_lists()
    tables = reports / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    out = tables / "loso.csv"
    done = set(pd.read_csv(out)["split"]) if out.exists() else set()
    pool = load_part(processed, PARTS[0], lists)
    splits = pd.read_parquet(processed / "splits.parquet")
    splits = pool[["uid"]].merge(splits, on="uid", how="left", validate="one_to_one")
    for k in split_ids:
        if k in done:
            log.info("split %d already in %s: skipped", k, out)
            continue
        _append(out, run_split(k, pool, splits, lists, cfg))
        summary = summarise(pd.read_csv(out))
        summary.to_csv(tables / "loso_summary.csv", index=False)
        (reports / "loso.md").write_text(render(summary, cfg), encoding="utf-8")
        log.info("split %d written", k)
    return reports / "loso.md"


def main(argv: list[str] | None = None) -> int:
    cfg = load_config("models")
    ap = argparse.ArgumentParser(prog="experiments.loso")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--splits", type=int, nargs="*", default=cfg["loso"]["splits"])
    ap.add_argument("--lists-dir", default=None)
    ap.add_argument("--platforms-file", default=None)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    lists = load_lists(a.lists_dir, a.platforms_file)
    print(run(a.processed, a.reports, a.splits, cfg=cfg, lists=lists))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
