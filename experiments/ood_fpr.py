"""Out-of-distribution false-positive rate on naturally browsed legitimate inner pages.

python -m experiments.ood_fpr --ood-csv data/raw/ood/ood_urls.csv [--processed ...] [--splits ...]

The URLs come from ``python -m collector crawl-ood`` (ordinary Tranco sites, head skipped, inner
pages, ``ok == True`` rows only). They are never trained or calibrated on. Per split k each model
is trained on the train side; the cal-side thresholds for target FPR 1% and 0.1% are applied to
the OOD URLs, and the share scored as phishing is the OOD FPR. A second threshold set comes from
the PhreshPhish part of the cal side only (its benign class is real browsing telemetry), which
shows how much of the gap is the threshold rather than the model.

Each split writes ``tables/ood_fpr_runs/split_<k>.csv`` (so splits run in parallel processes);
``ood_fpr.md`` is rebuilt from all of them. Finished splits are skipped on a rerun.
"""

from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

import numpy as np
import pandas as pd

from data_pipeline.split import CAL, TRAIN
from experiments.hybrid_a import make_hybrid
from experiments.metrics import operating_point
from experiments.tier_a import (
    SPECS,
    Spec,
    _fmt,
    apply_fitted,
    assert_no_overlap,
    load_part,
    make_model,
    model_input,
    refit,
)
from features.extract import extract
from features.fit import Fitted
from features.lists import Lists, load_lists
from features.registry import NAMES
from features.urlparts import parse
from phishdrift.config import load_config
from phishdrift.domains import url_depth, url_key

log = logging.getLogger("ood_fpr")

BROWSING_SOURCE = "phreshphish"
# hybrid2 and the page models are scored together with their blend in ``experiments.blend``.
MODELS = (  # (name, kind) kind: spec | hybrid variant
    ("lightgbm", Spec("lightgbm", "all")),
    ("xgboost", Spec("xgboost", "all")),
    ("char_ngram", SPECS[-1]),
    ("hybrid", "hybrid"),
)


def load_ood(csv: Path, lists: Lists) -> pd.DataFrame:
    """Usable OOD pages with tier A features (before the per-split fitted columns)."""
    raw = pd.read_csv(csv)
    raw = raw[raw["ok"].astype(str).str.lower() == "true"].drop_duplicates("url")
    rows = [extract(u, lists=lists, fitted=Fitted()) for u in raw["url"]]
    df = pd.DataFrame(rows, columns=list(NAMES)).astype("float32")
    df["url"] = raw["url"].to_numpy()
    df["domain"] = raw["domain"].astype(str).str.lower().to_numpy()
    df["label"] = 0
    df["depth"] = [url_depth(u) for u in df["url"]]
    df["_parts"] = [parse(u, lists.platforms) for u in df["url"]]
    df["_text"] = [p.canon if p is not None else "" for p in df["_parts"]]
    df["_key"] = df["url"].map(url_key)
    return df.reset_index(drop=True)


def run_split(k, pool, splits, ood, lists, cfg) -> list[dict]:
    targets, min_neg = cfg["eval"]["target_fprs"], cfg["eval"]["min_negatives"]
    side = splits[f"split_{k}"].to_numpy()
    train, cal = (pool[side == s] for s in (TRAIN, CAL))
    assert_no_overlap(train, ood, "train", "ood")
    assert_no_overlap(cal, ood, "cal", "ood")
    fitted = refit(train, lists)
    train, cal = (apply_fitted(f, fitted) for f in (train, cal))
    ood_k = apply_fitted(ood, fitted)
    y, w = train["label"].to_numpy(), train["weight"].to_numpy()
    browsing = (cal["source"] == BROWSING_SOURCE).to_numpy()
    depth = ood_k["depth"].to_numpy()
    rows = []
    for name, kind in MODELS:
        t0 = time.monotonic()
        if isinstance(kind, Spec):
            model = make_model(kind, cfg).fit(model_input(kind, train), y, w)
            score = lambda f, m=model, s=kind: m.score(model_input(s, f))  # noqa: E731
        else:
            model = make_hybrid(cfg, kind).fit(train, y, w)
            score = model.score
        s_cal, s_ood = score(cal), score(ood_k)
        for basis, mask in (("cal", np.ones(len(cal), bool)), ("cal_browsing", browsing)):
            for t in targets:
                thr = operating_point(cal["label"].to_numpy()[mask], s_cal[mask], t, min_neg)
                thr = thr["threshold"]
                row = {
                    "split": k,
                    "model": name,
                    "threshold_from": basis,
                    "target_fpr": t,
                    "threshold": thr,
                    "n_urls": len(ood_k),
                    "n_domains": ood_k["domain"].nunique(),
                }
                for label, m in (
                    ("all", np.ones(len(ood_k), bool)),
                    ("depth0", depth == 0),
                    ("depth1+", depth >= 1),
                ):
                    if m.any():
                        row[f"ood_fpr_{label}"] = float(np.mean(s_ood[m] >= thr))
                rows.append(row)
        log.info("split %d %s: %.0fs", k, name, time.monotonic() - t0)
    return rows


def render(runs: pd.DataFrame) -> str:
    first = runs.iloc[0]
    lines = [
        "# Out-of-distribution false-positive rate (naturally browsed legitimate inner pages)",
        "",
        "Generated by `python -m experiments.ood_fpr`. Do not edit by hand.",
        f"{int(first['n_urls']):,} pages from {int(first['n_domains']):,} sites that are in no",
        "training,",
        "calibration or held-out set. Share of these pages scored as phishing at the threshold",
        "for the target FPR. Median over splits [min, max]. `cal` thresholds come from the whole",
        "cal side; `cal_browsing` from the PhreshPhish part only (real browsing telemetry).",
        "",
        "| model | threshold from | target FPR | splits | OOD FPR (all) | OOD FPR (depth 1+) |",
        "|---|---|---|---|---|---|",
    ]
    for (model, basis, t), g in runs.groupby(["model", "threshold_from", "target_fpr"], sort=False):

        def cell(col, g=g):
            v = g[col]
            return f"{_fmt(v.median())} [{_fmt(v.min())}, {_fmt(v.max())}]"

        lines.append(
            f"| {model} | {basis} | {t:.1%} | {len(g)} | {cell('ood_fpr_all')} "
            f"| {cell('ood_fpr_depth1+')} |"
        )
    return "\n".join(lines + [""])


def write_reports(reports: Path) -> Path:
    parts = sorted((reports / "tables" / "ood_fpr_runs").glob("split_*.csv"))
    runs = pd.concat([pd.read_csv(p) for p in parts], ignore_index=True)
    runs.to_csv(reports / "tables" / "ood_fpr_runs.csv", index=False)
    out = reports / "ood_fpr.md"
    out.write_text(render(runs), encoding="utf-8")
    return out


def run(processed, reports, ood_csv, split_ids=None, cfg=None, lists=None) -> Path:
    cfg = cfg or load_config("models")
    lists = lists or load_lists()
    per_split = reports / "tables" / "ood_fpr_runs"
    per_split.mkdir(parents=True, exist_ok=True)
    pool = load_part(processed, "pool", lists)
    splits = pd.read_parquet(processed / "splits.parquet")
    splits = pool[["uid"]].merge(splits, on="uid", how="left", validate="one_to_one")
    ood = load_ood(ood_csv, lists)
    n_splits = sum(c.startswith("split_") for c in splits.columns)
    for k in split_ids if split_ids is not None else range(n_splits):
        out = per_split / f"split_{k}.csv"
        if out.exists():
            continue
        rows = run_split(k, pool, splits, ood, lists, cfg)
        tmp = out.with_suffix(".tmp")
        pd.DataFrame(rows).to_csv(tmp, index=False)
        tmp.replace(out)
        write_reports(reports)
        log.info("split %d written", k)
    return write_reports(reports)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.ood_fpr")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--ood-csv", type=Path, default=Path("data/raw/ood/ood_urls.csv"))
    ap.add_argument("--splits", type=int, nargs="*", default=None)
    ap.add_argument("--lists-dir", default=None)
    ap.add_argument("--platforms-file", default=None)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    lists = load_lists(a.lists_dir, a.platforms_file)
    print(run(a.processed, a.reports, a.ood_csv, a.splits, lists=lists))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
