"""Tier A (URL only) base learners over the 10 domain-grouped splits, plus the holdouts.

python -m experiments.tier_a [--processed data/processed] [--reports reports] [--splits 0 1 ...]

Inputs in ``--processed``: ``meta_<part>.parquet`` (uid, url, domain, label, source, depth,
weight; no HTML) and ``features_a[_<part>].parquet`` for part in pool, time_slice,
heldout_source, plus ``splits.parquet``.

Per split k, every model is trained on ``split_k == train`` only. Thresholds for the target
FPRs come from ``cal``. Metrics are reported on ``test``, on the held-out source and on the
time slice (neither is ever trained or calibrated on), on ``test`` with every URL replaced by
``https://www.<registrable domain>`` (representation check, L1), and per depth bucket of
``test`` (depth-matched view, L4). Shuffled-label controls (L11) retrain LightGBM and the char
n-gram model on permuted training labels. The two fitted tier A features (``tld_risk``,
``bigram_loglik_domain``) are refitted on each split's train side, so no test label leaks in.

Outputs in ``--reports``: ``tables/tier_a_runs.csv`` (one row per split, model and evaluation
set), ``tables/tier_a_summary.csv`` (median and range over splits), ``tables/tier_a_depth.csv``,
``tables/tier_a_controls.csv`` and ``tier_a.md``. Runs are appended after every split and
finished splits are skipped on a rerun, so a stopped run keeps its results.
"""

from __future__ import annotations

import argparse
import logging
import math
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from data_pipeline.split import CAL, TEST, TRAIN, LeakageError
from experiments.metrics import evaluate, operating_point
from features.extract import extract
from features.fit import Fitted, fit
from features.lists import Lists, load_lists
from features.registry import NAMES
from features.url_features import fitted_values
from features.urlparts import parse
from models.char_ngram import CharNgramLR
from models.gbdt import GBDT
from phishdrift.config import load_config
from phishdrift.domains import url_key

log = logging.getLogger("tier_a")
PARTS = ("pool", "time_slice", "heldout_source")
FITTED = ("bigram_loglik_domain", "tld_risk")
SUMMARY_METRICS = (
    "roc_auc",
    "pr_auc",
    "op_1pct_recall",
    "op_0p1pct_recall",
    "cal_1pct_recall",
    "cal_1pct_fpr",
    "cal_1pct_precision",
    "cal_1pct_f1",
    "cal_0p1pct_recall",
    "cal_0p1pct_fpr",
)


@dataclass(frozen=True)
class Spec:
    name: str  # lightgbm, xgboost, char_ngram
    features: str  # all, no_flagged, url_text


SPECS = (
    Spec("lightgbm", "all"),
    Spec("lightgbm", "no_flagged"),
    Spec("xgboost", "all"),
    Spec("xgboost", "no_flagged"),
    Spec("char_ngram", "url_text"),
)
CONTROL_SPECS = (Spec("lightgbm", "all"), Spec("char_ngram", "url_text"))


# --- loading ---------------------------------------------------------------------------


def load_part(processed: Path, part: str, lists: Lists) -> pd.DataFrame:
    """Metadata joined to the tier A features, with parsed URL parts and the dedup key."""
    meta = pd.read_parquet(processed / f"meta_{part}.parquet")
    feat_file = "features_a.parquet" if part == "pool" else f"features_a_{part}.parquet"
    feats = pd.read_parquet(processed / feat_file)
    df = meta.merge(feats, on="uid", how="inner", validate="one_to_one")
    if len(df) != len(meta):
        raise ValueError(f"{part}: {len(meta) - len(df)} rows have no tier A features")
    if "weight" not in df:
        df["weight"] = 1.0
    df["label"] = df["label"].astype(int)
    df["_parts"] = [parse(u, lists.platforms) for u in df["url"]]
    df["_text"] = [p.canon if p is not None else "" for p in df["_parts"]]
    df["_key"] = df["url"].map(url_key)
    return df.reset_index(drop=True)


def normalised_features(domains: pd.Series, lists: Lists) -> pd.DataFrame:
    """Tier A features of ``https://www.<domain>`` for each distinct domain (L1 check)."""
    uniq = pd.Index(domains.unique())
    urls = [f"https://www.{d}" for d in uniq]
    rows = [extract(u, lists=lists, fitted=Fitted()) for u in urls]
    out = pd.DataFrame(rows, columns=list(NAMES), index=uniq).astype("float32")
    out["_parts"] = [parse(u, lists.platforms) for u in urls]
    out["_text"] = [p.canon if p is not None else "" for p in out["_parts"]]
    return out


# --- leakage checks (hard failures) ----------------------------------------------------


def assert_no_overlap(a: pd.DataFrame, b: pd.DataFrame, name_a: str, name_b: str) -> None:
    dom = set(a["domain"]) & set(b["domain"])
    if dom:
        raise LeakageError(f"{len(dom)} domains in both {name_a} and {name_b}: {sorted(dom)[:5]}")
    keys = set(a["_key"]) & set(b["_key"])
    if keys:
        raise LeakageError(f"{len(keys)} URLs in both {name_a} and {name_b}: {sorted(keys)[:5]}")


# --- per split -------------------------------------------------------------------------


def refit(train: pd.DataFrame, lists: Lists) -> Fitted:
    data = fit(train["url"].tolist(), train["label"].tolist(), lists.platforms)
    return Fitted(**data)


def apply_fitted(df: pd.DataFrame, fitted: Fitted) -> pd.DataFrame:
    vals = [
        fitted_values(p, fitted) if p is not None else dict.fromkeys(FITTED, math.nan)
        for p in df["_parts"]
    ]
    out = df.copy()
    for name in FITTED:
        out[name] = np.array([v[name] for v in vals], dtype=np.float32)
    return out


def make_model(spec: Spec, cfg: dict):
    if spec.name == "char_ngram":
        return CharNgramLR(cfg["char_ngram"], cfg["seed"])
    flagged = set(cfg["source_flagged_features"])
    cols = [n for n in NAMES if spec.features == "all" or n not in flagged]
    return GBDT(spec.name, cfg[spec.name], cols, cfg["seed"])


def model_input(spec: Spec, df: pd.DataFrame):
    return df["_text"].tolist() if spec.name == "char_ngram" else df


def depth_bucket(depth: pd.Series, top: int) -> pd.Series:
    return depth.clip(upper=top).map(lambda d: f"{top}+" if d >= top else str(int(d)))


def run_split(
    k: int,
    pool: pd.DataFrame,
    splits: pd.DataFrame,
    holdouts: dict[str, pd.DataFrame],
    norm: pd.DataFrame,
    lists: Lists,
    cfg: dict,
) -> tuple[list[dict], list[dict], list[dict]]:
    ev = cfg["eval"]
    targets, min_neg = ev["target_fprs"], ev["min_negatives"]
    side = splits[f"split_{k}"].to_numpy()
    train, cal, test = (pool[side == s] for s in (TRAIN, CAL, TEST))
    assert_no_overlap(train, test, "train", "test")
    assert_no_overlap(train, cal, "train", "cal")
    assert_no_overlap(cal, test, "cal", "test")
    for name, h in holdouts.items():
        assert_no_overlap(train, h, "train", name)
        assert_no_overlap(cal, h, "cal", name)

    fitted = refit(train, lists)
    train, cal, test = (apply_fitted(f, fitted) for f in (train, cal, test))
    holdouts = {n: apply_fitted(h, fitted) for n, h in holdouts.items()}
    test_norm = test.drop_duplicates(["domain", "label"])[["domain", "label", "depth"]]
    norm_feats = apply_fitted(norm.loc[test_norm["domain"]].reset_index(drop=True), fitted)
    test_norm = pd.concat([test_norm.reset_index(drop=True), norm_feats], axis=1)

    eval_sets = {"test": test, **holdouts, "test_normalised": test_norm}
    y_train, w_train = train["label"].to_numpy(), train["weight"].to_numpy()
    runs, depth_rows, controls = [], [], []
    for spec in SPECS:
        t0 = time.monotonic()
        model = make_model(spec, cfg).fit(model_input(spec, train), y_train, w_train)
        s_cal = model.score(model_input(spec, cal))
        thresholds = {
            t: operating_point(cal["label"], s_cal, t, min_neg)["threshold"] for t in targets
        }
        base = {"split": k, "model": spec.name, "features": spec.features}
        for set_name, frame in eval_sets.items():
            s = model.score(model_input(spec, frame))
            row = evaluate(frame["label"], s, targets, min_neg, thresholds)
            runs.append(base | {"eval_set": set_name, "n_domains": frame["domain"].nunique()} | row)
            if set_name == "test":
                buckets = depth_bucket(frame["depth"], ev["depth_top_bucket"]).to_numpy()
                for b in sorted(set(buckets)):
                    m = buckets == b
                    r = evaluate(frame["label"].to_numpy()[m], s[m], targets, min_neg, thresholds)
                    depth_rows.append(base | {"depth": b} | r)
        log.info("split %d %s/%s: %.0fs", k, spec.name, spec.features, time.monotonic() - t0)

    # Controls are trained without sample weights. The per-(source, class) weights are heavy
    # tailed; with random labels a small tree leaf then usually holds no heavy row and scores
    # below average, so URLs in sparse regions of feature space (more often phishing) rank low
    # and the AUC drifts under 0.5 without any label information (0.43-0.45 on split 0).
    y_shuffled = np.random.default_rng(cfg["seed"] + k).permutation(y_train)
    for spec in CONTROL_SPECS:
        model = make_model(spec, cfg).fit(model_input(spec, train), y_shuffled)
        s = model.score(model_input(spec, test))
        row = evaluate(test["label"], s, targets, min_neg)
        controls.append({"split": k, "model": spec.name, "features": spec.features} | row)
    log.info("split %d controls done", k)
    return runs, depth_rows, controls


# --- reports ---------------------------------------------------------------------------


def summarise(runs: pd.DataFrame) -> pd.DataFrame:
    keys = ["model", "features", "eval_set"]
    metrics = [m for m in SUMMARY_METRICS if m in runs]
    g = runs.groupby(keys, sort=False)
    out = g[["n_urls", "n_domains", "n_pos", "n_neg"]].median()
    out["n_splits"] = g.size()
    for m in metrics:
        out[f"{m}_median"] = g[m].median()
        out[f"{m}_min"] = g[m].min()
        out[f"{m}_max"] = g[m].max()
    gran = [c for c in runs if c.endswith("_granularity_limited")]
    for c in gran:
        out[c] = g[c].any()
    return out.reset_index()


def _fmt(x: float, pct: bool = True) -> str:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "n/a"
    return f"{100 * x:.1f}" if pct else f"{x:.4f}"


def render_markdown(summary: pd.DataFrame, controls: pd.DataFrame, cfg: dict) -> str:
    ev = cfg["eval"]
    lines = [
        "# Tier A results (URL only)",
        "",
        "Generated by `python -m experiments.tier_a`. Do not edit by hand.",
        "Median over the domain-grouped splits, with [min, max] in brackets.",
        "`op` = operating point measured on the set itself (largest recall with FPR at or below",
        "the target); `cal` = threshold chosen on the calibration slice and applied to the set",
        "(what a deployed model does).",
        "Allowlist and blocklist layers are not involved: these are the models alone.",
        "",
    ]
    order = ["test", "heldout_source", "time_slice", "test_normalised"]
    for set_name in order:
        part = summary[summary["eval_set"] == set_name]
        if part.empty:
            continue
        r0 = part.iloc[0]
        lines += [
            f"## {set_name}",
            "",
            f"{int(r0['n_urls']):,} URLs, {int(r0['n_domains']):,} domains, "
            f"{int(r0['n_pos']):,} phishing, {int(r0['n_neg']):,} benign (median over splits).",
            "",
            "| model | features | ROC-AUC | PR-AUC | recall @1% FPR | recall @0.1% FPR "
            "| cal 1%: recall / FPR | cal 0.1%: recall / FPR |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for _, r in part.iterrows():

            def cell(m: str, pct: bool = True, row=r) -> str:
                return (
                    f"{_fmt(row[f'{m}_median'], pct)} "
                    f"[{_fmt(row[f'{m}_min'], pct)}, {_fmt(row[f'{m}_max'], pct)}]"
                )

            gl = "*" if r.get("op_0p1pct_granularity_limited", False) else ""
            lines.append(
                f"| {r['model']} | {r['features']} | {cell('roc_auc', False)} "
                f"| {cell('pr_auc', False)} | {cell('op_1pct_recall')} "
                f"| {cell('op_0p1pct_recall')}{gl} "
                f"| {_fmt(r['cal_1pct_recall_median'])} / {_fmt(r['cal_1pct_fpr_median'])} "
                f"| {_fmt(r['cal_0p1pct_recall_median'])} / {_fmt(r['cal_0p1pct_fpr_median'])} |"
            )
        lines.append("")
        if set_name in ("heldout_source", "time_slice"):
            hot = part[
                (part["roc_auc_median"] > ev["leakage_tripwire"])
                | (part["op_1pct_recall_median"] > ev["leakage_tripwire"])
            ]
            if not hot.empty:
                lines += [
                    f"**Leakage tripwire:** {len(hot)} model(s) score above "
                    f"{ev['leakage_tripwire']:.0%} here. Investigate before reporting.",
                    "",
                ]
    lines += [
        "`*` = the 0.1% point rests on fewer than "
        f"{ev['min_negatives']} negatives in at least one split.",
        "",
    ]
    if not controls.empty:
        c = controls.groupby(["model", "features"])["roc_auc"].agg(["mean", "min", "max"])
        lines += [
            "## Shuffled-label controls (test)",
            "",
            "| model | features | mean ROC-AUC | min | max | flagged |",
            "|---|---|---|---|---|---|",
        ]
        for (m, f), r in c.iterrows():
            flag = abs(r["mean"] - 0.5) > ev["shuffled_label_flag"]
            lines.append(
                f"| {m} | {f} | {r['mean']:.4f} | {r['min']:.4f} | {r['max']:.4f} "
                f"| {'YES' if flag else 'no'} |"
            )
        lines.append("")
    return "\n".join(lines)


def write_reports(reports: Path, cfg: dict) -> None:
    tables = reports / "tables"
    runs = pd.read_csv(tables / "tier_a_runs.csv")
    controls_path = tables / "tier_a_controls.csv"
    controls = pd.read_csv(controls_path) if controls_path.exists() else pd.DataFrame()
    summary = summarise(runs)
    summary.to_csv(tables / "tier_a_summary.csv", index=False)
    (reports / "tier_a.md").write_text(render_markdown(summary, controls, cfg), encoding="utf-8")


def _append(path: Path, rows: list[dict]) -> None:
    if not rows:
        return
    frame = pd.DataFrame(rows)
    frame.to_csv(path, mode="a", header=not path.exists(), index=False)


def run(
    processed: Path,
    reports: Path,
    split_ids: list[int] | None = None,
    cfg: dict | None = None,
    lists: Lists | None = None,
) -> Path:
    cfg = cfg or load_config("models")
    lists = lists or load_lists()
    tables = reports / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    runs_path = tables / "tier_a_runs.csv"
    done = set(pd.read_csv(runs_path)["split"]) if runs_path.exists() else set()
    for name in ("tier_a_depth.csv", "tier_a_controls.csv"):  # drop rows of an unfinished split
        path = tables / name
        if path.exists():
            kept = pd.read_csv(path)
            kept[kept["split"].isin(done)].to_csv(path, index=False)

    t0 = time.monotonic()
    frames = {p: load_part(processed, p, lists) for p in PARTS}
    pool = frames.pop("pool")
    splits = pd.read_parquet(processed / "splits.parquet")
    splits = pool[["uid"]].merge(splits, on="uid", how="left", validate="one_to_one")
    if splits.isna().any().any():
        raise ValueError("some pool rows have no split assignment")
    norm = normalised_features(pool["domain"], lists)
    log.info("loaded %d pool rows and holdouts in %.0fs", len(pool), time.monotonic() - t0)

    n_splits = sum(c.startswith("split_") for c in splits.columns)
    for k in split_ids if split_ids is not None else range(n_splits):
        if k in done:
            log.info("split %d already in %s: skipped", k, runs_path)
            continue
        runs, depth_rows, controls = run_split(k, pool, splits, frames, norm, lists, cfg)
        _append(tables / "tier_a_depth.csv", depth_rows)
        _append(tables / "tier_a_controls.csv", controls)
        _append(runs_path, runs)  # last: a split counts as done only once all its rows exist
        write_reports(reports, cfg)
        log.info("split %d written (%.0fs so far)", k, time.monotonic() - t0)
    return reports / "tier_a.md"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.tier_a")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--splits", type=int, nargs="*", default=None)
    ap.add_argument("--lists-dir", default=None, help="word lists (default configs/lists)")
    ap.add_argument("--platforms-file", default=None, help="default configs/platforms.yaml")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    lists = load_lists(a.lists_dir, a.platforms_file)
    print(run(a.processed, a.reports, a.splits, lists=lists))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
