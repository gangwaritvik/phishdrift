"""Tier C (domain / DNS / TLS at first-seen) over 10 registrable-domain-grouped splits.

python -m experiments.tier_c [--features data/processed/features_c.parquet] [--reports reports]
    [--with-a --processed DIR --lists-dir DIR --platforms-file FILE]

Input: the host-level table from ``python -m features build --tier C``. Eligible rows: label 0
or 1, not on a hosting platform, not an IP host, not answered by the collector PC's filtering
resolver, and still resolving at capture (a host that no longer resolves is mostly a taken-down
phishing page; keeping it would teach "dead = phishing"). Each filter's removals are reported
per class.

Per split k (domain-grouped train/cal/test, fractions in ``configs/models.yaml`` ``tier_c``):
LightGBM on every tier C feature, the same without the age features ("no age"), a trivial
baseline (younger domain = more suspicious; unknown age = most suspicious) and a shuffled-label
control. FPR thresholds come from cal and are applied to test; the test-side fixed-FPR operating
points are reported with the granularity flag.

``--with-a``: the tier A ``hybrid2`` model is trained once on the train and cal rows of split 0 of
the pool in ``--processed`` and scores every host as the bare URL ``https://<host>/`` (no path,
so neither class gets a depth advantage). Hosts whose registrable domain is anywhere in the pool,
time slice or held-out source are dropped first. Each split then adds "a_host" (that score
alone) and "c+a_host" (LightGBM on tier C plus the score).

Time check: with at least ``time_check.min_days`` distinct capture days, train on the older
days and test on the newest days (about ``time_check.test_fraction`` of rows), with test rows
whose domain is in train dropped.

Writes ``tables/tier_c_runs.csv`` (split x model), ``tables/tier_c_importance.csv``,
``tables/tier_c_filters.csv``, ``tables/tier_c_time.csv`` (when run) and ``tier_c.md``.
"""

from __future__ import annotations

import argparse
import logging
import math
from pathlib import Path

import numpy as np
import pandas as pd

from data_pipeline.split import (
    CAL,
    TEST,
    TRAIN,
    assert_disjoint,
    grouped_splits,
    random_domain_split,
)
from experiments.metrics import evaluate, fpr_tag, operating_point
from experiments.tier_a import _fmt
from features.lists import Lists, load_lists
from features.registry import NAMES_C, REGISTRY_C
from models.gbdt import GBDT
from phishdrift.config import load_config

log = logging.getLogger("tier_c")
MOST_SUSPICIOUS = 1e9  # baseline score for an unknown age: above minus any age in days
POOL_META = ("meta_pool.parquet", "meta_time_slice.parquet", "meta_heldout_source.parquet")
MAIN = ("lightgbm", "c_all")
CONTROL = ("lightgbm", "c_all_shuffled")
SUMMARY = (
    "roc_auc",
    "pr_auc",
    "op_1pct_recall",
    "op_0p1pct_recall",
    "cal_1pct_recall",
    "cal_1pct_fpr",
    "cal_0p1pct_recall",
    "cal_0p1pct_fpr",
)
CLASS_NAMES = {0: "benign", 1: "phishing"}


# --- data ------------------------------------------------------------------------------


def capture_lag_h(df: pd.DataFrame) -> pd.Series:
    """Hours from first seen (feed or benign draw) to the capture used; NaN when unknown."""
    first = pd.to_datetime(df["first_seen"], utc=True, errors="coerce")
    captured = pd.to_datetime(df["captured_at"], utc=True, errors="coerce")
    return (captured - first).dt.total_seconds() / 3600


def eligible(df: pd.DataFrame, max_lag_h: float | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """(eligible rows, removals per filter and class). Filters run in this order.
    ``max_lag_h``: drop hosts captured more than this many hours after they were first seen,
    so both classes are measured at the same age (a host re-captured a day later, e.g. after
    the PC's resolver blocked the first try, may already be suspended or taken down)."""
    steps = [
        ("label not 0/1", lambda d: ~d["label"].isin([0, 1])),
        ("hosting platform", lambda d: d["is_hosting_platform"].astype(bool)),
        ("IP host", lambda d: d["is_ip"].astype(bool)),
        ("filtered by the PC's resolver", lambda d: d["filtered"].astype(bool)),
        ("not resolving", lambda d: ~d["resolves"].fillna(False).astype(bool)),
    ]
    if max_lag_h is not None:
        steps.append(
            (
                f"captured more than {max_lag_h:g} h after first seen",
                lambda d: (capture_lag_h(d) > max_lag_h).fillna(False),
            ),
        )
    rows = []
    cur = df
    for name, drop in steps:
        mask = drop(cur).to_numpy()
        lab = cur.loc[mask, "label"]
        rows.append(
            {
                "filter": name,
                "benign": int((lab == 0).sum()),
                "phishing": int((lab == 1).sum()),
                "other": int((~lab.isin([0, 1])).sum()),
            }
        )
        cur = cur[~mask]
    out = cur.copy()
    out["label"] = out["label"].astype(int)
    out["url"] = "https://" + out["host"] + "/"  # dedup key for the split checks
    return out.reset_index(drop=True), pd.DataFrame(rows)


def class_counts(df: pd.DataFrame) -> pd.DataFrame:
    g = df.groupby("label")
    return pd.DataFrame({"hosts": g.size(), "domains": g["domain"].nunique()}).rename(
        index=CLASS_NAMES
    )


def pool_domains(processed: Path) -> set[str]:
    out: set[str] = set()
    for name in POOL_META:
        path = processed / name
        if path.exists():
            out |= set(pd.read_parquet(path, columns=["domain"])["domain"].astype(str).str.lower())
    return out


def a_host_scores(df: pd.DataFrame, processed: Path, lists: Lists, cfg: dict) -> np.ndarray:
    """Tier A hybrid2 score of ``https://<host>/``, trained on split 0's train+cal pool rows."""
    from experiments.hybrid_a import make_hybrid
    from experiments.tier_a import apply_fitted, load_part, refit
    from features.extract import extract
    from features.registry import NAMES
    from features.urlparts import parse

    pool = load_part(processed, "pool", lists)
    splits = pd.read_parquet(processed / "splits.parquet", columns=["uid", "split_0"])
    side = pool[["uid"]].merge(splits, on="uid", how="left", validate="one_to_one")["split_0"]
    train = pool[(side != TEST).to_numpy()]
    fitted = refit(train, lists)
    train = apply_fitted(train, fitted)
    model = make_hybrid(cfg, "hybrid2").fit(
        train, train["label"].to_numpy(), train["weight"].to_numpy()
    )
    urls = df["url"].tolist()
    frame = pd.DataFrame(
        [extract(u, lists=lists, fitted=fitted) for u in urls], columns=list(NAMES)
    ).astype("float32")
    frame["_parts"] = [parse(u, lists.platforms) for u in urls]
    frame["domain"] = df["domain"].to_numpy()
    return model.score(frame)


# --- models ----------------------------------------------------------------------------


def baseline_score(frame: pd.DataFrame) -> np.ndarray:
    age = frame["domain_age_days"].to_numpy(dtype=float)
    return np.where(np.isnan(age), MOST_SUSPICIOUS, -age)


def model_specs(cc: dict, with_a: bool) -> list[tuple[str, str, list[str] | None]]:
    """(model, features, columns); columns None = the age baseline, which is not trained."""
    no_age = [n for n in NAMES_C if n not in set(cc["no_age_drop"])]
    specs = [
        (*MAIN, list(NAMES_C)),
        ("lightgbm", "c_no_age", no_age),
        ("baseline", "domain_age_days", None),
    ]
    if with_a:
        specs += [
            ("a_host", "hybrid2_bare_host", ["a_host"]),
            ("lightgbm", "c+a_host", [*NAMES_C, "a_host"]),
        ]
    return specs


def fit_score(
    spec: tuple[str, str, list[str] | None],
    train: pd.DataFrame,
    y: np.ndarray,
    frames: list[pd.DataFrame],
    cc: dict,
    seed: int,
) -> tuple[list[np.ndarray], GBDT | None]:
    model, features, cols = spec
    if cols is None:
        return [baseline_score(f) for f in frames], None
    if model == "a_host":
        return [f["a_host"].to_numpy(dtype=float) for f in frames], None
    gbdt = GBDT("lightgbm", cc["lightgbm"], cols, seed).fit(train, y)
    return [gbdt.score(f) for f in frames], gbdt


def check_split(df: pd.DataFrame, side: pd.Series) -> None:
    """Hard failure on any registrable domain or URL shared by train, cal and test."""
    assert_disjoint(df, side, (TRAIN, CAL, TEST))


def score_sets(
    spec: tuple[str, str, list[str] | None],
    train: pd.DataFrame,
    cal: pd.DataFrame,
    test: pd.DataFrame,
    cc: dict,
    seed: int,
    targets: list[float],
    min_neg: int,
) -> tuple[dict, GBDT | None]:
    """Fit on train, thresholds on cal, metrics on test (one row)."""
    (s_cal, s_test), gbdt = fit_score(spec, train, train["label"].to_numpy(), [cal, test], cc, seed)
    thresholds, row = {}, {}
    for t in targets:
        op = operating_point(cal["label"], s_cal, t, min_neg)
        row[f"cal_{fpr_tag(t)}_threshold"] = op["threshold"]
        row[f"cal_{fpr_tag(t)}_granularity_limited"] = op["granularity_limited"]
        if not math.isnan(op["threshold"]):
            thresholds[t] = op["threshold"]
    row |= evaluate(test["label"], s_test, targets, min_neg, thresholds)
    row |= {"n_domains": test["domain"].nunique(), "cal_n_neg": int((cal["label"] == 0).sum())}
    return row, gbdt


def run_split(
    k: int, df: pd.DataFrame, side: pd.Series, cfg: dict, with_a: bool
) -> tuple[list[dict], list[dict]]:
    cc, ev = cfg["tier_c"], cfg["eval"]
    targets, min_neg = ev["target_fprs"], ev["min_negatives"]
    check_split(df, side)
    train, cal, test = (df[(side == s).to_numpy()] for s in (TRAIN, CAL, TEST))
    seed = cc["seed"] + k
    base = {"split": k, "n_train": len(train)}
    runs, importance = [], []
    for spec in model_specs(cc, with_a):
        row, gbdt = score_sets(spec, train, cal, test, cc, seed, targets, min_neg)
        runs.append(base | {"model": spec[0], "features": spec[1]} | row)
        if gbdt is not None and spec[:2] == MAIN:
            gain = gbdt.model.booster_.feature_importance(importance_type="gain")
            total = gain.sum() or 1.0
            importance += [
                {"split": k, "feature": n, "gain": float(g), "gain_share": float(g / total)}
                for n, g in zip(gbdt.columns, gain, strict=True)
            ]
    y_shuffled = np.random.default_rng(seed).permutation(train["label"].to_numpy())
    gbdt = GBDT("lightgbm", cc["lightgbm"], list(NAMES_C), seed).fit(train, y_shuffled)
    row = evaluate(test["label"], gbdt.score(test), targets, min_neg)
    row |= {"n_domains": test["domain"].nunique(), "cal_n_neg": int((cal["label"] == 0).sum())}
    runs.append(base | {"model": CONTROL[0], "features": CONTROL[1]} | row)
    return runs, importance


def time_check(df: pd.DataFrame, cfg: dict, with_a: bool) -> tuple[pd.DataFrame | None, str]:
    """Older capture days -> newest days. Returns (rows or None, one-line description)."""
    cc, ev = cfg["tier_c"], cfg["eval"]
    tc = cc["time_check"]
    day = df["captured_at"].dt.strftime("%Y-%m-%d")
    days = sorted(day.dropna().unique())
    if len(days) < tc["min_days"]:
        return None, (
            f"Time check skipped: the eligible rows span {len(days)} capture day(s), "
            f"fewer than {tc['min_days']}."
        )
    per_day = day.value_counts()
    test_days: list[str] = []
    for d in reversed(days[1:]):  # at least the oldest day stays in train
        test_days.append(d)
        if per_day[test_days].sum() >= tc["test_fraction"] * len(df):
            break
    is_test = day.isin(test_days).to_numpy()
    older = df[~is_test]
    newest = df[is_test]
    dropped = newest["domain"].isin(set(older["domain"]))
    newest = newest[~dropped.to_numpy()]
    cal_side = random_domain_split(older, cc["cal_fraction"], cc["seed"])
    train, cal = older[(cal_side == TRAIN).to_numpy()], older[(cal_side == TEST).to_numpy()]
    parts = pd.Series([TRAIN] * len(train) + [CAL] * len(cal) + [TEST] * len(newest), dtype=object)
    check_split(pd.concat([train, cal, newest], ignore_index=True), parts)
    targets, min_neg = ev["target_fprs"], ev["min_negatives"]
    rows = []
    for spec in model_specs(cc, with_a):
        row, _ = score_sets(spec, train, cal, newest, cc, cc["seed"], targets, min_neg)
        rows.append({"model": spec[0], "features": spec[1]} | row)
    desc = (
        f"Time check: train/cal on {len(days) - len(test_days)} older capture day(s) "
        f"({len(older):,} hosts), test on the newest {len(test_days)} day(s) "
        f"({', '.join(sorted(test_days))}): {len(newest):,} hosts after dropping "
        f"{int(dropped.sum()):,} whose registrable domain is in the older days."
    )
    return pd.DataFrame(rows), desc


# --- report ----------------------------------------------------------------------------


def summarise(runs: pd.DataFrame) -> pd.DataFrame:
    g = runs.groupby(["model", "features"], sort=False)
    out = g[["n_urls", "n_domains", "n_pos", "n_neg", "cal_n_neg"]].median()
    out["n_splits"] = g.size()
    for m in SUMMARY:
        col = runs[m] if m in runs else pd.Series(np.nan, index=runs.index)
        grouped = col.groupby([runs["model"], runs["features"]], sort=False)
        out[f"{m}_median"], out[f"{m}_min"], out[f"{m}_max"] = (
            grouped.median(),
            grouped.min(),
            grouped.max(),
        )
    for c in [c for c in runs if c.endswith("_granularity_limited")]:
        out[c] = g[c].apply(lambda s: bool(s.fillna(False).astype(bool).any()))
    return out.reset_index()


def _cell(r: pd.Series, m: str, pct: bool = True) -> str:
    return f"{_fmt(r[f'{m}_median'], pct)} [{_fmt(r[f'{m}_min'], pct)}, {_fmt(r[f'{m}_max'], pct)}]"


def _counts_lines(eligible_df: pd.DataFrame) -> list[str]:
    lines = ["| class | hosts | registrable domains | hosts per domain |", "|---|---|---|---|"]
    for name, r in class_counts(eligible_df).iterrows():
        lines.append(
            f"| {name} | {r['hosts']:,} | {r['domains']:,} | {r['hosts'] / r['domains']:.2f} |"
        )
    return lines


def _filter_lines(filters: pd.DataFrame) -> list[str]:
    lines = [
        "| filter (in order) | benign removed | phishing removed | other |",
        "|---|---|---|---|",
    ]
    for _, r in filters.iterrows():
        lines.append(f"| {r['filter']} | {r['benign']:,} | {r['phishing']:,} | {r['other']:,} |")
    return lines


CAVEATS = [
    "## Caveats",
    "",
    "- Benign hosts are sampled from Tranco-listed sites, so they are older and more established "
    "than the average legitimate site; registration-age and DNS-hygiene features look better "
    "here than they will on the long tail of small legitimate sites.",
    "- With a few thousand negatives, a 0.1% FPR point rests on a handful of false positives "
    "(granularity-limited); treat it as unmeasured.",
    "- There is no second live source to hold out, so there is no leave-one-source-out result "
    "for tier C.",
    "- Phishing on hosting platforms (removed here) and on compromised old domains is outside "
    "tier C: their registration, DNS and certificate belong to a legitimate owner.",
    "- Capture happens hours after a feed lists a host, so some phishing domains are already "
    "suspended (`rdap_client_hold`) or re-captured after a filtered first attempt; a deployed "
    "check sees the host earlier.",
    "- `rdap_found = 0` mostly means rdap.org has no server for the TLD (many ccTLDs), so it "
    "partly encodes the TLD.",
    "- Benign hosts arrive as `<domain>` and `www.<domain>` pairs while phishing hosts are "
    "mostly subdomains, so host-form features such as `has_cname` can separate the classes "
    "by collection method; its importance is shown above.",
    "",
]


def render(
    filters: pd.DataFrame,
    eligible_df: pd.DataFrame,
    cfg: dict,
    summary: pd.DataFrame | None = None,
    importance: pd.DataFrame | None = None,
    time_rows: pd.DataFrame | None = None,
    time_desc: str = "",
    notes: list[str] | None = None,
    reason: str | None = None,
    control: list[str] | None = None,
) -> str:
    ev = cfg["eval"]
    lines = ["# Tier C results (domain / DNS / TLS at first-seen)", ""]
    trained = summary[summary["features"] != CONTROL[1]] if summary is not None else None
    if trained is not None and (trained["roc_auc_median"] > ev["leakage_tripwire"]).any():
        hot = trained[trained["roc_auc_median"] > ev["leakage_tripwire"]]
        lines += [
            f"**Leakage tripwire: median test ROC-AUC above {ev['leakage_tripwire']:.2f} for "
            f"{', '.join(hot['model'] + '/' + hot['features'])}. Investigate before reporting.**",
            "",
        ]
    lines += [
        "Generated by `python -m experiments.tier_c`. Do not edit by hand.",
        "Rows are hosts (one per host, latest capture). Hosts outnumber registrable domains: "
        "a domain's hosts always stay on one side of a split.",
        "",
        "## Rows",
        "",
        *_filter_lines(filters),
        "",
        "Eligible:",
        "",
        *_counts_lines(eligible_df),
        "",
    ]
    for n in notes or []:
        lines += [n, ""]
    if reason is not None:
        return "\n".join(lines + [f"**Not trained:** {reason}", "", *CAVEATS])
    lines += [
        "## Test results",
        "",
        f"Median over {int(summary['n_splits'].max())} registrable-domain-grouped splits "
        "[min, max]. `op` = operating point on the test side itself (largest recall with FPR at "
        "or below the target); `cal` = threshold chosen on the cal side and applied to test. "
        "`*` = granularity-limited (the FPR budget allows fewer than "
        f"{ev['min_negatives']} false positives) in at least one split.",
        "",
        "| model | features | test hosts / domains | pos / neg | ROC-AUC | PR-AUC "
        "| recall @1% FPR | recall @0.1% FPR | cal 1%: recall / FPR | cal 0.1%: recall / FPR |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for _, r in summary.iterrows():
        g1 = "*" if r.get("op_1pct_granularity_limited", False) else ""
        g01 = "*" if r.get("op_0p1pct_granularity_limited", False) else ""
        lines.append(
            f"| {r['model']} | {r['features']} | {int(r['n_urls']):,} / {int(r['n_domains']):,} "
            f"| {int(r['n_pos']):,} / {int(r['n_neg']):,} | {_cell(r, 'roc_auc', False)} "
            f"| {_cell(r, 'pr_auc', False)} | {_cell(r, 'op_1pct_recall')}{g1} "
            f"| {_cell(r, 'op_0p1pct_recall')}{g01} "
            f"| {_fmt(r['cal_1pct_recall_median'])} / {_fmt(r['cal_1pct_fpr_median'])} "
            f"| {_fmt(r['cal_0p1pct_recall_median'])} / {_fmt(r['cal_0p1pct_fpr_median'])} |"
        )
    cal_neg = int(summary["cal_n_neg"].median())
    lines += [
        "",
        f"Cal side: median {cal_neg:,} benign hosts per split, so the thresholds allow "
        + ", ".join(
            f"{math.floor(t * cal_neg)} false positive(s) at {t:.1%} FPR" for t in ev["target_fprs"]
        )
        + " there.",
        "",
        *(control or []),
        "",
    ]
    if importance is not None and not importance.empty:
        top = importance.head(15)
        lines += [
            "## Feature importance (main model, gain share averaged over splits)",
            "",
            "| feature | group | gain share |",
            "|---|---|---|",
            *(
                f"| `{r['feature']}` | {r['group']} | {100 * r['gain_share_mean']:.1f}% |"
                for _, r in top.iterrows()
            ),
            "",
        ]
        cname = importance[importance["feature"] == "has_cname"]
        if not cname.empty:
            r = cname.iloc[0]
            lines += [
                f"`has_cname` (host-form sensitive): gain share {100 * r['gain_share_mean']:.1f}%, "
                f"rank {int(r['rank'])} of {len(importance)}.",
                "",
            ]
    lines += ["## Time check", "", time_desc, ""]
    if time_rows is not None and not time_rows.empty:
        lines += [
            "| model | features | hosts / domains | pos / neg | ROC-AUC | recall @1% FPR "
            "| cal 1%: recall / FPR |",
            "|---|---|---|---|---|---|---|",
        ]
        for _, r in time_rows.iterrows():
            gl = "*" if r.get("op_1pct_granularity_limited", False) else ""
            lines.append(
                f"| {r['model']} | {r['features']} | {r['n_urls']:,} / {r['n_domains']:,} "
                f"| {r['n_pos']:,} / {r['n_neg']:,} | {_fmt(r['roc_auc'], False)} "
                f"| {_fmt(r['op_1pct_recall'])}{gl} "
                f"| {_fmt(r.get('cal_1pct_recall', math.nan))} / "
                f"{_fmt(r.get('cal_1pct_fpr', math.nan))} |"
            )
        lines.append("")
    return "\n".join(lines + CAVEATS)


def control_lines(runs: pd.DataFrame, flag: float) -> list[str]:
    ctrl = runs[runs["features"] == CONTROL[1]]["roc_auc"]
    if ctrl.empty:
        return []
    mean = float(ctrl.mean())
    flagged = abs(mean - 0.5) > flag
    return [
        f"Shuffled-label control (labels permuted within train): mean test ROC-AUC {mean:.4f} "
        f"[{ctrl.min():.4f}, {ctrl.max():.4f}] over {len(ctrl)} splits; "
        f"{'**FLAGGED**' if flagged else 'not flagged'} (flag rule: |mean - 0.5| > {flag})."
    ]


def average_importance(imp: pd.DataFrame) -> pd.DataFrame:
    if imp.empty:
        return imp
    groups = {f.name: f.group for f in REGISTRY_C}
    out = (
        imp.groupby("feature")
        .agg(gain_mean=("gain", "mean"), gain_share_mean=("gain_share", "mean"))
        .sort_values("gain_share_mean", ascending=False)
        .reset_index()
    )
    out.insert(1, "group", out["feature"].map(groups).fillna("tier A score"))
    out["rank"] = np.arange(1, len(out) + 1)
    return out


# --- run -------------------------------------------------------------------------------


def run(
    features: Path,
    reports: Path,
    cfg: dict | None = None,
    with_a: bool = False,
    processed: Path | None = None,
    lists: Lists | None = None,
) -> Path:
    cfg = cfg or load_config("models")
    cc = cfg["tier_c"]
    tables = reports / "tables"
    tables.mkdir(parents=True, exist_ok=True)
    out_md = reports / "tier_c.md"
    df, filters = eligible(pd.read_parquet(features), cc.get("max_capture_lag_h"))
    notes: list[str] = []
    if with_a:
        if processed is None:
            raise ValueError("--with-a needs --processed")
        seen = pool_domains(processed)
        drop = df["domain"].isin(seen).to_numpy()
        lab = df.loc[drop, "label"]
        filters = pd.concat(
            [
                filters,
                pd.DataFrame(
                    [
                        {
                            "filter": "domain in the tier A pool (--with-a)",
                            "benign": int((lab == 0).sum()),
                            "phishing": int((lab == 1).sum()),
                            "other": 0,
                        }
                    ]
                ),
            ],
            ignore_index=True,
        )
        df = df[~drop].reset_index(drop=True)
    filters.to_csv(tables / "tier_c_filters.csv", index=False)
    lag = (df["captured_at"] - df["first_seen"]).dt.total_seconds() / 3600
    for lab, name in CLASS_NAMES.items():
        m = (df["label"] == lab).to_numpy()
        if m.any() and lag[m].notna().any():
            notes.append(
                f"Median hours from first seen in a feed to the capture used ({name}): "
                f"{lag[m].median():.1f}."
            )
    n_pos, n_neg = int((df["label"] == 1).sum()), int((df["label"] == 0).sum())
    reason = None
    if n_neg == 0:
        reason = "no eligible benign hosts, so no model can be trained or measured."
    elif min(n_pos, n_neg) < cc["min_rows_per_class"]:
        reason = (
            f"fewer than {cc['min_rows_per_class']} eligible hosts in a class "
            f"({n_pos} phishing, {n_neg} benign)."
        )
    if reason is not None:
        out_md.write_text(render(filters, df, cfg, notes=notes, reason=reason), encoding="utf-8")
        log.info("not trained: %s", reason)
        return out_md

    if with_a:
        df["a_host"] = a_host_scores(df, processed, lists or load_lists(), cfg)
    splits = grouped_splits(df, cc["n_splits"], cc["test_fraction"], cc["cal_fraction"], cc["seed"])
    runs, imp = [], []
    for k in range(cc["n_splits"]):
        r, i = run_split(k, df, splits[f"split_{k}"], cfg, with_a)
        runs += r
        imp += i
        log.info("split %d done", k)
    runs_df = pd.DataFrame(runs)
    runs_df.to_csv(tables / "tier_c_runs.csv", index=False)
    importance = average_importance(pd.DataFrame(imp))
    importance.to_csv(tables / "tier_c_importance.csv", index=False)
    time_rows, time_desc = time_check(df, cfg, with_a)
    if time_rows is not None:
        time_rows.to_csv(tables / "tier_c_time.csv", index=False)
    md = render(
        filters,
        df,
        cfg,
        summarise(runs_df),
        importance,
        time_rows,
        time_desc,
        notes=notes,
        control=control_lines(runs_df, cfg["eval"]["shuffled_label_flag"]),
    )
    out_md.write_text(md, encoding="utf-8")
    return out_md


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.tier_c")
    ap.add_argument("--features", type=Path, default=Path("data/processed/features_c.parquet"))
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--with-a", action="store_true", help="add the tier A bare-host score")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--lists-dir", default=None)
    ap.add_argument("--platforms-file", default=None)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    lists = load_lists(a.lists_dir, a.platforms_file) if a.with_a else None
    print(run(a.features, a.reports, with_a=a.with_a, processed=a.processed, lists=lists))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
