"""Do the cal-side FPR thresholds transfer to data they never saw? Five threshold rules compared.

python -m experiments.threshold_transfer [--processed data/processed] [--reports reports]
    [--splits ...] [--loso-splits ...] [--setting main loso] [--ood-csv ood_urls.csv]
    [--cache data/interim/threshold_transfer] [--loso-model hybrid2|lightgbm]

The address model (tier A ``hybrid2``, ``experiments.hybrid_a.make_hybrid``) takes its
suspicious / dangerous thresholds at the pooled calibration slice's 1% / 0.1% FPR point. On data
from other sources that point does not hold (held-out PhishStorm about 4.8% at "1%", leaving
PhreshPhish out about 20%). Rules compared, each fitted on the cal side only:

- ``pooled``: the current rule, ``experiments.metrics.operating_point`` on all cal rows;
- ``worst_source``: ``experiments.blend2.worst_source_threshold`` (highest per-source cal point
  among sources with enough negatives for the target), never below ``pooled``;
- ``balanced``: the FPR point on cal where every source's legitimate rows carry equal total
  weight (sources with fewer than ``balanced_min_negatives`` cal negatives get none), so the
  biggest source no longer sets the pooled FPR;
- ``ucb_binom``: per source, the lowest threshold whose one-sided Clopper-Pearson upper bound
  (``confidence``) on the false-positive rate is at or below the target; sources too small to
  certify the target even with zero false positives are skipped instead of driving the
  threshold; the result is the highest of those and the pooled bound. Assumes independent
  URLs, but URLs cluster by domain (up to 20 per domain), so the bound is optimistic;
- ``ucb_boot``: per source with enough negatives (same rule as ``worst_source``), its threshold
  in ``n_bootstrap`` resamples of its legitimate *domains*, taking the ``confidence`` quantile;
  the highest over sources and ``pooled``. Respects the domain clustering.
- ``oracle_source`` (reference only, test per source): each source's own cal point. Not usable
  at runtime, where the source of a live URL is unknown; it is an upper bound.

Settings:
- ``main``: per split k (10 domain-grouped splits), the model is trained on the train side,
  rules are fitted on the cal side and applied to test (pooled and per source), the held-out
  source, the newest time slice and, with ``--ood-csv``, the naturally browsed legitimate pages.
- ``loso``: per split k in ``loso.splits`` and per source S with both classes, the model is
  trained and the rules fitted on the train / cal sides without S (``experiments.loso``'s
  protocol) and applied to every row of S.

Model scores are cached per unit under ``cache_dir`` (training is skipped when present); result
rows are written one file per unit to ``reports/tables/threshold_transfer_runs/`` (units can run
in parallel processes with ``PHISHDRIFT_THREADS=1``), and the report is rebuilt from all of them.
"""

from __future__ import annotations

import argparse
import logging
import math
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import beta

from data_pipeline.split import CAL, TEST, TRAIN
from experiments.blend2 import worst_source_threshold
from experiments.hybrid_a import make_hybrid
from experiments.metrics import at_threshold, operating_point
from experiments.tier_a import (
    PARTS,
    Spec,
    _fmt,
    apply_fitted,
    assert_no_overlap,
    load_part,
    make_model,
    refit,
)
from features.lists import Lists, load_lists
from phishdrift.config import load_config

log = logging.getLogger("threshold_transfer")

RULES = ("pooled", "worst_source", "balanced", "ucb_binom", "ucb_boot")
ORACLE = "oracle_source"
NO_ALARM = float(np.finfo(np.float64).max)  # threshold above every score (as operating_point)
RUNS = "threshold_transfer_runs"
SCORE_COLS = ["part", "source", "domain", "label", "score"]


# --- threshold rules ---------------------------------------------------------------------------


def threshold_at(
    y: np.ndarray,
    score: np.ndarray,
    target: float,
    neg_weight: np.ndarray | None = None,
    max_fp: float | None = None,
) -> float:
    """``operating_point``'s threshold with weighted negatives.

    Candidates are the distinct scores. A candidate is feasible when the weight of negatives
    scoring at or above it is at most ``max_fp`` (default ``target`` times the total negative
    weight). Among feasible candidates the one with the most positives at or above it wins,
    ties going to the higher threshold, as in ``operating_point``. With unit weights the two
    agree. Nothing feasible: ``NO_ALARM``.
    """
    y = np.asarray(y).astype(int)
    s = np.asarray(score, dtype=float)
    neg = y == 0
    w = np.ones(int(neg.sum())) if neg_weight is None else np.asarray(neg_weight, dtype=float)
    total = float(w.sum())
    budget = target * total if max_fp is None else float(max_fp)
    cand = np.unique(s)
    order = np.argsort(s[neg], kind="stable")
    sn = s[neg][order]
    cum = np.concatenate([[0.0], np.cumsum(w[order])])
    neg_above = total - cum[np.searchsorted(sn, cand, side="left")]
    sp = np.sort(s[~neg])
    pos_above = len(sp) - np.searchsorted(sp, cand, side="left")
    ok = neg_above <= budget + 1e-9 * max(total, 1.0)
    if not ok.any():
        return NO_ALARM
    best = pos_above[ok].max()
    return float(cand[ok & (pos_above == best)].max())


def pooled_threshold(y, score, target, min_neg) -> float:
    return operating_point(y, score, target, min_neg)["threshold"]


def balanced_threshold(cal: pd.DataFrame, score, target, min_source_neg) -> tuple[float, str]:
    """FPR point where each source with ``>= min_source_neg`` cal negatives weighs the same."""
    y = cal["label"].to_numpy().astype(int)
    src = cal["source"].to_numpy()
    neg_src = src[y == 0]
    counts = pd.Series(neg_src).value_counts()
    keep = counts[counts >= min_source_neg]
    if keep.empty:  # no source big enough to weigh: same as pooled
        return threshold_at(y, score, target), "pooled (no source eligible)"
    w = np.array([1.0 / keep[s] if s in keep.index else 0.0 for s in neg_src])
    return threshold_at(y, score, target, w), ",".join(sorted(keep.index))


def cp_upper(k: np.ndarray | int, n: int, confidence: float) -> np.ndarray:
    """One-sided Clopper-Pearson upper bound on a rate from ``k`` events in ``n`` trials."""
    k = np.asarray(k, dtype=float)
    out = beta.ppf(confidence, k + 1, np.maximum(n - k, 1e-12))
    return np.where(k >= n, 1.0, out)


def max_false_positives(n: int, target: float, confidence: float) -> int:
    """Largest false-positive count whose upper bound is <= target; -1 if even 0 is too many."""
    if n <= 0:
        return -1
    ks = np.arange(0, math.floor(target * n) + 1)
    ok = np.flatnonzero(cp_upper(ks, n, confidence) <= target)
    return int(ok[-1]) if len(ok) else -1


def _with_pos(y, s, m):
    """Rows of mask ``m`` that are negative, plus every positive (candidate thresholds)."""
    sel = (m & (y == 0)) | (y == 1)
    return y[sel], s[sel], sel


def ucb_binom_threshold(cal: pd.DataFrame, score, target, confidence) -> tuple[float, str]:
    y = cal["label"].to_numpy().astype(int)
    s = np.asarray(score, dtype=float)
    k_all = max_false_positives(int((y == 0).sum()), target, confidence)
    best = threshold_at(y, s, target, max_fp=k_all) if k_all >= 0 else NO_ALARM
    who = "pooled"
    for src, idx in cal.groupby("source").indices.items():
        m = np.zeros(len(y), bool)
        m[idx] = True
        n = int((m & (y == 0)).sum())
        k = max_false_positives(n, target, confidence)
        if k < 0:
            continue  # too few negatives to certify the target: no say
        yy, ss, _ = _with_pos(y, s, m)
        t = threshold_at(yy, ss, target, max_fp=k)
        if t > best:
            best, who = t, src
    return best, (who if best < NO_ALARM else "uncertifiable (cal too small)")


def ucb_boot_threshold(
    cal: pd.DataFrame, score, target, confidence, n_boot, min_neg, seed
) -> tuple[float, str]:
    y = cal["label"].to_numpy().astype(int)
    s = np.asarray(score, dtype=float)
    best, who = pooled_threshold(y, s, target, min_neg), "pooled"
    rng = np.random.default_rng(seed)
    for src, idx in sorted(cal.groupby("source").indices.items()):
        m = np.zeros(len(y), bool)
        m[idx] = True
        neg = m & (y == 0)
        if math.floor(target * neg.sum()) < min_neg:
            continue
        yy, ss, sel = _with_pos(y, s, m)
        dom_codes, doms = pd.factorize(cal["domain"].to_numpy()[sel & (y == 0)])
        thr = np.empty(n_boot)
        for b in range(n_boot):
            draw = np.bincount(rng.integers(0, len(doms), len(doms)), minlength=len(doms))
            thr[b] = threshold_at(yy, ss, target, neg_weight=draw[dom_codes].astype(float))
        t = float(np.quantile(thr, confidence, method="higher"))
        if t > best:
            best, who = t, src
    return best, who


def rule_thresholds(cal: pd.DataFrame, score, targets, tcfg: dict, min_neg: int) -> list[dict]:
    """One row per (rule, target): the threshold and the source that sets it."""
    y = cal["label"].to_numpy().astype(int)
    s = np.asarray(score, dtype=float)
    rows = []
    for i, t in enumerate(targets):
        pooled = pooled_threshold(y, s, t, min_neg)
        ws, ws_src = worst_source_threshold(cal, s, t, min_neg)
        found = {
            "pooled": (pooled, "pooled"),
            "worst_source": (max(pooled, ws), ws_src if ws > pooled else "pooled"),
            "balanced": balanced_threshold(cal, s, t, tcfg["balanced_min_negatives"]),
            "ucb_binom": ucb_binom_threshold(cal, s, t, tcfg["confidence"]),
            "ucb_boot": ucb_boot_threshold(
                cal,
                s,
                t,
                tcfg["confidence"],
                tcfg["n_bootstrap"],
                min_neg,
                tcfg["bootstrap_seed"] + i,
            ),
        }
        for rule in RULES:
            thr, who = found[rule]
            rows.append(
                {"rule": rule, "target_fpr": t, "threshold": _no_alarm_inf(thr), "set_by": who}
            )
    return rows


def _no_alarm_inf(thr: float) -> float:
    """``NO_ALARM`` (no feasible threshold: never warn) as inf, so medians stay finite-safe."""
    return math.inf if thr >= NO_ALARM else thr


def oracle_thresholds(cal: pd.DataFrame, score, targets, min_neg) -> dict[tuple[str, float], float]:
    """Each source's own cal point (reference: the source of a live URL is unknown)."""
    y = cal["label"].to_numpy().astype(int)
    s = np.asarray(score, dtype=float)
    out = {}
    for src, idx in cal.groupby("source").indices.items():
        if (y[idx] == 0).any() and (y[idx] == 1).any():
            for t in targets:
                out[(src, t)] = pooled_threshold(y[idx], s[idx], t, min_neg)
    return out


# --- evaluation --------------------------------------------------------------------------------


def eval_row(frame: pd.DataFrame, score, threshold: float, target: float, min_neg: int, conf):
    y = frame["label"].to_numpy().astype(int)
    s = np.asarray(score, dtype=float)
    r = at_threshold(y, s, threshold)
    n_neg, n_pos = int((y == 0).sum()), int((y == 1).sum())
    fp = int(((s >= threshold) & (y == 0)).sum())
    return {
        "n_urls": len(y),
        "n_pos": n_pos,
        "n_neg": n_neg,
        "n_domains": frame["domain"].nunique(),
        "n_neg_domains": frame.loc[y == 0, "domain"].nunique(),
        "fp": fp,
        "fpr": r["fpr"],
        "fpr_upper": float(cp_upper(fp, n_neg, conf)) if n_neg else math.nan,
        "recall": r["recall"],
        "precision": r["precision"],
        "granularity_limited": math.floor(target * n_neg) < min_neg,
    }


def evaluate_rules(
    cal: pd.DataFrame,
    sets: dict[str, pd.DataFrame],
    targets: list[float],
    tcfg: dict,
    min_neg: int,
    oracle: bool = False,
) -> list[dict]:
    """Rows for every rule x target x eval set. Frames carry a ``score`` column."""
    thr_rows = rule_thresholds(cal, cal["score"].to_numpy(), targets, tcfg, min_neg)
    conf = tcfg["confidence"]
    rows = []
    for tr in thr_rows:
        for name, frame in sets.items():
            if frame.empty:
                continue
            r = eval_row(frame, frame["score"], tr["threshold"], tr["target_fpr"], min_neg, conf)
            rows.append(tr | {"eval_set": name} | r)
    if oracle:
        orc = oracle_thresholds(cal, cal["score"].to_numpy(), targets, min_neg)
        for name, frame in sets.items():
            if not name.startswith("test:"):
                continue
            src = name.removeprefix("test:")
            for t in targets:
                if (src, t) not in orc:
                    continue
                thr = _no_alarm_inf(orc[(src, t)])
                r = eval_row(frame, frame["score"], thr, t, min_neg, conf)
                rows.append(
                    {"rule": ORACLE, "target_fpr": t, "threshold": thr, "set_by": src}
                    | {"eval_set": name}
                    | r
                )
    return rows


# --- model scores (cached) ---------------------------------------------------------------------


def _fit_score(model: str, train: pd.DataFrame, cfg: dict):
    y, w = train["label"].to_numpy(), train["weight"].to_numpy()
    if model == "hybrid2":
        m = make_hybrid(cfg, "hybrid2").fit(train, y, w)
        return m.score
    if model == "lightgbm":
        m = make_model(Spec("lightgbm", "all"), cfg).fit(train, y, w)
        return m.score
    raise ValueError(f"unknown model {model!r}")


def _scored(part: str, frame: pd.DataFrame, score) -> pd.DataFrame:
    out = frame[["source", "domain", "label"]].copy() if "source" in frame else None
    if out is None:
        out = frame[["domain", "label"]].copy()
        out["source"] = part
    out["part"] = part
    out["score"] = np.asarray(score, dtype=float)
    return out[SCORE_COLS].reset_index(drop=True)


def main_scores(k, pool, splits, extra, ood, lists, cfg, model) -> pd.DataFrame:
    side = splits[f"split_{k}"].to_numpy()
    train, cal, test = (pool[side == s] for s in (TRAIN, CAL, TEST))
    for name, other in {"cal": cal, "test": test, **extra, **ood}.items():
        assert_no_overlap(train, other, "train", name)
    for name, other in {"test": test, **extra, **ood}.items():
        assert_no_overlap(cal, other, "cal", name)
    t0 = time.monotonic()
    fitted = refit(train, lists)
    train, cal, test = (apply_fitted(f, fitted) for f in (train, cal, test))
    score = _fit_score(model, train, cfg)
    parts = {"cal": cal, "test": test}
    parts |= {n: apply_fitted(f, fitted) for n, f in (extra | ood).items()}
    out = pd.concat([_scored(n, f, score(f)) for n, f in parts.items()], ignore_index=True)
    log.info("split %d %s scored: %.0fs", k, model, time.monotonic() - t0)
    return out


def loso_scores(k, held, pool, splits, lists, cfg, model) -> pd.DataFrame:
    side = splits[f"split_{k}"].to_numpy()
    keep = (pool["source"] != held).to_numpy()
    train, cal, target = pool[keep & (side == TRAIN)], pool[keep & (side == CAL)], pool[~keep]
    assert_no_overlap(train, target, "train", held)
    assert_no_overlap(cal, target, "cal", held)
    assert_no_overlap(train, cal, "train", "cal")
    t0 = time.monotonic()
    fitted = refit(train, lists)
    train, cal, target = (apply_fitted(f, fitted) for f in (train, cal, target))
    score = _fit_score(model, train, cfg)
    out = pd.concat(
        [_scored("cal", cal, score(cal)), _scored("target", target, score(target))],
        ignore_index=True,
    )
    log.info("split %d leave out %s (%s): %.0fs", k, held, model, time.monotonic() - t0)
    return out


def _cached(path: Path, make) -> pd.DataFrame:
    if path.exists():
        return pd.read_parquet(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    df = make()
    tmp = path.with_suffix(".tmp")
    df.to_parquet(tmp, index=False)
    tmp.replace(path)
    return df


# --- per-unit rows -----------------------------------------------------------------------------


def main_rows(k: int, scores: pd.DataFrame, cfg: dict, tcfg: dict) -> list[dict]:
    ev = cfg["eval"]
    cal = scores[scores["part"] == "cal"]
    test = scores[scores["part"] == "test"]
    sets = {"test": test}
    sets |= {f"test:{s}": g for s, g in test.groupby("source", sort=True)}
    for p in sorted(set(scores["part"]) - {"cal", "test"}):
        sets[p] = scores[scores["part"] == p]
    rows = evaluate_rules(cal, sets, ev["target_fprs"], tcfg, ev["min_negatives"], oracle=True)
    return [{"setting": "main", "split": k, "left_out": ""} | r for r in rows]


def loso_rows(k: int, held: str, scores: pd.DataFrame, cfg: dict, tcfg: dict) -> list[dict]:
    ev = cfg["eval"]
    cal = scores[scores["part"] == "cal"]
    sets = {f"left_out:{held}": scores[scores["part"] == "target"]}
    rows = evaluate_rules(cal, sets, ev["target_fprs"], tcfg, ev["min_negatives"])
    return [{"setting": "loso", "split": k, "left_out": held} | r for r in rows]


# --- report ------------------------------------------------------------------------------------


def worst_case(runs: pd.DataFrame) -> pd.DataFrame:
    """Per setting, split, rule, target: highest FPR over sources with enough negatives.

    main: over ``test:<source>`` sets; loso: over the left-out sources of that split.
    """
    ok = runs["fpr"].notna() & ~runs["granularity_limited"].astype(bool)
    is_src = runs["eval_set"].str.startswith(("test:", "left_out:"))
    part = runs[ok & is_src & (runs["rule"] != ORACLE)]
    if part.empty:
        return pd.DataFrame(columns=["setting", "split", "rule", "target_fpr", "worst_fpr"])
    idx = part.groupby(["setting", "split", "rule", "target_fpr"])["fpr"].idxmax()
    out = part.loc[idx, ["setting", "split", "rule", "target_fpr", "fpr", "eval_set"]]
    return out.rename(columns={"fpr": "worst_fpr", "eval_set": "worst_set"})


def summarise(runs: pd.DataFrame) -> pd.DataFrame:
    keys = ["setting", "eval_set", "rule", "target_fpr"]
    g = runs.groupby(keys, sort=False)
    out = g[["n_urls", "n_pos", "n_neg", "n_domains", "n_neg_domains"]].median()
    out["n_splits"] = g.size()
    out["granularity_limited"] = g["granularity_limited"].any()
    over = (runs["fpr"] > runs["target_fpr"]).astype(float)
    out["share_over_target"] = over.groupby([runs[c] for c in keys], sort=False).mean()
    for m in ("fpr", "recall", "threshold"):
        out[f"{m}_median"] = g[m].median()
        out[f"{m}_min"] = g[m].min()
        out[f"{m}_max"] = g[m].max()
    return out.reset_index()


def _cell(g: pd.DataFrame, col: str) -> str:
    v = g[col].dropna()
    if v.empty:
        return "n/a"
    return f"{_fmt(v.median())} [{_fmt(v.min())}, {_fmt(v.max())}]"


def _counts(m: pd.DataFrame, sets: list[str]) -> str:
    out = []
    for s in sets:
        g = m[m["eval_set"] == s]
        if not g.empty:
            n, d = int(g["n_neg"].median()), int(g["n_neg_domains"].median())
            out.append(f"{s.split(':', 1)[-1]} {n:,} / {d:,}")
    return ", ".join(out)


def _thr_cell(v: pd.Series) -> str:
    v = v.dropna()
    if v.empty:
        return "n/a"
    med = float(np.median(v))
    return "none (never warns)" if math.isinf(med) else f"{med:.4f}"


def _fpr_cell(g: pd.DataFrame) -> str:
    if g.empty or g["fpr"].isna().all():
        return "n/a"
    flag = " †" if g["granularity_limited"].astype(bool).any() else ""
    return _cell(g, "fpr") + flag


RULE_TEXT = {
    "pooled": "current rule: cal-slice FPR point over all cal rows",
    "worst_source": "highest per-source cal point (sources with enough negatives), never below "
    "pooled (`blend2` `_ws`)",
    "balanced": "cal FPR point with every source's legitimate rows given equal total weight",
    "ucb_binom": "per source, lowest threshold whose Clopper-Pearson upper bound on FPR meets the "
    "target; sources too small to certify it are skipped",
    "ucb_boot": "per source, the confidence quantile of its threshold over domain bootstrap "
    "resamples; highest over sources and pooled",
    ORACLE: "each source's own cal point (reference only: not usable at runtime)",
}


def render(runs: pd.DataFrame, cfg: dict, tcfg: dict) -> str:
    targets = cfg["eval"]["target_fprs"]
    runs = runs.copy()
    runs["granularity_limited"] = runs["granularity_limited"].astype(bool)
    worst = worst_case(runs)
    conf = tcfg["confidence"]
    lines = [
        "# Threshold transfer: does the cal-side target FPR hold on unseen data?",
        "",
        "Generated by `python -m experiments.threshold_transfer`. Do not edit by hand.",
        f"Address model: `{tcfg['model']}` (main setting), `{tcfg['loso']['model']}`",
        "(leave one source out). Every rule is fitted on the calibration side only and applied",
        "unchanged. Allowlist and blocklist are off. Median over splits [min, max].",
        f"FPR cells marked † rest on fewer than {cfg['eval']['min_negatives']} allowed false",
        "positives (floor(target x negatives)) in at least one split: granularity-limited.",
        "`worst source` = highest FPR over sources that are not granularity-limited",
        "(main: test per source; LOSO: the left-out sources).",
        "",
        "Rules:",
        "",
    ]
    lines += [f"- `{r}`: {RULE_TEXT[r]}" for r in (*RULES, ORACLE)]
    lines += [
        "",
        f"Confidence {conf:.0%}; domain bootstrap {tcfg['n_bootstrap']} replicates; balanced rule",
        f"ignores sources with fewer than {tcfg['balanced_min_negatives']} cal negatives.",
        "Per-source calibration (`oracle_source`) needs the source of a URL, which is unknown for",
        "a live URL; it is shown only as an upper bound on the test side.",
        "",
    ]
    main = runs[runs["setting"] == "main"]
    if not main.empty:
        sets = [
            s
            for s in ("test", "heldout_source", "time_slice", "ood_urls")
            if s in set(main["eval_set"])
        ]
        for t in targets:
            m = main[main["target_fpr"] == t]
            w = worst[(worst["setting"] == "main") & (worst["target_fpr"] == t)]
            head = "| rule | threshold | " + " | ".join(f"{s}: FPR | {s}: recall" for s in sets)
            lines += [
                f"## Main setting, target FPR {t:.1%} ({m['split'].nunique()} splits)",
                "",
                head + " | worst source FPR | splits over target (worst source) |",
                "|---" * (2 + 2 * len(sets) + 2) + "|",
            ]
            for rule in RULES:
                r = m[m["rule"] == rule]
                cells = []
                for s in sets:
                    g = r[r["eval_set"] == s]
                    cells += [_fpr_cell(g), _cell(g, "recall") if g["n_pos"].sum() else "n/a"]
                wr = w[w["rule"] == rule]
                over = (wr["worst_fpr"] > t).mean() if len(wr) else math.nan
                thr = r[r["eval_set"] == "test"]["threshold"]
                lines.append(
                    f"| {rule} | {_thr_cell(thr)} | "
                    + " | ".join(cells)
                    + f" | {_cell(wr.rename(columns={'worst_fpr': 'v'}), 'v')} "
                    + f"| {_fmt(over)} |"
                )
            lines += ["", "Legitimate URLs / domains (median): " + _counts(m, sets) + "."]
            lines += [
                "",
                f"### Test per source, target FPR {t:.1%}: FPR / recall",
                "",
            ]
            srcs = sorted(s for s in m["eval_set"].unique() if s.startswith("test:"))
            lines += [
                "| rule | " + " | ".join(f"{s.removeprefix('test:')}" for s in srcs) + " |",
                "|---" * (1 + len(srcs)) + "|",
            ]
            for rule in (*RULES, ORACLE):
                r = m[m["rule"] == rule]
                cells = []
                for s in srcs:
                    g = r[r["eval_set"] == s]
                    if g.empty:
                        cells.append("n/a")
                        continue
                    rec = _fmt(g["recall"].median()) if g["n_pos"].sum() else "n/a"
                    cells.append(f"{_fpr_cell(g)} / {rec}")
                lines.append(f"| {rule} | " + " | ".join(cells) + " |")
            lines += ["", "Legitimate test URLs / domains (median): " + _counts(m, srcs) + ".", ""]
        lines += ["### Who sets the threshold (count of splits)", ""]
        lines += ["| rule | target FPR | set by |", "|---|---|---|"]
        thr = main[main["eval_set"] == "test"]
        for (rule, t), g in thr.groupby(["rule", "target_fpr"], sort=False):
            who = g["set_by"].replace("", "n/a").value_counts()
            text = ", ".join(f"{n} ({c})" for n, c in who.items())
            lines.append(f"| {rule} | {t:.1%} | {text} |")
        lines.append("")
    loso = runs[runs["setting"] == "loso"]
    if not loso.empty:
        srcs = sorted(loso["left_out"].unique())
        for t in targets:
            m = loso[loso["target_fpr"] == t]
            w = worst[(worst["setting"] == "loso") & (worst["target_fpr"] == t)]
            lines += [
                f"## Leave one source out, target FPR {t:.1%} ({m['split'].nunique()} splits)",
                "",
                "Model trained and rules fitted without the source; FPR / recall on all its rows.",
                "",
                "| rule | " + " | ".join(srcs) + " | worst left-out FPR |",
                "|---" * (2 + len(srcs)) + "|",
            ]
            for rule in RULES:
                r = m[m["rule"] == rule]
                cells = []
                for s in srcs:
                    g = r[r["left_out"] == s]
                    rec = _fmt(g["recall"].median()) if len(g) and g["n_pos"].sum() else "n/a"
                    cells.append(f"{_fpr_cell(g)} / {rec}")
                wr = w[w["rule"] == rule].rename(columns={"worst_fpr": "v"})
                lines.append(f"| {rule} | " + " | ".join(cells) + f" | {_cell(wr, 'v')} |")
            names = [f"left_out:{s}" for s in srcs]
            lines += ["", "Legitimate URLs / domains (median): " + _counts(m, names) + ".", ""]
    trip = cfg["eval"]["leakage_tripwire"]
    held = runs[
        runs["eval_set"].isin(["heldout_source", "time_slice"]) | (runs["setting"] == "loso")
    ]
    if ((held["recall"] > trip) & (held["n_pos"] > 0)).any():
        lines += [f"**Leakage tripwire:** a held-out recall above {trip:.0%}. Investigate.", ""]
    return "\n".join(lines)


def write_reports(reports: Path, cfg: dict, tcfg: dict) -> Path:
    tables = reports / "tables"
    parts = sorted((tables / RUNS).glob("*.csv"))
    out = reports / "threshold_transfer.md"
    if not parts:
        return out
    runs = pd.concat(
        [pd.read_csv(p, keep_default_na=False, na_values=[""]) for p in parts], ignore_index=True
    )
    runs["left_out"] = runs["left_out"].fillna("")
    runs["set_by"] = runs["set_by"].fillna("")
    runs = runs.sort_values(["setting", "split", "left_out"], kind="stable")
    runs.to_csv(tables / f"{RUNS}.csv", index=False)
    summarise(runs).to_csv(tables / "threshold_transfer_summary.csv", index=False)
    worst_case(runs).to_csv(tables / "threshold_transfer_worst.csv", index=False)
    out.write_text(render(runs, cfg, tcfg), encoding="utf-8")
    return out


# --- driver ------------------------------------------------------------------------------------


def _write_rows(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    pd.DataFrame(rows).to_csv(tmp, index=False)
    tmp.replace(path)


def run(
    processed: Path,
    reports: Path,
    split_ids: list[int] | None = None,
    loso_ids: list[int] | None = None,
    settings: tuple[str, ...] = ("main", "loso"),
    cfg: dict | None = None,
    lists: Lists | None = None,
    ood_csv: Path | None = None,
    cache: Path | None = None,
) -> Path:
    cfg = cfg or load_config("models")
    tcfg = cfg["threshold_transfer"]
    lists = lists or load_lists()
    cache = Path(cache or tcfg["cache_dir"])
    runs_dir = reports / "tables" / RUNS
    pool = load_part(processed, PARTS[0], lists)
    splits = pd.read_parquet(processed / "splits.parquet")
    splits = pool[["uid"]].merge(splits, on="uid", how="left", validate="one_to_one")
    n_splits = sum(c.startswith("split_") for c in splits.columns)

    if "main" in settings:
        extra = {p: load_part(processed, p, lists) for p in PARTS[1:]}
        ood = {}
        if ood_csv:
            from experiments.ood_fpr import load_ood

            ood["ood_urls"] = load_ood(ood_csv, lists).assign(source="ood_urls")
        ids = split_ids if split_ids is not None else tcfg.get("splits") or range(n_splits)
        for k in ids:
            path = cache / f"{tcfg['model']}_main_split_{k}.parquet"
            scores = _cached(
                path,
                lambda k=k: main_scores(k, pool, splits, extra, ood, lists, cfg, tcfg["model"]),
            )
            if ood and "ood_urls" not in set(scores["part"]):
                log.warning("split %d: cached scores have no ood_urls (delete %s)", k, path)
            _write_rows(runs_dir / f"main_split_{k}.csv", main_rows(k, scores, cfg, tcfg))
            write_reports(reports, cfg, tcfg)

    if "loso" in settings:
        lcfg = tcfg["loso"]
        both = pool.groupby("source")["label"].nunique()
        sources = sorted(both.index if not lcfg["skip_one_class"] else both[both == 2].index)
        for k in loso_ids if loso_ids is not None else lcfg["splits"]:
            for held in sources:
                path = cache / f"{lcfg['model']}_loso_split_{k}_{held}.parquet"
                scores = _cached(
                    path,
                    lambda k=k, held=held: loso_scores(
                        k, held, pool, splits, lists, cfg, lcfg["model"]
                    ),
                )
                rows = loso_rows(k, held, scores, cfg, tcfg)
                _write_rows(runs_dir / f"loso_split_{k}_{held}.csv", rows)
                write_reports(reports, cfg, tcfg)
    return write_reports(reports, cfg, tcfg)


def main(argv: list[str] | None = None) -> int:
    cfg = load_config("models")
    ap = argparse.ArgumentParser(prog="experiments.threshold_transfer")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--splits", type=int, nargs="*", default=None, help="main setting splits")
    ap.add_argument("--loso-splits", type=int, nargs="*", default=None)
    ap.add_argument("--setting", nargs="+", choices=("main", "loso"), default=["main", "loso"])
    ap.add_argument("--loso-model", choices=("hybrid2", "lightgbm"), default=None)
    ap.add_argument("--ood-csv", type=Path, default=None, help="crawl-ood first pass ood_urls.csv")
    ap.add_argument("--cache", type=Path, default=None, help="score cache (default from config)")
    ap.add_argument("--lists-dir", default=None)
    ap.add_argument("--platforms-file", default=None)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    if a.loso_model:
        cfg["threshold_transfer"]["loso"]["model"] = a.loso_model
    lists = load_lists(a.lists_dir, a.platforms_file)
    out = run(
        a.processed,
        a.reports,
        a.splits,
        a.loso_splits,
        tuple(a.setting),
        cfg=cfg,
        lists=lists,
        ood_csv=a.ood_csv,
        cache=a.cache,
    )
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
