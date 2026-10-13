"""Robustness to URL evasion: hybrid2 before and after adversarial training, one family held out.

python -m experiments.robustness [--processed ...] [--reports reports] [--splits ...]

Per split k:
- ``base``: hybrid2 trained on the clean train side (the model the extension runs);
- ``adv``: the same model trained on the train side plus one variant (``train_fraction`` of the
  rows, both classes, so an attack artefact never becomes a label) for every family except the
  held-out one, ``families[k % 6]``. Variants keep their parent's domain, so domain-grouped
  folds and the split's domain disjointness still hold. Variants go into training folds only.
- both models are scored on the clean test side and on test URLs rewritten by each family. The
  suspicious and dangerous thresholds are the 1% / 0.1% FPR points of the clean cal side, so
  an *evasion rate* is the share of phishing variants scored below the threshold, and the false
  alarm side is the share of legitimate variants (and of long legitimate URLs) above it.

Each split writes ``tables/robustness/split_<k>.csv``; ``robustness.md`` is rebuilt from all of
them. Finished splits are skipped on a rerun.
"""

from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path

import numpy as np
import pandas as pd

from attacks import FAMILIES, apply_family
from data_pipeline.split import CAL, TEST, TRAIN
from experiments.hybrid_a import make_hybrid
from experiments.metrics import evaluate, operating_point
from experiments.tier_a import _fmt, apply_fitted, assert_no_overlap, load_part, refit
from features.extract import extract
from features.fit import Fitted
from features.lists import Lists, load_lists
from features.registry import NAMES
from features.urlparts import parse
from phishdrift.config import load_config
from phishdrift.domains import url_key

log = logging.getLogger("robustness")
VARIANT = "hybrid2"


def variants(rows: pd.DataFrame, family: str, lists: Lists, fitted: Fitted, seed: int):
    """``rows`` rewritten by ``family`` with their tier A features; rows it does not apply to
    are dropped. Domain, label, weight and depth are the parent's."""
    new = [apply_family(family, u, lists, seed) for u in rows["url"]]
    keep = np.array([u is not None for u in new])
    out = rows.loc[keep].copy()
    out["url"] = [u for u in new if u is not None]
    feats = pd.DataFrame(
        [extract(u, lists=lists, fitted=Fitted()) for u in out["url"]],
        columns=list(NAMES),
        index=out.index,
    ).astype("float32")
    out[list(NAMES)] = feats
    out["_parts"] = [parse(u, lists.platforms) for u in out["url"]]
    out["_text"] = [p.canon if p is not None else "" for p in out["_parts"]]
    out["_key"] = out["url"].map(url_key)
    return apply_fitted(out, fitted)


def _flag_row(split, name, held_out, label, frame, score, thr, extra=None):
    row = {
        "split": split,
        "model": name,
        "held_out": held_out,
        "set": label,
        "n_urls": len(frame),
        "n_domains": frame["domain"].nunique(),
        "flag_suspicious": float(np.mean(score >= thr[0.01])) if len(frame) else np.nan,
        "flag_dangerous": float(np.mean(score >= thr[0.001])) if len(frame) else np.nan,
    }
    return row | (extra or {})


def run_split(k, pool, splits, lists, cfg):
    rc, ev = cfg["robustness"], cfg["eval"]
    targets, min_neg = ev["target_fprs"], ev["min_negatives"]
    held_out = FAMILIES[k % len(FAMILIES)]
    side = splits[f"split_{k}"].to_numpy()
    train, cal, test = (pool[side == s] for s in (TRAIN, CAL, TEST))
    assert_no_overlap(train, test, "train", "test")
    assert_no_overlap(train, cal, "train", "cal")
    t0 = time.monotonic()
    fitted = refit(train, lists)
    train, cal, test = (apply_fitted(f, fitted) for f in (train, cal, test))
    rng = np.random.default_rng(rc["seed"] + k)

    adv_parts = [train]
    for fam in FAMILIES:
        if fam == held_out:
            continue
        pick = train.sample(frac=rc["train_fraction"], random_state=int(rng.integers(1 << 31)))
        adv_parts.append(variants(pick, fam, lists, fitted, rc["seed"]))
    adv_train = pd.concat(adv_parts, ignore_index=True)
    log.info(
        "split %d: %d clean + %d variant training rows (%.0fs)",
        k,
        len(train),
        len(adv_train) - len(train),
        time.monotonic() - t0,
    )

    ph = test[test["label"] == 1]
    bn = test[test["label"] == 0]
    ph = ph.sample(n=min(rc["eval_phishing"], len(ph)), random_state=rc["seed"] + k)
    bn = bn.sample(n=min(rc["eval_benign"], len(bn)), random_state=rc["seed"] + k)
    long_cut = bn["url"].str.len().quantile(rc["long_url_quantile"])
    long_bn = test[(test["label"] == 0) & (test["url"].str.len() >= long_cut)]
    sets = {"clean_phishing": ph, "clean_benign": bn, "long_benign": long_bn}
    for fam in FAMILIES:
        sets[f"{fam}:phishing"] = variants(ph, fam, lists, fitted, rc["seed"])
        sets[f"{fam}:benign"] = variants(bn, fam, lists, fitted, rc["seed"])
    log.info("split %d: evaluation variants built (%.0fs)", k, time.monotonic() - t0)

    rows = []
    for name, tr, y in (
        ("base", train, train["label"].to_numpy()),
        ("adv", adv_train, adv_train["label"].to_numpy()),
    ):
        model = make_hybrid(cfg, VARIANT).fit(tr, y, tr["weight"].to_numpy())
        thr = {
            t: operating_point(cal["label"], model.score(cal), t, min_neg)["threshold"]
            for t in targets
        }
        clean = evaluate(test["label"].to_numpy(), model.score(test), targets, min_neg, thr)
        rows.append(
            {"split": k, "model": name, "held_out": held_out, "set": "clean_test"}
            | {"n_domains": test["domain"].nunique()}
            | clean
        )
        for label, frame in sets.items():
            score = model.score(frame) if len(frame) else np.array([])
            fam = label.split(":")[0]
            extra = {"applied": len(frame) / max(len(ph if "phishing" in label else bn), 1)}
            extra["family_held_out"] = fam == held_out
            rows.append(_flag_row(k, name, held_out, label, frame, score, thr, extra))
        log.info("split %d %s: scored (%.0fs)", k, name, time.monotonic() - t0)
    return rows


# --- report ----------------------------------------------------------------------------


def _cell(series: pd.Series) -> str:
    return f"{_fmt(series.median())} [{_fmt(series.min())}, {_fmt(series.max())}]"


def render(runs: pd.DataFrame, cfg: dict) -> str:
    splits = sorted(runs["split"].unique())
    rc = cfg["robustness"]
    lines = [
        "# Robustness to URL evasion (hybrid2, tier A)",
        "",
        "Generated by `python -m experiments.robustness`. Do not edit by hand.",
        f"{len(splits)} domain-grouped splits ({', '.join(map(str, splits))}); "
        "median [min, max] in %.",
        "`base` = the model the extension runs; `adv` = trained with evasion variants of every",
        "family except the one held out in that split (split k holds out family k mod 6, so each",
        "family is held out in one split). Thresholds are the 1% / 0.1% FPR points of the clean",
        "cal side. Evasion rate = 100% minus the share of phishing variants flagged. Variants are",
        f"made from the same {rc['eval_phishing']:,} test phishing and {rc['eval_benign']:,} test",
        "benign URLs (or fewer) in every family; `applied` is the share a family could be",
        "applied to (e.g. a homoglyph needs a replaceable letter).",
        "",
    ]
    clean = runs[runs["set"] == "clean_test"]
    lines += [
        "## Clean test side (nothing rewritten)",
        "",
        "| model | splits | URLs | domains | ROC-AUC | recall @1% FPR | recall @0.1% FPR "
        "| cal 1%: recall / FPR | cal 0.1%: recall / FPR |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for m, g in clean.groupby("model", sort=False):
        lines.append(
            f"| {m} | {len(g)} | {int(g['n_urls'].median()):,} | {int(g['n_domains'].median()):,} "
            f"| {_fmt(g['roc_auc'].median(), False)} | {_cell(g['op_1pct_recall'])} "
            f"| {_cell(g['op_0p1pct_recall'])} "
            f"| {_fmt(g['cal_1pct_recall'].median())} / {_fmt(g['cal_1pct_fpr'].median())} "
            f"| {_fmt(g['cal_0p1pct_recall'].median())} / {_fmt(g['cal_0p1pct_fpr'].median())} |"
        )
    flags = runs[runs["set"] != "clean_test"].copy()
    flags["family_held_out"] = flags["family_held_out"].astype(bool)
    flags["evade_susp"] = 1 - flags["flag_suspicious"]
    flags["evade_dang"] = 1 - flags["flag_dangerous"]
    ph = flags[flags["set"].str.endswith("phishing")]
    lines += [
        "",
        "## Evasion rate of phishing URLs",
        "",
        "Share of rewritten phishing URLs NOT flagged. `held-out` rows are the splits where that",
        "family was not in the adversarial model's training data (one split per family).",
        "",
        "| family | model | applied | evaded at suspicious (1% FPR) "
        "| evaded at dangerous (0.1% FPR) |",
        "|---|---|---|---|---|",
    ]
    names = ["clean_phishing", *(f"{f}:phishing" for f in FAMILIES)]
    for label in names:
        for m in ("base", "adv"):
            g = ph[(ph["set"] == label) & (ph["model"] == m)]
            if g.empty:
                continue
            held = g[g["family_held_out"]] if label != "clean_phishing" else g.iloc[0:0]
            seen = g[~g["family_held_out"]] if label != "clean_phishing" else g
            fam = label.split(":")[0]
            tag = "clean" if label == "clean_phishing" else fam
            if m == "adv" and len(held):
                rows = [(f"{tag} (seen in training)", seen), (f"{tag} (held out)", held)]
            else:
                rows = [(tag, g)]
            for tag2, gg in rows:
                if gg.empty:
                    continue
                lines.append(
                    f"| {tag2} | {m} | {_fmt(gg['applied'].median())} "
                    f"| {_cell(gg['evade_susp'])} | {_cell(gg['evade_dang'])} |"
                )
    bn = flags[flags["set"].str.endswith("benign")]
    lines += [
        "",
        "## False alarms on rewritten and long legitimate URLs",
        "",
        "Share of legitimate URLs flagged (the target on clean URLs is 1% and 0.1%). `long_benign`",
        f"= legitimate test URLs above the {rc['long_url_quantile']:.0%} length quantile; "
        "the `shortener` rows are legitimate URLs wrapped in a public shortener.",
        "",
        "| set | model | URLs | domains | flagged at suspicious | flagged at dangerous |",
        "|---|---|---|---|---|---|",
    ]
    for label in ["clean_benign", "long_benign", *(f"{f}:benign" for f in FAMILIES)]:
        for m in ("base", "adv"):
            g = bn[(bn["set"] == label) & (bn["model"] == m)]
            if g.empty:
                continue
            held = g[g["family_held_out"]]
            groups = [(label, g)]
            if m == "adv" and len(held):
                groups = [(f"{label} (seen in training)", g[~g["family_held_out"]]),
                          (f"{label} (held out)", held)]  # fmt: skip
            for tag, gg in groups:
                if gg.empty:
                    continue
                lines.append(
                    f"| {tag} | {m} | {int(gg['n_urls'].median()):,} "
                    f"| {int(gg['n_domains'].median()):,} "
                    f"| {_cell(gg['flag_suspicious'])} | {_cell(gg['flag_dangerous'])} |"
                )
    return "\n".join(lines) + "\n"


def write_reports(reports: Path, cfg: dict) -> Path:
    parts = sorted((reports / "tables" / "robustness").glob("split_*.csv"))
    runs = pd.concat([pd.read_csv(p) for p in parts], ignore_index=True)
    runs.to_csv(reports / "tables" / "robustness.csv", index=False)
    out = reports / "robustness.md"
    out.write_text(render(runs, cfg), encoding="utf-8")
    return out


def run(
    processed: Path,
    reports: Path,
    split_ids: list[int] | None = None,
    cfg: dict | None = None,
    lists: Lists | None = None,
) -> Path:
    cfg = cfg or load_config("models")
    lists = lists or load_lists()
    per_split = reports / "tables" / "robustness"
    per_split.mkdir(parents=True, exist_ok=True)
    pool = load_part(processed, "pool", lists)
    splits = pd.read_parquet(processed / "splits.parquet")
    splits = pool[["uid"]].merge(splits, on="uid", how="left", validate="one_to_one")
    for k in split_ids if split_ids is not None else cfg["robustness"]["splits"]:
        out = per_split / f"split_{k}.csv"
        if out.exists():
            log.info("split %d already done", k)
            continue
        pd.DataFrame(run_split(k, pool, splits, lists, cfg)).to_csv(out, index=False)
        write_reports(reports, cfg)
        log.info("split %d written", k)
    return write_reports(reports, cfg)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.robustness")
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
