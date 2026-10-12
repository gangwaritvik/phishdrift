"""Looking for gains over the hybrid tier A model, chosen on calibration slices only.

python -m experiments.gains_a scorer NAME --split 0      # one text scorer: OOF train + cal scores
python -m experiments.gains_a combine TAG --scorers a b --split 0 [--gbdt VARIANT] [--seed S]
python -m experiments.gains_a report

Nothing here touches the test slices, the held-out source or the time slice: a split is loaded
as train + cal only, and every number is measured on the cal side (recall at FPR 1% / 0.1% at
the cal side's own operating points, ROC-AUC, PR-AUC). A scorer is a text model (character
n-gram LR, word LR or naive Bayes) on one piece of the URL; ``scorer`` fits it on the train side
with domain-grouped out-of-fold scores (as ``models.hybrid.HybridA`` does) and caches the scores.
``combine`` trains the LightGBM on the 99 URL features plus the named scorers' scores.
One result file per run (``tables/gains_a_runs/*.json``), so runs go in parallel processes.
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB

from data_pipeline.split import CAL, TRAIN
from experiments.metrics import curve_metrics, operating_point
from experiments.tier_a import apply_fitted, assert_no_overlap, load_part, refit
from features.lists import Lists, load_lists
from features.registry import NAMES
from models.char_ngram import CharNgramLR
from models.gbdt import GBDT
from models.stack import grouped_folds, logit
from models.text_scorers import PIECES, WordLR
from phishdrift.config import load_config

log = logging.getLogger("gains_a")


class CharNB:
    """Multinomial naive Bayes on character n-gram counts."""

    def __init__(self, params: dict, seed: int):
        self.vec = CountVectorizer(
            analyzer="char", ngram_range=tuple(params["ngram_range"]), min_df=params["min_df"],
            max_features=params["max_features"], lowercase=False, dtype=np.float32,
        )  # fmt: skip
        self.nb = MultinomialNB(alpha=params["alpha"])

    def fit(self, texts, y, w=None):
        self.nb.fit(self.vec.fit_transform(texts), y, sample_weight=w)
        return self

    def score(self, texts):
        return self.nb.predict_proba(self.vec.transform(texts))[:, 1]


def char_params(base: dict, **over) -> dict:
    return {**base, **over}


NB = {"ngram_range": [1, 5], "min_df": 3, "alpha": 0.5}

# name -> (text piece, kind, parameter overrides). The first two are the scorers of the hybrid.
SCORERS: dict[str, tuple[str, str, dict]] = {
    "char_url": ("url", "char", {}),
    "char_host": ("host", "char", {}),
    "char_url_c1": ("url", "char", {"C": 1.0}),
    "char_url_c16": ("url", "char", {"C": 16.0}),
    "char_host_c1": ("host", "char", {"C": 1.0}),
    "char_host_c16": ("host", "char", {"C": 16.0}),
    "char_url_w26": ("url", "char", {"ngram_range": [2, 6], "max_features": 800000}),
    "char_host_w26": ("host", "char", {"ngram_range": [2, 6], "min_df": 2}),
    "char_domain": ("domain", "char", {"ngram_range": [2, 6], "min_df": 2}),
    "char_path": ("path", "char", {"min_df": 3}),
    "word_url": ("url", "word", {"min_df": 2, "C": 4.0}),
    "word_host": ("host", "word", {"min_df": 2, "C": 4.0}),
    "nb_host": ("host", "nb", {**NB, "max_features": 400000}),
    "nb_url": ("url", "nb", {**NB, "max_features": 800000}),
}

# LightGBM variants over config's lightgbm block (changes only).
GBDT_VARIANTS: dict[str, dict] = {
    "base": {},
    "unweighted": {"_weight": "none"},
    "sqrt_weight": {"_weight": "sqrt"},
    "slow": {"learning_rate": 0.03, "n_estimators": 1200},
    "leaves31": {"num_leaves": 31},
    "leaves127": {"num_leaves": 127, "min_child_samples": 30},
    "mcs150": {"min_child_samples": 150},
    "col50": {"colsample_bytree": 0.5},
}


def make_scorer(name: str, cfg: dict):
    piece, kind, over = SCORERS[name]
    if kind == "char":
        return CharNgramLR(char_params(cfg["char_ngram"], **over), cfg["seed"])
    if kind == "word":
        return WordLR(over, cfg["seed"])
    return CharNB(over, cfg["seed"])


def piece_texts(frame: pd.DataFrame, piece: str) -> np.ndarray:
    get = PIECES[piece]
    return np.array([get(p) if p is not None else "" for p in frame["_parts"]], dtype=object)


def load_split(processed: Path, k: int, lists: Lists) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Train and cal sides of split ``k`` with the fitted features refit on the train side."""
    pool = load_part(processed, "pool", lists)
    splits = pd.read_parquet(processed / "splits.parquet")
    splits = pool[["uid"]].merge(splits, on="uid", how="left", validate="one_to_one")
    side = splits[f"split_{k}"].to_numpy()
    train, cal = pool[side == TRAIN], pool[side == CAL]
    assert_no_overlap(train, cal, "train", "cal")
    fitted = refit(train, lists)
    return apply_fitted(train, fitted).reset_index(drop=True), apply_fitted(
        cal, fitted
    ).reset_index(drop=True)


def cal_metrics(y: np.ndarray, score: np.ndarray, cfg: dict) -> dict:
    ev = cfg["eval"]
    row = {"n_urls": len(y), "n_pos": int(y.sum()), "n_neg": int((y == 0).sum())} | curve_metrics(
        y, score
    )
    for t in ev["target_fprs"]:
        op = operating_point(y, score, t, ev["min_negatives"])
        tag = f"{t * 100:g}pct".replace(".", "p")
        row[f"recall_{tag}"] = op["recall"]
        row[f"fpr_{tag}"] = op["achieved_fpr"]
    return row


def write_row(reports: Path, tag: str, row: dict) -> None:
    out = reports / "tables" / "gains_a_runs"
    out.mkdir(parents=True, exist_ok=True)
    tmp = out / f"{tag}.tmp"
    tmp.write_text(json.dumps(row, indent=1), encoding="utf-8")
    tmp.replace(out / f"{tag}.json")


def run_scorer(name: str, k: int, a: argparse.Namespace, cfg: dict, lists: Lists) -> None:
    t0 = time.monotonic()
    train, cal = load_split(a.processed, k, lists)
    y, w = train["label"].to_numpy(), train["weight"].to_numpy()
    piece = SCORERS[name][0]
    t_train, t_cal = piece_texts(train, piece), piece_texts(cal, piece)
    n_folds = cfg["stack"]["n_folds"]
    folds = grouped_folds(train["domain"], n_folds, cfg["seed"])
    oof = np.zeros(len(train))
    for f in range(n_folds):
        a_, b_ = folds != f, folds == f
        oof[b_] = (
            make_scorer(name, cfg).fit(list(t_train[a_]), y[a_], w[a_]).score(list(t_train[b_]))
        )
    cal_score = make_scorer(name, cfg).fit(list(t_train), y, w).score(list(t_cal))
    a.cache.mkdir(parents=True, exist_ok=True)
    np.savez(a.cache / f"{name}_s{k}.npz", oof=logit(oof), cal=logit(cal_score))
    row = {"kind": "scorer", "name": name, "split": k, "seconds": round(time.monotonic() - t0)}
    write_row(
        a.reports, f"scorer_{name}_s{k}", row | cal_metrics(cal["label"].to_numpy(), cal_score, cfg)
    )
    log.info("scorer %s split %d: %.0fs", name, k, time.monotonic() - t0)


def run_combine(tag: str, k: int, a: argparse.Namespace, cfg: dict, lists: Lists) -> None:
    t0 = time.monotonic()
    train, cal = load_split(a.processed, k, lists)
    y, w = train["label"].to_numpy(), train["weight"].to_numpy()
    for name in a.scorers:
        z = np.load(a.cache / f"{name}_s{k}.npz")
        if len(z["oof"]) != len(train) or len(z["cal"]) != len(cal):
            raise ValueError(f"cached scores of {name} (split {k}) do not match the split")
        train[name], cal[name] = z["oof"].astype(np.float32), z["cal"].astype(np.float32)
    var = dict(GBDT_VARIANTS[a.gbdt])
    mode = var.pop("_weight", "base")
    if mode == "none":
        w = np.ones(len(train))
    elif mode == "sqrt":
        w = np.sqrt(w)
    params = {**cfg["lightgbm"], **var}
    model = GBDT("lightgbm", params, list(NAMES) + list(a.scorers), a.seed).fit(train, y, w)
    row = {"kind": "combine", "name": tag, "scorers": " ".join(a.scorers), "gbdt": a.gbdt,
           "seed": a.seed, "split": k, "seconds": round(time.monotonic() - t0)}  # fmt: skip
    write_row(
        a.reports,
        f"combine_{tag}_s{k}_seed{a.seed}",
        row | cal_metrics(cal["label"].to_numpy(), model.score(cal), cfg),
    )
    log.info("combine %s split %d: %.0fs", tag, k, time.monotonic() - t0)


def report(reports: Path) -> Path:
    rows = [
        json.loads(p.read_text())
        for p in sorted((reports / "tables" / "gains_a_runs").glob("*.json"))
    ]
    df = pd.DataFrame(rows)
    df.to_csv(reports / "tables" / "gains_a_cal.csv", index=False)
    pct = lambda x: f"{100 * x:.1f}%"  # noqa: E731
    lines = [
        "# Looking for gains over the hybrid (calibration slices only)",
        "",
        "Generated by `python -m experiments.gains_a report`. Do not edit by hand.",
        "Every number is on the calibration side of the split (recall at the cal side's own",
        "FPR points); the test slices, the held-out source and the time slice were not loaded.",
        "",
    ]
    for kind, title in (("scorer", "Text scorers alone"), ("combine", "LightGBM + scorers")):
        d = df[df["kind"] == kind]
        if d.empty:
            continue
        lines += [f"## {title}", ""]
        if kind == "combine":
            lines += [
                "| run | scorers | LightGBM | seed | split | ROC-AUC | recall @1% | recall @0.1% |",
                "|---|---|---|---|---|---|---|---|",
            ]
            for _, r in d.sort_values(["split", "name", "seed"]).iterrows():
                cells = [r["name"], r["scorers"], r["gbdt"], r["seed"], r["split"]]
                cells += [f"{r['roc_auc']:.4f}", pct(r["recall_1pct"]), pct(r["recall_0p1pct"])]
                lines.append("| " + " | ".join(str(c) for c in cells) + " |")
        else:
            lines += [
                "| scorer | split | ROC-AUC | recall @1% | recall @0.1% | seconds |",
                "|---|---|---|---|---|---|",
            ]
            for _, r in d.sort_values(["split", "name"]).iterrows():
                cells = [r["name"], r["split"], f"{r['roc_auc']:.4f}"]
                cells += [pct(r["recall_1pct"]), pct(r["recall_0p1pct"]), r["seconds"]]
                lines.append("| " + " | ".join(str(c) for c in cells) + " |")
        lines.append("")
    out = reports / "gains_a.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.gains_a")
    ap.add_argument("mode", choices=["scorer", "combine", "report"])
    ap.add_argument("name", nargs="?")
    ap.add_argument("--split", type=int, default=0)
    ap.add_argument("--scorers", nargs="*", default=[])
    ap.add_argument("--gbdt", default="base", choices=sorted(GBDT_VARIANTS))
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--cache", type=Path, default=Path(".cache/gains_a"))
    ap.add_argument("--lists-dir", default=None)
    ap.add_argument("--platforms-file", default=None)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    if a.mode == "report":
        print(report(a.reports))
        return 0
    cfg = load_config("models")
    a.seed = cfg["seed"] if a.seed is None else a.seed
    lists = load_lists(a.lists_dir, a.platforms_file)
    if a.mode == "scorer":
        run_scorer(a.name, a.split, a, cfg, lists)
    else:
        run_combine(a.name, a.split, a, cfg, lists)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
