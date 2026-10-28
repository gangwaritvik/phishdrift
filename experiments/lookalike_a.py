"""Brand look-alike experiments E0-E3 (and the rule reference E3r) for the tier A hybrid.

python -m experiments.lookalike_a --processed DIR --reports DIR --split K [--feed-json FILE]
python -m experiments.lookalike_a --reports DIR --render          # merge the splits into SUMMARY.md

Question: does the tier A model learn to flag clean look-alikes such as ``paypa1.com``, and what
does the brand-domain information add beyond training data? Plan: the Claude Doc "PhishDrift: why
brand look-alikes slip through"; settings in ``configs/lookalike_exp.yaml``, fixed before any result
was read. Nothing shipped is touched and nothing is tuned on a test side.

==== ============================================================================================
E0   shipped hybrid2 (LightGBM + char/word text scores), trained unchanged
E1a  character n-gram TF-IDF + logistic regression on the URL alone (no trees)
E1b  the same, trained with the look-alike examples
E2   E0 trained with the look-alike examples (no new features)
E3   E2 plus the four brand-mismatch columns (``features/brand_mismatch.py``)
E3r  E0 plus the removed escalate-only rule: warned if E0 warns or the rule fires (1% level only)
==== ============================================================================================

Look-alike examples (training rows only): brand names of 4 of 5 brand folds turned into look-alike
domains in the ``TRAIN_STYLES`` (``attacks/lookalike.py``), label phishing, each paired with a
same-size set of official domains of the same brands, label legitimate; real paths sampled from the
training rows. A brand's variants share one group for the out-of-fold text scores. Thresholds come
from the natural calibration slice (never from look-alikes or test). Evaluation look-alikes use only
the held-out brand fold, in all nine styles (``TEST_ONLY_STYLES`` were never trained on) and three
URL shapes. Hard failures: a test look-alike domain or brand also in training.
"""

from __future__ import annotations

import argparse
import copy
import json
import logging
import math
import pickle
import random
import time
from functools import partial
from pathlib import Path

import numpy as np
import pandas as pd

from attacks.lookalike import STYLES, TEST_ONLY_STYLES, TRAIN_STYLES, make_domain
from experiments.char_cnn_a import _rows, _thresholds, build_ctx
from experiments.hybrid_a import make_hybrid
from experiments.metrics import evaluate
from experiments.tier_a import refit
from features.brand_mismatch import COLUMNS, BrandMismatch
from features.fit import Fitted
from features.lists import Lists, load_lists
from features.registry import NAMES
from features.urlparts import parse
from models.char_ngram import CharNgramLR
from models.gbdt import GBDT
from models.lookalike_aug import (
    LeakageError,
    add_brand,
    augmentation,
    own_tld,
    real_paths,
    split_brands,
    url_frame,
)
from models.text_scorers import piece_texts
from phishdrift.config import load_config

log = logging.getLogger("lookalike_a")
MODELS = ("E0", "E1a", "E1b", "E2", "E3")
Z95 = 1.96


def wilson(k: int, n: int) -> tuple[float, float]:
    if n == 0:
        return math.nan, math.nan
    p, z2 = k / n, Z95**2
    centre = (p + z2 / (2 * n)) / (1 + z2 / n)
    half = Z95 * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / (1 + z2 / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def lookalike_test(test_brands, bm, exp, test_paths, unlisted, lists, fitted) -> pd.DataFrame:
    """Held-out-brand look-alikes (every style and shape), official controls, unlisted names."""
    shapes = {"bare": "/", "login": "/login"}
    rows = []

    def add(group, style, host, brand, rng, mode):
        for shape in exp["shapes"]:
            path = rng.choice(test_paths) if shape == "deep" else shapes[shape]
            rows.append(
                (f"https://{host}{path}", group, style, shape, style in TRAIN_STYLES, brand, mode)
            )

    tlds = tuple(exp["tlds"])
    for b in test_brands:
        for style in STYLES:
            # "own": the brand's own suffix (paypa1.com), "other": a random one (paypa1.xyz)
            for mode, prob in (("own", 1.0), ("other", 0.0)):
                rng = random.Random(f"{exp['seed']}|{style}|{b}|{mode}")
                own = own_tld(bm, b, rng)
                if mode == "own" and (own is None or style == "suffix"):
                    continue
                dom = make_domain(style, b, rng, own, tlds, own_prob=prob)
                if dom and dom not in bm.official and dom.split(".")[0] not in bm.brands:
                    add("listed", style, dom, b, rng, mode)
        if bm.owned.get(b):
            rng = random.Random(f"{exp['seed']}|official|{b}")
            add("official", "official", rng.choice(sorted(bm.owned[b])), b, rng, "own")
    for name in unlisted:
        for style in STYLES:
            for mode, prob in (("own", 1.0), ("other", 0.0)):
                if mode == "own" and style == "suffix":
                    continue
                rng = random.Random(f"{exp['seed']}|unlisted|{style}|{name}|{mode}")
                dom = make_domain(style, name, rng, "com", tlds, own_prob=prob)
                if dom and dom.split(".")[0] not in bm.brands:
                    add("unlisted", style, dom, name, rng, mode)
    df = pd.DataFrame(
        rows, columns=["url", "group", "style", "shape", "seen_style", "brand", "tld_mode"]
    )
    frame = url_frame(df["url"].tolist(), lists, fitted, bm)
    return pd.concat([frame, df.drop(columns="url")], axis=1)


# ---- models --------------------------------------------------------------------------------------


class CharAlone:
    """E1: character n-gram TF-IDF + logistic regression on the masked URL."""

    def __init__(self, cfg: dict):
        self.model = CharNgramLR(
            {**cfg["char_ngram"], **cfg["hybrid2"]["scorers"][0]["params"]}, cfg["seed"]
        )

    def fit(self, frame, y, w):
        self.model.fit(piece_texts(frame, "url"), y, w)
        return self

    def score(self, frame):
        return self.model.score(piece_texts(frame, "url"))


def e3_from_e2(e2, train_aug, y, w, cfg):
    """E2's text models and out-of-fold scores, trees refitted with the brand columns added."""
    m = copy.copy(e2)
    m.columns = [*e2.columns, *COLUMNS]
    cols = [*m.columns, *m.scorer_names]
    m.gbdt = GBDT("lightgbm", cfg["lightgbm"], cols, cfg["seed"])
    m.gbdt.fit(train_aug.assign(**e2.oof), y, w)
    return m


def rule_flag(frame: pd.DataFrame) -> np.ndarray:
    return ((frame["brand_homograph"] == 1) | (frame["brand_edit1"] == 1)).to_numpy()


# ---- one split -----------------------------------------------------------------------------------


def run_split(args, cfg, lists, exp) -> None:
    ctx = build_ctx(args, cfg, lists, {"split": exp["split"], "bar_points": exp["bar_points"]})
    k, out = ctx["k"], ctx["tables"]
    done = out / "DONE"
    if done.exists():
        log.info("split %d already done", k)
        return
    bm = BrandMismatch.from_lists(min_brand_len=exp["min_brand_len"])
    train, cal, sets = ctx["train"], ctx["cal"], dict(ctx["sets_f"])
    fitted = refit(train, lists)
    train = add_brand(train, bm)
    cal = add_brand(cal, bm)
    sets = {n: add_brand(f, bm) for n, f in sets.items()}
    if args.natural_csv and "natural" not in sets:  # a PC pool without a staged natural part
        used = {d for f in (train, cal, *sets.values()) for d in f["domain"]}
        sets["natural"] = natural_frame(args.natural_csv, lists, fitted, bm, used)
    targets, min_neg = ctx["targets"], ctx["min_neg"]
    rng = random.Random(exp["seed"] + k)

    train_brands, test_brands = split_brands(lists, exp, k)

    real_domains = set(train["domain"]) | set(cal["domain"])
    for f in sets.values():
        real_domains |= set(f["domain"])
    aug = augmentation(train, train_brands, bm, exp, lists, fitted, real_domains, rng)
    train_aug = pd.concat([train, aug], ignore_index=True)
    y0, w0 = train["label"].to_numpy(), train["weight"].to_numpy()
    ya, wa = train_aug["label"].to_numpy(), train_aug["weight"].to_numpy()

    natural = sets.get("natural")
    names = sorted(
        {
            p.label
            for p in (natural["_parts"] if natural is not None else [])
            if p and p.label.isalpha()
        }
        - bm.brands
    )
    names = [n for n in names if len(n) >= 4]
    unlisted = random.Random(exp["seed"]).sample(names, min(exp["unlisted_names"], len(names)))
    la = lookalike_test(test_brands, bm, exp, real_paths(ctx["test"]), unlisted, lists, fitted)
    # a generated name that is a real site (``chess.com`` from the suffix style) is not a look-alike
    la = la[~la["domain"].isin(real_domains)].reset_index(drop=True)
    clash = set(la["domain"]) & set(train_aug["domain"])
    if clash or set(test_brands) & {g[6:] for g in aug["domain"]}:
        raise LeakageError(f"look-alike test rows overlap training: {sorted(clash)[:5]}")

    # One table of every extra URL a model is scored on; scores are kept per URL so the merge
    # step can cut them any way (suffix mode, style, shape) without retraining.
    parts = [la.assign(set="lookalike")]
    if args.feed_json:
        for cat, urls in json.loads(Path(args.feed_json).read_text()).items():
            if cat in ("homoglyph", "edit1", "none"):
                frame = url_frame(urls, lists, fitted, bm)
                parts.append(frame[~frame["domain"].isin(real_domains)].assign(set=f"feed_{cat}"))
    near = {**sets, "cal": cal}  # legitimate rows whose name the brand rule would flag
    for n in ("test", "heldout_source", "natural", "cal"):
        f = near[n]
        parts.append(f[(f["label"] == 0) & rule_flag(f)].assign(set=f"near:{n}"))
    ev = pd.concat(parts, ignore_index=True)
    meta_cols = ["url", "set", "group", "style", "shape", "seen_style", "tld_mode", "brand"]
    meta = ev[meta_cols].assign(
        homograph=ev["brand_homograph"].to_numpy(), edit1=ev["brand_edit1"].to_numpy()
    )
    meta.to_parquet(out / "ev_meta.parquet", index=False)

    def evaluate_model(name, model, score_fn):
        t0 = time.monotonic()
        thr = _thresholds(cal["label"], score_fn(cal), targets, min_neg)
        base = {"split": k, "model": name}
        rows = _rows(base, sets, score_fn, targets, min_neg, thr)
        pd.DataFrame(rows).to_csv(out / f"main_{name}.csv", index=False)
        pd.DataFrame({"score": score_fn(ev)}).to_parquet(out / f"scores_{name}.parquet")
        pd.DataFrame(
            [
                {
                    "model": name,
                    "threshold_1pct": thr[targets[0]],
                    "threshold_0p1pct": thr[targets[1]],
                }
            ]
        ).to_csv(out / f"thr_{name}.csv", index=False)
        log.info("%s evaluated (%.0fs)", name, time.monotonic() - t0)

    def exists(name):
        return (out / f"main_{name}.csv").exists()

    want = set(args.models or MODELS)

    def save(name, model):
        if args.save_models:
            d = Path(args.save_models) / f"split_{k}"
            d.mkdir(parents=True, exist_ok=True)
            with open(d / f"{name}.pkl", "wb") as f:
                pickle.dump(model, f)

    if "E0" in want and not exists("E0"):
        e0 = make_hybrid(cfg, "hybrid2").fit(train, y0, w0)
        save("E0", e0)
        evaluate_model("E0", e0, e0.score)
        del e0
    for name in ("E1a", "E1b"):
        if name in want and not exists(name):
            f, y, w = (train, y0, w0) if name == "E1a" else (train_aug, ya, wa)
            m = CharAlone(cfg).fit(f, y, w)
            evaluate_model(name, m, m.score)
    if want & {"E2", "E3"} and not all(exists(n) for n in want & {"E2", "E3"}):
        e2 = make_hybrid(cfg, "hybrid2").fit(train_aug, ya, wa)
        save("E2", e2)
        evaluate_model("E2", e2, e2.score)
        if "E3" in want:
            e3 = e3_from_e2(e2, train_aug, ya, wa, cfg)
            evaluate_model("E3", e3, e3.score)
    # shuffled-label control (trees only, unweighted like experiments.tier_a)
    if not (out / "control.csv").exists():
        shuffled = np.random.default_rng(cfg["seed"] + k).permutation(ya)
        cols = [*NAMES, *COLUMNS] if "E3" in want else list(NAMES)
        g = GBDT("lightgbm", cfg["lightgbm"], cols, cfg["seed"]).fit(train_aug, shuffled)
        test = add_brand(ctx["test"], bm)
        r = evaluate(test["label"].to_numpy(), g.score(test), targets, min_neg)
        pd.DataFrame([{"split": k, "roc_auc": r["roc_auc"]}]).to_csv(
            out / "control.csv", index=False
        )
    pd.DataFrame(
        [
            {
                "split": k,
                "train_rows": len(train),
                "aug_rows": len(aug),
                "test_brands": len(test_brands),
                "lookalike_rows": len(la),
            }
        ]
    ).to_csv(out / "sizes.csv", index=False)
    done.write_text("ok")


# ---- merge ---------------------------------------------------------------------------------------


def _med_col(frame: pd.DataFrame, col: str) -> str:
    return _med(frame[col])


def _med(s: pd.Series) -> str:
    s = s.dropna()
    return (
        "n/a" if s.empty else f"{100 * s.median():.1f} [{100 * s.min():.1f}, {100 * s.max():.1f}]"
    )


def _load_ev(dirs: list[Path], models: tuple[str, ...] = MODELS) -> pd.DataFrame:
    """Per-URL table: meta, split, and for each model whether it warns / says dangerous."""
    frames = []
    for d in dirs:
        meta = pd.read_parquet(d / "ev_meta.parquet")
        meta["split"] = int(pd.read_csv(d / "sizes.csv")["split"].iloc[0])
        for m in models:
            thr = pd.read_csv(d / f"thr_{m}.csv").iloc[0]
            s = pd.read_parquet(d / f"scores_{m}.parquet")["score"].to_numpy()
            meta[m] = s >= thr["threshold_1pct"]
            meta[f"{m}_dangerous"] = s >= thr["threshold_0p1pct"]
        meta["rule"] = (meta["homograph"] == 1) | (meta["edit1"] == 1)
        meta["E3r"] = meta["E0"] | meta["rule"]
        frames.append(meta)
    return pd.concat(frames, ignore_index=True)


COLS = (*MODELS, "E3r")  # render() narrows this to the models that were run


def _rate(g: pd.DataFrame, col: str) -> str:
    n, k = len(g), int(g[col].sum())
    if not n:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{100 * k / n:.1f}% [{100 * lo:.0f}-{100 * hi:.0f}] (n={n})"


def _per_split(g: pd.DataFrame, col: str) -> str:
    r = g.groupby("split")[col].mean()
    n = g.groupby("split").size()
    if r.empty:
        return "n/a"
    return f"{100 * r.median():.1f} [{100 * r.min():.1f}, {100 * r.max():.1f}] (n={int(n.median())} per split)"


def _table(head: list[str], rows: list[tuple[list[str], pd.DataFrame]], fn, cols=None) -> list[str]:
    cols = cols or COLS
    out = ["| " + " | ".join([*head, *cols]) + " |", "|" + "---|" * (len(head) + len(cols))]
    for label, g in rows:
        if len(g):
            out.append("| " + " | ".join([*label, *(fn(g, c) for c in cols)]) + " |")
    return [*out, ""]


def render(root: Path, bar: float) -> str:
    dirs = sorted(d / "tables" for d in root.glob("split_*") if (d / "tables" / "DONE").exists())
    if not dirs:
        raise SystemExit("no finished split under " + str(root))

    def cat(prefix: str) -> pd.DataFrame:
        return pd.concat(
            [pd.read_csv(f) for d in dirs for f in sorted(d.glob(f"{prefix}*.csv"))],
            ignore_index=True,
        )

    main, sizes, control = cat("main_"), cat("sizes"), cat("control")
    global COLS
    models = tuple(m for m in MODELS if all((d / f"thr_{m}.csv").exists() for d in dirs))
    COLS = (*models, "E3r")
    ev = _load_ev(dirs, models)
    note = root / "data_note.txt"
    data = (
        note.read_text(encoding="utf-8").strip()
        if note.exists()
        else "the processed data given to the run"
    )
    splits = sorted(int(x) for x in main["split"].unique())
    L = [
        "# Brand look-alike experiments: " + ", ".join(models),
        "",
        "Generated by `python -m experiments.lookalike_a --render`. Do not edit by hand.",
        "",
        f"Splits {splits} of {data}. E0 here is retrained by this script, not the shipped model. "
        "Median [min, max] over the splits unless a count is "
        f"given. The {bar:g}-point bar is a proposal. Thresholds: cal-side 1% (suspicious) and 0.1% "
        "(dangerous) FPR points of the pool's calibration slice (natural look-alike-free rows).",
        "",
        f"Per split: {int(sizes['train_rows'].median()):,} training rows, "
        f"{int(sizes['aug_rows'].median()):,} look-alike/official rows added (E1b, E2, E3 where run), "
        f"{int(sizes['test_brands'].median())} held-out brands "
        f"({int(sizes['lookalike_rows'].median()):,} look-alike test URLs).",
        "",
        "`E3r` = E0 plus the old escalate-only rule (warn if E0 warns or the brand rule fires), "
        "suspicious level only. Look-alike tables pool the splits (each split has its own held-out "
        "brands); `own` = the brand's own suffix (paypa1.com), `other` = a random suffix.",
        "",
    ]
    L += [
        "## Main metrics (percent)",
        "",
        "| set | model | ROC-AUC | PR-AUC | recall @1% FPR (op) | recall @0.1% FPR (op) | cal 1%: recall / FPR / precision | cal 0.1%: recall / FPR |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for s in ("test", "heldout_source", "time_slice", "natural", "test_normalised"):
        for m in models:
            r = main[(main["eval_set"] == s) & (main["model"] == m)]
            if r.empty:
                continue
            fmt = partial(_med_col, r)
            L.append(
                f"| {s} | {m} | {r['roc_auc'].median():.4f} | {r['pr_auc'].median():.4f} | {fmt('op_1pct_recall')} "
                f"| {fmt('op_0p1pct_recall')} | {fmt('cal_1pct_recall')} / {fmt('cal_1pct_fpr')} / {fmt('cal_1pct_precision')} "
                f"| {fmt('cal_0p1pct_recall')} / {fmt('cal_0p1pct_fpr')} |"
            )
    L += [
        "",
        f"Change against E0 in recall at matched FPR (points; bar {bar:g}), median and range over splits:",
        "",
    ]
    for s in ("test", "heldout_source", "time_slice", "test_normalised"):
        for col, level in (("op_1pct_recall", "1%"), ("op_0p1pct_recall", "0.1%")):
            base = main[(main["eval_set"] == s) & (main["model"] == "E0")].set_index("split")
            for m in models[1:]:
                r = main[(main["eval_set"] == s) & (main["model"] == m)].set_index("split")
                d = 100 * (r[col] - base[col]).dropna()
                if not d.empty:
                    L.append(
                        f"- {s} at {level}, {m}: {d.median():+.1f} [{d.min():+.1f}, {d.max():+.1f}], "
                        f"higher in {int((d > 0).sum())} of {len(d)} splits"
                    )
    L += ["", "False alarms on natural legitimate pages at the cal-side 1% / 0.1% thresholds:", ""]
    for m in models:
        r = main[(main["eval_set"] == "natural") & (main["model"] == m)]
        if not r.empty:
            L.append(f"- {m}: {_med(r['cal_1pct_fpr'])} / {_med(r['cal_0p1pct_fpr'])}")

    la = ev[(ev["set"] == "lookalike") & (ev["group"] == "listed")]
    L += [
        "",
        "## Look-alikes of held-out brands: share warned (suspicious or worse)",
        "",
        "95% Wilson interval in brackets. `seen` = the style was in the training examples, "
        "`unseen` = held out. Brands the model never saw examples for in every row.",
        "",
    ]
    rows = []
    for mode in ("own", "other"):
        for seen in (True, False):
            for shape in ("bare", "login", "deep"):
                g = la[
                    (la["tld_mode"] == mode) & (la["seen_style"] == seen) & (la["shape"] == shape)
                ]
                rows.append(([mode, "seen" if seen else "unseen", shape], g))
    L += _table(["suffix", "styles", "shape"], rows, _rate)
    L += ["Per style, held-out brands, bare host, brand's own suffix (the `paypa1.com` case):", ""]
    rows = []
    for st in STYLES:
        g = la[(la["tld_mode"] == "own") & (la["shape"] == "bare") & (la["style"] == st)]
        rows.append(([st + (" (unseen)" if st in TEST_ONLY_STYLES else "")], g))
    L += _table(["style"], rows, _rate)
    L += ["Same, random suffix (`paypa1.xyz`):", ""]
    rows = []
    for st in STYLES:
        g = la[(la["tld_mode"] == "other") & (la["shape"] == "bare") & (la["style"] == st)]
        rows.append(([st + (" (unseen)" if st in TEST_ONLY_STYLES else "")], g))
    L += _table(["style"], rows, _rate)
    own = la[la["tld_mode"] == "own"]
    L += [
        "Dangerous (0.1% FPR threshold), own suffix, all shapes: "
        + "; ".join(f"{m} {_rate(own, f'{m}_dangerous')}" for m in models),
        "",
        "### Controls and the coverage ceiling",
        "",
        "Official domains of the same held-out brands (1 = false alarm):",
        "",
    ]
    off = ev[(ev["set"] == "lookalike") & (ev["group"] == "official")]
    L += _table(
        ["shape"], [([s], off[off["shape"] == s]) for s in ("bare", "login", "deep")], _rate
    )
    L += [
        "Names NOT on the brand list, made look-alike the same way (no brand to know; this is the ceiling):",
        "",
    ]
    un = ev[(ev["set"] == "lookalike") & (ev["group"] == "unlisted")]
    rows = [
        ([mode, shape], un[(un["tld_mode"] == mode) & (un["shape"] == shape)])
        for mode in ("own", "other")
        for shape in ("bare", "deep")
    ]
    L += _table(["suffix", "shape"], rows, _rate)

    L += [
        "## Real feed and legitimate near-neighbours (rate per split: median [min, max])",
        "",
        "Feed URLs: Phishing.Database ACTIVE feed, domains in the sample removed; they may partly "
        "overlap rows the PC model trained on. `feed_homoglyph` and `feed_edit1` are the feed URLs the "
        "brand rule fires on; `feed_none` has no brand signal. `near:*` = legitimate rows (pool test and "
        "calibration sides, held-out source, natural pages) where the brand rule fires: legitimate "
        "names that look like a brand's; warned = false alarm.",
        "",
    ]
    sets = [
        "feed_homoglyph",
        "feed_edit1",
        "feed_none",
        "near:test",
        "near:cal",
        "near:heldout_source",
        "near:natural",
    ]
    L += _table(["set"], [([s], ev[ev["set"] == s]) for s in sets], _per_split)
    near = ev[ev["set"].str.startswith("near:")]
    top = "E3" if "E3" in models else "E2"
    flagged = near[near[top] & ~near["E0"]][["split", "set", "url", "homograph", "edit1"]]
    flagged.drop_duplicates(["set", "url"]).to_csv(
        root / f"near_flagged_by_{top}_not_E0.csv", index=False
    )
    L += [
        f"Legitimate near-neighbour URLs flagged by {top} but not by E0: {len(flagged.drop_duplicates(['set', 'url']))} "
        f"of {near.drop_duplicates(['set', 'url']).shape[0]} distinct (list in `near_flagged_by_{top}_not_E0.csv`).",
        "",
    ]
    auc = control["roc_auc"]
    L += [
        "Shuffled-label control (trees on the tier A features"
        + (" + brand columns" if "E3" in models else "")
        + ", labels shuffled over train + look-alike rows), "
        f"test ROC-AUC: {auc.mean():.4f} over {len(auc)} splits "
        f"({'FLAGGED' if abs(auc.mean() - 0.5) > 0.05 else 'not flagged'}, limit 0.05).",
        "",
    ]
    hot = main[
        main["eval_set"].isin(["heldout_source"])
        & ((main["roc_auc"] > 0.99) | (main["op_1pct_recall"] > 0.99))
    ]
    L.append(
        "Leakage tripwire (held-out source above 99%): "
        + ("TRIGGERED for " + str(sorted(hot["model"].unique())) if len(hot) else "not triggered")
        + "."
    )
    return "\n".join(L) + "\n"


def natural_frame(csv: Path, lists: Lists, fitted: Fitted, bm: BrandMismatch, used: set[str]):
    """Naturally browsed legitimate pages (evaluation only), minus domains seen anywhere in the run."""
    nat = pd.read_csv(csv)
    nat = nat[nat["ok"].astype(str).str.lower() == "true"].drop_duplicates("url")
    nat = nat[~nat["domain"].isin(used)].reset_index(drop=True)
    frame = url_frame(nat["url"].tolist(), lists, fitted, bm)
    frame["label"], frame["source"], frame["weight"] = 0, "natural", 1.0
    frame["depth"] = nat["url"].str.replace(r"^[a-z]+://[^/]+", "", regex=True).str.count(r"/[^/]")
    return frame


def make_feed_json(feed_txt: Path, out_json: Path, exp: dict, args) -> None:
    """One URL per registrable domain of a feed file, grouped by what the brand rule says."""
    lists = load_lists(args.lists_dir, args.platforms_file)
    bm = BrandMismatch.from_lists(min_brand_len=exp["min_brand_len"])
    seen: set[str] = set()
    groups: dict[str, list[str]] = {"homoglyph": [], "edit1": [], "none": []}
    for line in feed_txt.read_text(encoding="utf-8", errors="ignore").splitlines():
        url = line.strip()
        parts = parse(url, lists.platforms) if url else None
        if parts is None or parts.domain in seen:
            continue
        seen.add(parts.domain)
        f = bm.features(parts)
        if f["brand_homograph"] == 1:
            groups["homoglyph"].append(url)
        elif f["brand_edit1"] == 1:
            groups["edit1"].append(url)
        elif f["brand_other_suffix"] == 0 and f["brand_official"] == 0:
            groups["none"].append(url)
    groups["none"] = random.Random(exp["seed"]).sample(
        groups["none"], min(exp["feed_sample"], len(groups["none"]))
    )
    out_json.write_text(json.dumps(groups), encoding="utf-8")
    print(out_json, {k: len(v) for k, v in groups.items()})


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.lookalike_a")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--reports", type=Path, default=Path("reports/lookalike"))
    ap.add_argument("--split", type=int, default=None)
    ap.add_argument("--smoke", type=int, default=0)
    ap.add_argument("--feed-json", default=None)
    ap.add_argument("--make-feed-json", nargs=2, metavar=("FEED_TXT", "OUT_JSON"), default=None)
    ap.add_argument("--models", nargs="*", choices=MODELS, default=None)
    ap.add_argument("--save-models", default=None, help="pickle E0/E2 here (never a shipped path)")
    ap.add_argument("--data-note", default=None)
    ap.add_argument("--natural-csv", type=Path, default=None, help="configs/eval/ood_urls.csv")
    ap.add_argument("--lists-dir", default=None)
    ap.add_argument("--platforms-file", default=None)
    ap.add_argument("--render", action="store_true")
    a = ap.parse_args(argv)
    exp = load_config("lookalike_exp")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    if a.make_feed_json:
        make_feed_json(Path(a.make_feed_json[0]), Path(a.make_feed_json[1]), exp, a)
        return 0
    if a.data_note:
        a.reports.mkdir(parents=True, exist_ok=True)
        (a.reports / "data_note.txt").write_text(a.data_note, encoding="utf-8")
    if a.render:
        text = render(a.reports, exp["bar_points"])
        (a.reports / "SUMMARY.md").write_text(text, encoding="utf-8")
        print(text)
        return 0
    k = exp["split"] if a.split is None else a.split
    a.split = k
    root = a.reports
    a.reports = root / f"split_{k}"
    run_split(a, load_config("models"), load_lists(a.lists_dir, a.platforms_file), exp)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
