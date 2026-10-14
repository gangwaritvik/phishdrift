"""Shipped page model: blend, fair HTML numbers, two-check rule and source-robust thresholds.

python -m experiments.blend2 [--processed data/processed] [--reports reports] [--splits ...]
    [--ood-csv data/raw/ood/ood_urls.csv] [--ood-html-dir data/raw/ood_html] [--save-models DIR]

Per split k (train side for fitting, cal side for calibration and thresholds):

- ``a``  address model: tier A hybrid2 (the model in the extension);
- ``b``  page model: ``models.page_model.PageModel``, LightGBM on the tier A + tier B features
  and ``a``'s text scores (out-of-fold on the train rows), fitted on train rows with usable HTML.
  It shares ``a``'s text scorers, so the browser needs one set of vocabularies.

Both scores are isotonic-calibrated on the cal side (``b`` on cal rows with HTML) with a 1e-9 *
raw tie-break so equal calibrated values keep the raw order. ``blend`` = calibrated ``b`` where
the page has HTML, calibrated ``a`` otherwise; its thresholds come from the pooled blended cal
scores. Four questions, one table each:

1. ``blend2.md``: blend vs address only on test, newest time slice and held-out source, split by
   whether the URL has usable HTML (same layout as ``reports/blend.md``).
2. Fair HTML numbers (``blend2_fair.md``). Usable HTML is more common on legitimate than on
   phishing pages, so the phishing pages with HTML may be an easier subset. Measured on the
   sources that saved HTML at collection time: (a) the address model's recall on phishing with vs
   without HTML (if it is higher on the HTML rows, those rows are easier), (b) recall on the HTML
   rows re-weighted by inverse propensity: P(usable HTML | URL features, source) is fitted on the
   train side per class, and each test row with HTML gets weight 1/p (clipped), which estimates
   the recall had every page had usable HTML, assuming HTML loss depends only on what the URL
   features and source capture (an assumption, not a measurement), and (c) the end-to-end
   PhreshPhish result where pages without HTML fall back to the address model.
3. Verdict rules (``blend2_rules.md``): the share of phishing warned (suspicious or worse) and
   of legitimate pages warned, and the same for dangerous, under
   ``a_only`` (address model, its own thresholds), ``blend``, ``shipped`` (what the extension
   does: the address model's dangerous verdict acts before the page loads, then the blend), and
   ``agree`` (shipped, but a suspicious banner on a page with HTML needs both the page model and
   the address model over their 1% thresholds; dangerous unchanged). Also on the naturally
   browsed legitimate pages (``ood_urls`` address only, ``ood_html`` with HTML).
4. Source-robust thresholds (in the same rules table, ``*_ws``): instead of the pooled cal 1% /
   0.1% points, take each source's own cal point (sources with enough legitimate rows for the
   target) and use the highest, so no known source exceeds the target on cal.

One file per split and table under ``reports/tables/blend2_*/split_<k>.csv``.
"""

from __future__ import annotations

import argparse
import logging
import math
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.isotonic import IsotonicRegression

from data_pipeline.split import CAL, TEST, TRAIN
from experiments.blend import with_page_features
from experiments.hybrid_a import make_hybrid
from experiments.metrics import evaluate, operating_point
from experiments.ood_fpr import load_ood
from experiments.ood_fpr_b import load_ood_b
from experiments.tier_a import _fmt, apply_fitted, assert_no_overlap, load_part, refit
from features.lists import load_lists
from features.registry import NAMES, NAMES_B
from models.page_model import PageModel
from phishdrift.config import load_config

log = logging.getLogger("blend2")

TIE = 1e-9
HTML_SOURCES = ("phreshphish", "phishpedia", "phishblitz")  # saved HTML at collection time
FAIR_SOURCE = "phreshphish"  # the only source with collection-time HTML for both classes
MAX_IPW = 20.0
RULES = ("a_only", "blend", "shipped", "agree", "a_only_ws", "shipped_ws", "agree_ws")
TABLES = ("blend2_runs", "blend2_rules", "blend2_fair", "blend2_thresholds")


class Calibrated:
    """Isotonic map plus a tiny raw tie-break, fitted on the cal side."""

    def __init__(self, raw: np.ndarray, y: np.ndarray):
        self.iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(raw, y)

    def __call__(self, raw: np.ndarray) -> np.ndarray:
        return self.iso.predict(raw) + TIE * np.asarray(raw)


def worst_source_threshold(frame, score, target, min_neg) -> tuple[float, str]:
    """Highest per-source cal threshold for ``target`` among sources with enough negatives."""
    best, who = -math.inf, ""
    for src, idx in frame.groupby("source").indices.items():
        y = frame["label"].to_numpy()[idx]
        n_neg = int((y == 0).sum())
        if math.floor(target * n_neg) < min_neg or y.sum() == 0:
            continue
        thr = operating_point(y, score[idx], target, min_neg)["threshold"]
        if thr > best:
            best, who = thr, src
    return best, who


def propensity(train: pd.DataFrame) -> dict[int, HistGradientBoostingClassifier]:
    """P(usable HTML | tier A features, source) per class, on train rows of HTML sources."""
    out = {}
    rows = train[train["source"].isin(HTML_SOURCES)]
    for label in (0, 1):
        r = rows[rows["label"] == label]
        if r["has_html"].nunique() < 2:
            continue
        x = _prop_x(r)
        out[label] = HistGradientBoostingClassifier(max_iter=200, random_state=0).fit(
            x, r["has_html"].to_numpy()
        )
    return out


def _prop_x(frame: pd.DataFrame) -> np.ndarray:
    src = np.stack([(frame["source"] == s).to_numpy() for s in HTML_SOURCES], axis=1)
    return np.hstack([frame[list(NAMES)].to_numpy(np.float32), src.astype(np.float32)])


class Scored:
    """Calibrated scores of one set under both models, plus the verdict flags of every rule."""

    def __init__(self, frame, a, b, cal_a, cal_b):
        text = a.text_scores(frame)
        self.html = frame["has_html"].to_numpy()
        self.ca = cal_a(a.gbdt.score(frame.assign(**text)))
        self.cb = np.full(len(frame), np.nan)
        if self.html.any():
            sub = frame[self.html]
            sub_text = {k: v[self.html] for k, v in text.items()}
            self.cb[self.html] = cal_b(b.score(sub, sub_text))
        self.blend = np.where(self.html, self.cb, self.ca)

    def flags(self, rule: str, thr: dict) -> tuple[np.ndarray, np.ndarray]:
        """(warned = suspicious or worse, dangerous) under one rule."""
        ws = rule.endswith("_ws")
        base = rule.removesuffix("_ws")
        a1, a01 = thr["a_ws" if ws else "a"]
        t1, t01 = thr["blend_ws" if ws else "blend"]
        if base == "a_only":
            return self.ca >= a1, self.ca >= a01
        if base == "blend":
            return self.blend >= t1, self.blend >= t01
        danger = (self.blend >= t01) | (self.ca >= a01)
        if base == "shipped":
            return (self.blend >= t1) | danger, danger
        # agree: on pages with HTML the banner needs both models
        warn_html = (self.cb >= t1) & (self.ca >= a1)
        warn = np.where(self.html, warn_html, self.blend >= t1) | danger
        return warn, danger


def _rates(y, m, warn, danger) -> dict:
    pos, neg = m & (y == 1), m & (y == 0)
    n_pos, n_neg = int(pos.sum()), int(neg.sum())
    return {
        "n_pos": n_pos,
        "n_neg": n_neg,
        "warn_recall": warn[pos].mean() if n_pos else np.nan,
        "warn_fpr": warn[neg].mean() if n_neg else np.nan,
        "danger_recall": danger[pos].mean() if n_pos else np.nan,
        "danger_fpr": danger[neg].mean() if n_neg else np.nan,
    }


def run_split(k, pool, splits, extra, ood, lists, cfg, save_dir=None) -> dict[str, list[dict]]:
    targets, min_neg = cfg["eval"]["target_fprs"], cfg["eval"]["min_negatives"]
    side = splits[f"split_{k}"].to_numpy()
    train, cal, test = (pool[side == s] for s in (TRAIN, CAL, TEST))
    for name, other in {"cal": cal, "test": test, **extra, **ood}.items():
        assert_no_overlap(train, other, "train", name)
    for name, other in {"test": test, **ood}.items():
        assert_no_overlap(cal, other, "cal", name)
    t0 = time.monotonic()
    fitted = refit(train, lists)
    train, cal, test = (apply_fitted(f, fitted) for f in (train, cal, test))
    sets = {"test": test} | {n: apply_fitted(f, fitted) for n, f in extra.items()}
    ood = {n: apply_fitted(f, fitted) for n, f in ood.items()}

    y, w = train["label"].to_numpy(), train["weight"].to_numpy()
    a = make_hybrid(cfg, "hybrid2").fit(train, y, w)
    b = PageModel(a, cfg["lightgbm"], cfg["seed"]).fit(train, y, w, train["has_html"].to_numpy())
    log.info("split %d fitted: %.0fs", k, time.monotonic() - t0)

    # calibration on the cal side
    yc, ch = cal["label"].to_numpy(), cal["has_html"].to_numpy()
    text = a.text_scores(cal)
    raw_a = a.gbdt.score(cal.assign(**text))
    raw_b = b.score(cal[ch], {n: v[ch] for n, v in text.items()})
    cal_a, cal_b = Calibrated(raw_a, yc), Calibrated(raw_b, yc[ch])
    sc = Scored(cal, a, b, cal_a, cal_b)
    thr, thr_rows = {}, []
    for name, s in (("a", sc.ca), ("blend", sc.blend)):
        thr[name] = tuple(operating_point(yc, s, t, min_neg)["threshold"] for t in targets)
        ws = [worst_source_threshold(cal, s, t, min_neg) for t in targets]
        thr[name + "_ws"] = tuple(max(p, wt) for p, (wt, _) in zip(thr[name], ws, strict=True))
        for t, pooled, (wt, src) in zip(targets, thr[name], ws, strict=True):
            thr_rows.append(
                {"split": k, "score": name, "target_fpr": t, "pooled": pooled}
                | {"worst_source": wt, "worst_source_name": src}
            )

    if save_dir is not None:
        save_dir.mkdir(parents=True, exist_ok=True)
        with open(save_dir / f"blend2_split_{k}.pkl", "wb") as fh:
            pickle.dump(
                {"a": a, "b": b, "cal_a": cal_a, "cal_b": cal_b, "fitted": fitted, "thr": thr}
                | {"targets": targets},
                fh,
            )

    runs, rules, fair = [], [], []
    scored = {n: Scored(f, a, b, cal_a, cal_b) for n, f in sets.items()}
    scored |= {n: Scored(f, a, b, cal_a, cal_b) for n, f in ood.items()}
    frames = sets | ood

    # 1. score metrics (same layout as reports/blend.md)
    for set_name, frame in sets.items():
        s = scored[set_name]
        yy = frame["label"].to_numpy()
        for model, score, thr_key in (("blend", s.blend, "blend"), ("a_only", s.ca, "a")):
            cal_thr = dict(zip(targets, thr[thr_key], strict=True))
            for tag, m in (("", np.ones(len(yy), bool)), (":html", s.html), (":nohtml", ~s.html)):
                if not m.any():
                    continue
                r = evaluate(yy[m], score[m], targets, min_neg, cal_thr)
                n_dom = frame.loc[m, "domain"].nunique()
                runs.append(
                    {"split": k, "model": model, "eval_set": set_name + tag, "n_domains": n_dom} | r
                )

    # 3 + 4. verdict rules on every set, incl. the natural legitimate pages
    for set_name, frame in frames.items():
        s = scored[set_name]
        yy = frame["label"].to_numpy()
        groups = {"": np.ones(len(yy), bool), ":html": s.html, ":nohtml": ~s.html}
        if set_name == "test":
            src = frame["source"].to_numpy()
            groups[f":{FAIR_SOURCE}"] = src == FAIR_SOURCE
            groups[f":{FAIR_SOURCE}:html"] = (src == FAIR_SOURCE) & s.html
        for rule in RULES:
            warn, danger = s.flags(rule, thr)
            for tag, m in groups.items():
                if not m.any():
                    continue
                n_dom = frame.loc[m, "domain"].nunique()
                rules.append(
                    {"split": k, "rule": rule, "eval_set": set_name + tag, "n_urls": int(m.sum())}
                    | {"n_domains": n_dom}
                    | _rates(yy, m, warn, danger)
                )

    # 2. fair HTML numbers on test and the time slice
    props = propensity(train)
    for set_name in ("test", "time_slice"):
        if set_name not in sets:
            continue
        frame, s = sets[set_name], scored[set_name]
        yy = frame["label"].to_numpy()
        in_src = frame["source"].isin(HTML_SOURCES).to_numpy()
        fair_src = (frame["source"] == FAIR_SOURCE).to_numpy()
        a_warn, _ = s.flags("a_only", thr)
        sh_warn, sh_danger = s.flags("shipped", thr)
        bl_warn, bl_danger = s.flags("blend", thr)
        row = {"split": k, "eval_set": set_name}
        for label, cls in ((1, "phish"), (0, "legit")):
            c = in_src & (yy == label)
            h, nh = c & s.html, c & ~s.html
            row[f"{cls}_n"] = int(c.sum())
            row[f"{cls}_html_share"] = h.sum() / c.sum() if c.any() else np.nan
            row[f"{cls}_fair_html_share"] = (
                (fair_src & s.html & (yy == label)).sum() / (fair_src & (yy == label)).sum()
                if (fair_src & (yy == label)).any()
                else np.nan
            )
            row[f"a_{cls}_warn_html"] = a_warn[h].mean() if h.any() else np.nan
            row[f"a_{cls}_warn_nohtml"] = a_warn[nh].mean() if nh.any() else np.nan
            row[f"blend_{cls}_warn_html"] = bl_warn[h].mean() if h.any() else np.nan
            row[f"blend_{cls}_danger_html"] = bl_danger[h].mean() if h.any() else np.nan
            if label in props and h.any():
                p = props[label].predict_proba(_prop_x(frame[h]))[:, 1]
                wt = np.minimum(1.0 / np.maximum(p, 1e-6), MAX_IPW)
                row[f"blend_{cls}_warn_html_ipw"] = float(np.average(bl_warn[h], weights=wt))
                row[f"blend_{cls}_danger_html_ipw"] = float(np.average(bl_danger[h], weights=wt))
                row[f"a_{cls}_warn_html_ipw"] = float(np.average(a_warn[h], weights=wt))
                row[f"{cls}_ipw_ess"] = float(wt.sum() ** 2 / (wt**2).sum())
            f = fair_src & (yy == label)
            row[f"shipped_{cls}_warn_{FAIR_SOURCE}"] = sh_warn[f].mean() if f.any() else np.nan
            row[f"shipped_{cls}_danger_{FAIR_SOURCE}"] = sh_danger[f].mean() if f.any() else np.nan
            row[f"a_{cls}_warn_{FAIR_SOURCE}"] = a_warn[f].mean() if f.any() else np.nan
        fair.append(row)
    log.info("split %d done: %.0fs", k, time.monotonic() - t0)
    return {
        "blend2_runs": runs,
        "blend2_rules": rules,
        "blend2_fair": fair,
        "blend2_thresholds": thr_rows,
    }


# --- reports ---------------------------------------------------------------------------------


def _med(g: pd.Series, pct: bool = True) -> str:
    return f"{_fmt(g.median(), pct)} [{_fmt(g.min(), pct)}, {_fmt(g.max(), pct)}]"


def render_runs(runs: pd.DataFrame) -> str:
    lines = [
        "# Shipped page model: blend of page model (HTML) and address model",
        "",
        "Generated by `python -m experiments.blend2`. Do not edit by hand.",
        "Page model = LightGBM on address + page features and the address model's text scores",
        "(`models/page_model.py`, the model in the extension). `blend` uses it where the page has",
        "usable HTML and the address model otherwise; thresholds from the pooled blended cal",
        "scores. Median over splits [min, max].",
        "",
        "| set | model | splits | URLs | domains | ROC-AUC | recall @1% FPR | recall @0.1% FPR "
        "| cal 1%: recall / FPR | cal 0.1%: recall / FPR |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for (set_name, model), g in runs.groupby(["eval_set", "model"], sort=False):
        lines.append(
            f"| {set_name} | {model} | {len(g)} | {int(g['n_urls'].median()):,} "
            f"| {int(g['n_domains'].median()):,} | {_med(g['roc_auc'], False)} "
            f"| {_med(g['op_1pct_recall'])} | {_med(g['op_0p1pct_recall'])} "
            f"| {_fmt(g['cal_1pct_recall'].median())} / {_fmt(g['cal_1pct_fpr'].median())} "
            f"| {_fmt(g['cal_0p1pct_recall'].median())} / {_fmt(g['cal_0p1pct_fpr'].median())} |"
        )
    return "\n".join(lines + [""])


RULE_TEXT = {
    "a_only": "address model only, its own cal thresholds",
    "blend": "page model where there is HTML, address model otherwise",
    "shipped": "what the extension does: address-model dangerous acts before the page loads, "
    "then the blend",
    "agree": "shipped, but a suspicious banner on a page with HTML needs both models",
    "a_only_ws": "a_only with source-robust thresholds",
    "shipped_ws": "shipped with source-robust thresholds",
    "agree_ws": "agree with source-robust thresholds",
}


def render_rules(rules: pd.DataFrame, thr: pd.DataFrame) -> str:
    lines = [
        "# Verdict rules: warnings on phishing and on legitimate pages",
        "",
        "Generated by `python -m experiments.blend2`. Do not edit by hand.",
        "`warn` = suspicious or dangerous (banner or warning page), `danger` = dangerous only.",
        "Phishing columns are the share of phishing URLs warned (recall), legitimate columns the",
        "share of legitimate URLs warned (false alarms). `ood_urls` / `ood_html` are naturally",
        "browsed legitimate pages outside every set (address only / with usable HTML). Allowlist",
        "and blocklist are off. Median over splits [min, max].",
        "",
    ]
    lines += [f"- `{r}`: {RULE_TEXT[r]}" for r in RULES]
    lines += [
        "- source-robust (`_ws`): each source's own cal 1% / 0.1% threshold, highest one used",
        "",
        "| set | rule | splits | URLs | phishing warned | legit warned | phishing dangerous "
        "| legit dangerous |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for (set_name, rule), g in rules.groupby(["eval_set", "rule"], sort=False):
        lines.append(
            f"| {set_name} | {rule} | {len(g)} | {int(g['n_urls'].median()):,} "
            f"| {_med(g['warn_recall'])} | {_med(g['warn_fpr'])} "
            f"| {_med(g['danger_recall'])} | {_med(g['danger_fpr'])} |"
        )
    lines += [
        "",
        "## Thresholds (calibrated scale): pooled cal point vs highest per-source cal point",
        "",
        "| score | target FPR | splits | pooled | source-robust | source that sets it (count) |",
        "|---|---|---|---|---|---|",
    ]
    for (score, t), g in thr.groupby(["score", "target_fpr"], sort=False):
        who = g["worst_source_name"].value_counts()
        lines.append(
            f"| {score} | {t:.1%} | {len(g)} | {g['pooled'].median():.4f} "
            f"| {g['worst_source'].median():.4f} "
            f"| {', '.join(f'{n} ({c})' for n, c in who.items())} |"
        )
    return "\n".join(lines + [""])


def render_fair(fair: pd.DataFrame) -> str:
    def m(col, pct=True):
        ok = col in fair_g and fair_g[col].notna().any()
        return _med(fair_g[col], pct) if ok else "n/a"

    lines = [
        "# Fair HTML numbers",
        "",
        "Generated by `python -m experiments.blend2`. Do not edit by hand.",
        f"Sources that saved HTML at collection time ({', '.join(HTML_SOURCES)}); "
        f"`{FAIR_SOURCE}` is the only one with both classes.",
        "Rates are at the cal-side 1% (`warned`) and 0.1% (`dangerous`) thresholds.",
        "IPW: each HTML row weighted by 1 / P(usable HTML | URL features, source), fitted on the",
        f"train side per class, clipped at {MAX_IPW:g}; it estimates the rate had every page had",
        "usable HTML, under the assumption that HTML loss depends only on what the URL features",
        "and source capture. ESS = effective sample size of the weights. Median over splits",
        "[min, max].",
        "",
    ]
    for set_name, fair_g in fair.groupby("eval_set", sort=False):
        lines += [
            f"## {set_name}",
            "",
            "| quantity | phishing | legitimate |",
            "|---|---|---|",
            f"| rows in these sources | {int(fair_g['phish_n'].median()):,} "
            f"| {int(fair_g['legit_n'].median()):,} |",
            f"| share with usable HTML | {m('phish_html_share')} | {m('legit_html_share')} |",
            f"| share with usable HTML, {FAIR_SOURCE} | {m('phish_fair_html_share')} "
            f"| {m('legit_fair_html_share')} |",
            f"| address model warned: rows with HTML | {m('a_phish_warn_html')} "
            f"| {m('a_legit_warn_html')} |",
            f"| address model warned: rows without HTML | {m('a_phish_warn_nohtml')} "
            f"| {m('a_legit_warn_nohtml')} |",
            f"| address model warned: rows with HTML, IPW | {m('a_phish_warn_html_ipw')} "
            f"| {m('a_legit_warn_html_ipw')} |",
            f"| blend warned: rows with HTML (as reported) | {m('blend_phish_warn_html')} "
            f"| {m('blend_legit_warn_html')} |",
            f"| blend warned: rows with HTML, IPW (fair) | {m('blend_phish_warn_html_ipw')} "
            f"| {m('blend_legit_warn_html_ipw')} |",
            f"| blend dangerous: rows with HTML | {m('blend_phish_danger_html')} "
            f"| {m('blend_legit_danger_html')} |",
            f"| blend dangerous: rows with HTML, IPW (fair) | {m('blend_phish_danger_html_ipw')} "
            f"| {m('blend_legit_danger_html_ipw')} |",
            f"| IPW effective sample size | {m('phish_ipw_ess', False)} "
            f"| {m('legit_ipw_ess', False)} |",
            f"| {FAIR_SOURCE} end to end, shipped warned (no HTML -> address model) "
            f"| {m(f'shipped_phish_warn_{FAIR_SOURCE}')} "
            f"| {m(f'shipped_legit_warn_{FAIR_SOURCE}')} |",
            f"| {FAIR_SOURCE} end to end, shipped dangerous "
            f"| {m(f'shipped_phish_danger_{FAIR_SOURCE}')} "
            f"| {m(f'shipped_legit_danger_{FAIR_SOURCE}')} |",
            f"| {FAIR_SOURCE}, address model only warned | {m(f'a_phish_warn_{FAIR_SOURCE}')} "
            f"| {m(f'a_legit_warn_{FAIR_SOURCE}')} |",
            "",
        ]
    return "\n".join(lines)


def write_reports(reports: Path) -> Path:
    tables = reports / "tables"
    data = {}
    for name in TABLES:
        parts = sorted((tables / name).glob("split_*.csv"))
        if not parts:
            return reports / "blend2.md"
        data[name] = pd.concat([pd.read_csv(p) for p in parts], ignore_index=True)
        data[name].to_csv(tables / f"{name}.csv", index=False)
    (reports / "blend2.md").write_text(render_runs(data["blend2_runs"]), encoding="utf-8")
    (reports / "blend2_rules.md").write_text(
        render_rules(data["blend2_rules"], data["blend2_thresholds"]), encoding="utf-8"
    )
    (reports / "blend2_fair.md").write_text(render_fair(data["blend2_fair"]), encoding="utf-8")
    return reports / "blend2.md"


def run(processed, reports, split_ids, lists, ood_csv, ood_html_dir, save_dir=None) -> Path:
    cfg = load_config("models")
    for name in TABLES:
        (reports / "tables" / name).mkdir(parents=True, exist_ok=True)
    ood = {}
    if ood_csv:
        urls = load_ood(ood_csv, lists)
        ood["ood_urls"] = urls.assign(**{c: np.nan for c in NAMES_B}, has_html=False)
    if ood_html_dir:
        pages, _ = load_ood_b(ood_html_dir, lists)
        ood["ood_html"] = pages.assign(has_html=True)
    pool = with_page_features(load_part(processed, "pool", lists), processed, "pool")
    extra = {
        p: with_page_features(load_part(processed, p, lists), processed, p)
        for p in ("time_slice", "heldout_source")
    }
    splits = pd.read_parquet(processed / "splits.parquet")
    splits = pool[["uid"]].merge(splits, on="uid", how="left", validate="one_to_one")
    n_splits = sum(c.startswith("split_") for c in splits.columns)
    for k in split_ids if split_ids is not None else range(n_splits):
        outs = {n: reports / "tables" / n / f"split_{k}.csv" for n in TABLES}
        if all(p.exists() for p in outs.values()):
            continue
        result = run_split(k, pool, splits, extra, ood, lists, cfg, save_dir)
        for name, rows in result.items():
            tmp = outs[name].with_suffix(".tmp")
            pd.DataFrame(rows).to_csv(tmp, index=False)
            tmp.replace(outs[name])
        write_reports(reports)
        log.info("split %d written", k)
    return write_reports(reports)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.blend2")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--splits", type=int, nargs="*", default=None)
    ap.add_argument("--ood-csv", type=Path, default=None, help="crawl-ood first pass ood_urls.csv")
    ap.add_argument("--ood-html-dir", type=Path, default=None, help="crawl-ood --html-pass folder")
    ap.add_argument("--save-models", type=Path, default=None, help="pickle models here")
    ap.add_argument("--lists-dir", default=None)
    ap.add_argument("--platforms-file", default=None)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    lists = load_lists(a.lists_dir, a.platforms_file)
    print(run(a.processed, a.reports, a.splits, lists, a.ood_csv, a.ood_html_dir, a.save_models))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
