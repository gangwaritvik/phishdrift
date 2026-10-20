# ruff: noqa: E501
"""Turn the per-job result files into verdicts and the study report (reports/phishguard/).

Every number in ``verification.md`` comes from the result files; nothing is typed by hand.
"""

from __future__ import annotations

import math
import pickle
from itertools import combinations
from pathlib import Path

import numpy as np
import pandas as pd

from phishguard.data import REPS


def load(out: Path, part: str) -> list[dict]:
    return [pickle.loads(p.read_bytes()) for p in sorted((out / "results" / part).glob("*/*.pkl"))]


def runs_table(results: list[dict]) -> pd.DataFrame:
    rows = []
    for r in results:
        for (rep, m), v in r["runs"].items():
            rows.append(
                {
                    "cell": r["cell"],
                    "split": r["split"],
                    "rep": rep,
                    "model": m,
                    **{
                        k: x
                        for k, x in v.items()
                        if k not in ("draws", "draws_depth", "thresholds")
                    },
                    "_draws": v["draws"],
                    "_draws_depth": v["draws_depth"],
                }
            )
    return pd.DataFrame(rows)


def testable(results: list[dict], cfg: dict) -> set[str]:
    t = cfg["testable"]
    c = pd.DataFrame([{"cell": r["cell"], **r["counts"]} for r in results]).groupby("cell").median()
    c = c[[k for k in c.columns if k != "platform_share"]]
    ok = (c[["urls_0", "urls_1"]].min(axis=1) >= t["min_urls_per_class"]) & (
        c[["domains_0", "domains_1"]].min(axis=1) >= t["min_domains_per_class"]
    )
    return set(c.index[ok])


def holds(
    effects: np.ndarray,
    draws: np.ndarray,
    cfg: dict,
    direction: int | None = None,
    null: float = 0.0,
) -> tuple[bool, int, float, float, float]:
    """Effect has its direction in >= min splits AND the pooled bootstrap interval excludes null.
    Direction defaults to the sign of the median effect (for contrasts with no expected sign)."""
    effects = effects[~np.isnan(effects)]
    draws = draws[~np.isnan(draws)]
    med = float(np.median(effects)) if len(effects) else math.nan
    if not len(effects) or not len(draws):
        return False, 0, med, math.nan, math.nan
    d = direction if direction is not None else (1 if med >= null else -1)
    same = int(((effects - null) * d > 0).sum())
    a = (1 - cfg["holds"]["ci"]) / 2
    lo, hi = (float(x) for x in np.quantile(draws, [a, 1 - a]))
    ci_ok = lo > null if d > 0 else hi < null
    return same >= cfg["holds"]["min_splits_same_sign"] and ci_ok, same, med, lo, hi


def verdict(flags: list[bool], cfg: dict) -> str:
    v = cfg["verdict"]
    if len(flags) < v["min_settings"]:
        return "not testable"
    share = sum(flags) / len(flags)
    return (
        "replicated"
        if share >= v["replicated"]
        else "partly replicated"
        if share >= v["partly"]
        else "not replicated"
    )


def _pivot(runs: pd.DataFrame, col: str) -> dict:
    return {
        (c, r, m): g.sort_values("split")[col].to_numpy()
        for (c, r, m), g in runs.groupby(["cell", "rep", "model"])
    }


def _draws(runs: pd.DataFrame, col: str = "_draws") -> dict:
    return {
        (c, r, m): np.stack(g.sort_values("split")[col].to_list())
        for (c, r, m), g in runs.groupby(["cell", "rep", "model"])
    }


def findings_a(results: list[dict], cfg: dict) -> tuple[dict[str, pd.DataFrame], set[str]]:
    runs = runs_table(results)
    ok = testable(results, cfg)
    auc, dr = _pivot(runs, "roc_auc"), _draws(runs)
    aucd, drd = _pivot(runs, "auc_depth"), _draws(runs, "_draws_depth")
    cells = sorted(ok)
    plat = (
        pd.DataFrame([{"cell": r["cell"], "p": r["counts"]["platform_share"]} for r in results])
        .groupby("cell")["p"]
        .median()
        .to_dict()
    )
    models = cfg["models_a"]
    out: dict[str, list] = {
        k: [] for k in ("F1", "F2", "F3", "F3_depth", "H5", "F4", "HP", "H6", "OOD", "controls")
    }
    for c, m in ((c, m) for c in cells for m in models):
        if (c, "R1", m) not in auc:
            continue
        e = auc[(c, "R1", m)] - auc[(c, "R4", m)]
        h = holds(e, (dr[(c, "R1", m)] - dr[(c, "R4", m)]).ravel(), cfg, 1)
        out["F1"].append(
            _row(c, m, h, R1=np.median(auc[(c, "R1", m)]), R4=np.median(auc[(c, "R4", m)]))
        )
        num, den = dr[(c, "R3", m)] - dr[(c, "R4", m)], dr[(c, "R1", m)] - dr[(c, "R4", m)]
        with np.errstate(divide="ignore", invalid="ignore"):
            share_d = np.where(np.abs(den) > 1e-6, num / den, np.nan).ravel()
            share_e = (auc[(c, "R3", m)] - auc[(c, "R4", m)]) / e
        out["F2"].append(_row(c, m, holds(share_e, share_d, cfg, 1, cfg["f2_share"])))
        sd1, sd4 = np.std(auc[(c, "R1", m)], ddof=1), np.std(auc[(c, "R4", m)], ddof=1)
        out["F4"].append(
            {
                "cell": c,
                "model": m,
                "sd_R1": sd1,
                "sd_R4": sd4,
                "holds": sd4 > cfg["f4_sd_ratio"] * sd1,
            }
        )
        if (c, "R4u", m) in auc and plat.get(c, 0) >= 0.01:
            h = holds(
                auc[(c, "R4", m)] - auc[(c, "R4u", m)],
                (dr[(c, "R4", m)] - dr[(c, "R4u", m)]).ravel(),
                cfg,
                1,
            )
            out["HP"].append(
                _row(
                    c,
                    m,
                    h,
                    masked=np.median(auc[(c, "R4", m)]),
                    unmasked=np.median(auc[(c, "R4u", m)]),
                )
            )
    # F3: one population swapped, the other held fixed, at R4 (and depth-reweighted R4)
    for fixed_idx in (0, 1):
        groups: dict[str, list[str]] = {}
        for c in cells:
            groups.setdefault(c.split("__")[1 - fixed_idx], []).append(c)
        for cs in groups.values():
            for a, b in combinations(sorted(cs), 2):
                for m in models:
                    for key, A, D in (("F3", auc, dr), ("F3_depth", aucd, drd)):
                        if (a, "R4", m) not in A or (b, "R4", m) not in A:
                            continue
                        e = A[(a, "R4", m)] - A[(b, "R4", m)]
                        h = holds(e, (D[(a, "R4", m)] - D[(b, "R4", m)]).ravel(), cfg)
                        out[key].append(
                            _row(f"{a} vs {b}", m, h, swapped="phishing" if fixed_idx else "benign")
                        )
    phs = sorted({c.split("__")[0] for c in cells})
    bns = sorted({c.split("__")[1] for c in cells})
    for (p1, p2), (b1, b2) in ((p, b) for p in combinations(phs, 2) for b in combinations(bns, 2)):
        A_, B_, C_, D_ = (f"{p1}__{b1}", f"{p1}__{b2}", f"{p2}__{b1}", f"{p2}__{b2}")
        if not {A_, B_, C_, D_} <= ok:
            continue
        for m in models:
            e = (auc[(D_, "R4", m)] - auc[(C_, "R4", m)]) - (
                auc[(B_, "R4", m)] - auc[(A_, "R4", m)]
            )
            d = (dr[(D_, "R4", m)] - dr[(C_, "R4", m)]) - (dr[(B_, "R4", m)] - dr[(A_, "R4", m)])
            out["H5"].append(_row(f"{p1},{p2} x {b1},{b2}", m, holds(e, d.ravel(), cfg)))
    # H6 transfer and OOD natural pages
    tr: dict = {}
    for r in results:
        if r["cell"] not in ok:
            continue
        for (rep, m), targets in r["transfer"].items():
            for t, v in targets.items():
                tcell = f"{t[0]}__{t[1]}".replace("phish:", "").replace("benign:", "")
                if tcell in ok:
                    tr.setdefault((r["cell"], tcell, rep, m), []).append(v["auc"])
        for m, v in r["natural"].items():
            test_fpr = r["runs"][("R1", m)].get("cal_1pct_fpr", math.nan)
            n_neg = r["runs"][("R1", m)]["n_neg"]
            out["OOD"].append(
                {
                    "cell": r["cell"],
                    "model": m,
                    "split": r["split"],
                    "natural_fpr": v["fpr_0.01"],
                    "natural_fpr_0p1": v["fpr_0.001"],
                    "natural_fpr_at_0p5": v["fpr_0p5"],
                    "test_fpr": test_fpr,
                    "floor": 1 / max(n_neg, 1),
                }
            )
        for (rep, m), a in r["controls"].items():
            out["controls"].append(
                {"cell": r["cell"], "rep": rep, "model": m, "split": r["split"], "auc": a}
            )
    for (c, t, rep, m), v in tr.items():
        v = np.array(v)
        out["H6"].append(
            {
                "train": c,
                "test": t,
                "rep": rep,
                "model": m,
                "auc_median": np.median(v),
                "above": int((v > 0.5).sum()),
                "holds": (v > 0.5).sum() >= cfg["holds"]["min_splits_same_sign"],
            }
        )
    tables = {k: pd.DataFrame(v) for k, v in out.items()}
    if len(tables["OOD"]):
        o = tables["OOD"]
        o["ratio_ok"] = o["natural_fpr"] > cfg["ood_ratio"] * np.maximum(o["test_fpr"], o["floor"])
        g = o.groupby(["cell", "model"])
        tables["OOD"] = g.agg(
            natural_fpr=("natural_fpr", "median"),
            natural_fpr_0p1=("natural_fpr_0p1", "median"),
            natural_fpr_at_0p5=("natural_fpr_at_0p5", "median"),
            test_fpr=("test_fpr", "median"),
            splits_ok=("ratio_ok", "sum"),
        ).reset_index()
        tables["OOD"]["holds"] = tables["OOD"]["splits_ok"] >= cfg["holds"]["min_splits_same_sign"]
    if len(tables["controls"]):
        c = (
            tables["controls"]
            .groupby(["cell", "rep", "model"])["auc"]
            .mean()
            .reset_index(name="mean_auc")
        )
        c["flagged"] = (c["mean_auc"] - 0.5).abs() > cfg["control_flag"]
        tables["controls"] = c
    tables["runs"] = (
        runs.drop(columns=["_draws", "_draws_depth"])
        .groupby(["cell", "rep", "model"])
        .median(numeric_only=True)
        .reset_index()
    )
    return tables, ok


def _row(setting, model, h, **extra) -> dict:
    ok, same, med, lo, hi = h
    return {
        "setting": setting,
        "model": model,
        "holds": ok,
        "splits_in_direction": same,
        "median": med,
        "ci_lo": lo,
        "ci_hi": hi,
        **extra,
    }


FINDINGS = [
    ("F1", "Representation sensitivity: AUC falls from R1 to R4"),
    ("F2", "Most of the fall sits in host/subdomain structure (R3 to R4 share > 0.5)"),
    ("F3", "Source dependence: swapping one population moves R4 AUC"),
    ("F3_depth", "Source dependence survives depth reweighting"),
    ("H5", "A phishing x benign interaction is established (expected: inconclusive)"),
    ("F4", "Split sensitivity: SD of R4 AUC > 3 x SD of R1 AUC"),
    ("HP", "Masking hosting-platform identity raises R4 AUC"),
    ("H6", "Transfer to fully independent cells stays above chance (R4)"),
    ("OOD", "False alarms on natural legitimate pages > 5 x the in-cell rate"),
]


def summary(tables: dict) -> pd.DataFrame:
    rows = []
    for key, text in FINDINGS:
        t = tables.get(key, pd.DataFrame())
        if key == "H6" and len(t):
            t = t[t["rep"] == "R4"]
        flags = t["holds"].astype(bool).tolist() if len(t) else []
        rows.append(
            {
                "finding": key,
                "statement": text,
                "settings": len(flags),
                "hold": int(sum(flags)),
                "share": sum(flags) / len(flags) if flags else math.nan,
                "verdict": verdict(flags, CFG),
            }
        )
    return pd.DataFrame(rows)


CFG: dict = {}


def _md(df: pd.DataFrame, floatfmt: str = ".3f") -> str:
    if not len(df):
        return "_none_\n"
    cols = list(df.columns)
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for _, r in df.iterrows():
        lines.append(
            "| "
            + " | ".join(format(v, floatfmt) if isinstance(v, float) else str(v) for v in r)
            + " |"
        )
    return "\n".join(lines) + "\n"


def by_model(t: pd.DataFrame) -> pd.DataFrame:
    if not len(t):
        return t
    return t.groupby("model")["holds"].agg(settings="size", hold="sum").reset_index()


def part_b(out: Path, data: Path, cfg: dict) -> str:
    res = load(out, "B")
    if not res:
        return "_Part B not run._\n"
    runs = runs_table(res)
    med = (
        runs.groupby(["cell", "rep", "model"])[["roc_auc", "auc_depth", "op_1pct_recall"]]
        .median()
        .reset_index()
    )
    nat = pd.DataFrame(
        [{"cell": r["cell"], "rep": k, **v} for r in res for k, v in r["natural"].items()]
    )
    trn = pd.DataFrame(
        [
            {"train": r["cell"], "rep": k[0], "test": f"{t[0]}__{t[1]}", "auc": v["auc"]}
            for r in res
            for k, ts in r["transfer"].items()
            for t, v in ts.items()
        ]
    )
    ctl = pd.DataFrame([{"cell": r["cell"], "auc": a} for r in res for a in r["controls"].values()])
    meta = pd.concat(
        [pd.read_parquet(data / f"meta_{p}.parquet") for p in ("pool", "heldout_source")]
    )
    has = meta["uid"].isin(
        set(pd.read_parquet(data / "features_b.parquet", columns=["uid"])["uid"])
    )
    miss = meta.assign(has_html=has).groupby(["source", "label"])["has_html"].mean().reset_index()
    pr = meta[meta["source"] == "phreshphish"]
    from sklearn.metrics import roc_auc_score

    auc_has = roc_auc_score(pr["label"], ~has[meta["source"] == "phreshphish"])
    s = "Exploratory: counts toward no verdict.\n\n### Page representation ladder (median ROC-AUC over splits)\n\n"
    s += _md(
        med.pivot_table(index=["cell", "model"], columns="rep", values="roc_auc").reset_index()
    )
    s += "\n### Natural legitimate pages with HTML (median FPR at the cell's own thresholds)\n\n"
    s += (
        _md(nat.groupby(["cell", "rep"]).median(numeric_only=True).reset_index())
        if len(nat)
        else "_none_\n"
    )
    s += "\n### Transfer to independent cells (median ROC-AUC)\n\n"
    s += (
        _md(trn.groupby(["train", "test", "rep"])["auc"].median().reset_index())
        if len(trn)
        else "_none_\n"
    )
    s += f"\n### Shuffled-label control (P1, LightGBM)\n\nMean ROC-AUC {ctl['auc'].mean():.4f} over {len(ctl)} runs.\n"
    s += "\n### E9: who has usable HTML (share of rows)\n\n" + _md(miss)
    s += f"\nIn PhreshPhish, *missing HTML* alone predicts phishing with ROC-AUC {auc_has:.3f}.\n"
    return s


def write(out: Path, data: Path, reports: Path, cfg: dict, commit: str) -> Path:
    CFG.update(cfg)
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "tables").mkdir(exist_ok=True)
    res = load(out, "A")
    tables, ok = findings_a(res, cfg)
    for k, t in tables.items():
        t.to_csv(reports / "tables" / f"{k}.csv", index=False)
    summ = summary(tables)
    summ.to_csv(reports / "tables" / "verdicts.csv", index=False)
    runs = tables["runs"]
    s = [
        "# PhishGuard verification study: results\n",
        "Generated by `python -m phishguard all`. Do not edit by hand. Plan frozen at commit "
        f"`{commit}` (`configs/phishguard.yaml`). Part A = URLs (verdicts); Part B = page HTML (exploratory).\n",
        f"Testable cells: {len(ok)} of {len({r['cell'] for r in res})}; {cfg['n_splits']} domain-grouped splits each.\n",
        "## Verdicts (Part A)\n",
        _md(summ.drop(columns=[])),
        "\n## E0: reproduction of the first study (XGBoost, median ROC-AUC)\n",
    ]
    e0 = []
    for cell, pub in cfg["published"].items():
        for rep in REPS:
            v = runs[(runs["cell"] == cell) & (runs["rep"] == rep) & (runs["model"] == "xgboost")][
                "roc_auc"
            ]
            e0.append(
                {
                    "cell": cell,
                    "rep": rep,
                    "published": pub[rep],
                    "now": float(v.iloc[0]) if len(v) else math.nan,
                }
            )
    e0 = pd.DataFrame(e0)
    e0["gap"] = e0["now"] - e0["published"]
    s += [
        _md(e0),
        "Differences from the first study: de-duplicated and depth-balanced pool, 99 features instead of 38, "
        "10 splits instead of one frozen split, crawl pool rebuilt. R3 equals R2 here: the feature engine "
        "drops a leading www from every URL, so the www step is zero by construction.\n",
        "\n## Representation ladder (median ROC-AUC, Part A)\n",
        _md(
            runs[runs["rep"].isin(REPS)]
            .pivot_table(index=["cell", "model"], columns="rep", values="roc_auc")
            .reset_index()
        ),
    ]
    for key, text in FINDINGS:
        t = tables.get(key, pd.DataFrame())
        s += [
            f"\n## {key}: {text}\n",
            "By model:\n\n",
            _md(by_model(t)),
            f"\nFull table: `reports/phishguard/tables/{key}.csv`.\n",
        ]
    c = tables["controls"]
    s += [
        "\n## Shuffled-label controls\n",
        f"{int(c['flagged'].sum()) if len(c) else 0} of {len(c)} conditions flagged (|mean AUC - 0.5| > {cfg['control_flag']}).\n",
    ]
    sig = out / "results" / "signature.pkl"
    if sig.exists():
        g = pickle.loads(sig.read_bytes())
        s += [
            "\n## E8: dataset fingerprint within one class (balanced accuracy, 5 domain folds)\n",
            _md(
                pd.DataFrame(
                    [
                        {
                            "part": k[0],
                            "class": "phishing" if k[1] else "benign",
                            "input": k[2],
                            "balanced_accuracy": v["balanced_accuracy"],
                            "chance": v["chance"],
                            "n": v["n"],
                        }
                        for k, v in g.items()
                    ]
                )
            ),
        ]
    s += ["\n## Part B: page HTML (exploratory)\n", part_b(out, data, cfg)]
    path = reports / "verification.md"
    path.write_text("\n".join(s), encoding="utf-8")
    return path
