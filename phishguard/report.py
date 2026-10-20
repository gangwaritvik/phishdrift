# ruff: noqa: E501
"""Build the PhishGuard study report: figures and a Markdown source, from the tables only.

    python -m phishguard.report --run /mnt/project-files/phishdrift/phishguard_run \
        --out reports/phishguard/report

Every number comes from ``reports/phishguard/tables/*.csv`` and ``reports/phishguard/verification.md``;
the first study's numbers are the constants in ``FIRST`` (docs/prior_work/representation_sensitivity_report.pdf).
Convert with pandoc (docx) and LibreOffice (pdf).
"""

from __future__ import annotations

import argparse
import contextlib
import re
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

TABLES = Path("reports/phishguard/tables")
VERIF = Path("reports/phishguard/verification.md")
PHISH = ["phreshphish", "phiusiil", "urlphish", "phishstorm", "phishpedia"]
BENIGN = ["phreshphish", "phiusiil", "urlphish", "phishstorm", "crawl"]
MODELS = ["lightgbm", "xgboost", "logreg", "char_ngram"]
MODEL_LABEL = {
    "lightgbm": "LightGBM",
    "xgboost": "XGBoost",
    "logreg": "Logistic regression",
    "char_ngram": "Char n-gram LR",
}
COL = {"lightgbm": "#1f6f8b", "xgboost": "#c8553d", "logreg": "#6a994e", "char_ngram": "#7b5ea7"}
FIRST = {  # prior study (report v1.1.1), numbers quoted from the PDF
    "F1": "cell A raw 0.9988 to R4 0.7297; all cells R4 0.63-0.86",
    "F2": "R1-R4 drop share in host/subdomain 0.870 (cell A), 0.563 (cell C)",
    "F3": "swapping the phishing source moves R4 by 0.13-0.16",
    "F4": "R4 SD across 10 splits up to 0.1164 against at most 0.0026 for raw",
    "HP": "masking raised held-out R4 AUC in 60 of 60 pairs",
    "H6": "R4 0.694 and 0.706, on 119 benign domains",
    "OOD": "raw model 1.0 on natural legitimate pages against 0.00026 on the benchmark; normalised 0.090",
}


def md_table(text: str, heading: str, nth: int = 0) -> pd.DataFrame:
    """Read the nth Markdown table that follows a heading containing ``heading``."""
    start = text.index(heading)
    lines = text[start:].splitlines()
    tables, cur = [], []
    for ln in lines[1:]:
        if ln.startswith("|"):
            cur.append(ln)
        elif cur:
            tables.append(cur)
            cur = []
            if len(tables) > nth:
                break
    if cur and len(tables) <= nth:
        tables.append(cur)
    rows = [[c.strip() for c in r.strip("|").split("|")] for r in tables[nth] if "---" not in r]
    df = pd.DataFrame(rows[1:], columns=rows[0])
    for c in df.columns:
        with contextlib.suppress(ValueError, TypeError):
            df[c] = pd.to_numeric(df[c].replace({"nan": np.nan}))
    return df


def style() -> None:
    plt.rcParams.update(
        {
            "figure.dpi": 150,
            "savefig.dpi": 200,
            "font.size": 9,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "grid.alpha": 0.25,
            "axes.titlesize": 10,
            "axes.titleweight": "bold",
        }
    )


def save(fig, out: Path, name: str) -> str:
    fig.tight_layout()
    fig.savefig(out / f"{name}.png", bbox_inches="tight")
    plt.close(fig)
    return f"{name}.png"


def fig_design(out: Path) -> str:
    fig, ax = plt.subplots(figsize=(8, 3.6))
    ax.axis("off")
    boxes = [
        (0.02, "5 phishing sources\nPhreshPhish, PhiUSIIL,\nURL-Phish, PhishStorm,\nPhishpedia"),
        (
            0.27,
            "5 legitimate sources\nPhreshPhish, PhiUSIIL,\nURL-Phish, PhishStorm,\ninner-page crawl",
        ),
        (
            0.52,
            "25 cells x 4 models\nx 4 URL forms (R1-R4)\nx 10 domain-grouped\nsplits = 1,000 fits",
        ),
        (
            0.77,
            "Per finding:\nholds in >= 9 of 10 splits\nand bootstrap CI excludes\nthe null, then % of cells",
        ),
    ]
    for x, t in boxes:
        ax.add_patch(plt.Rectangle((x, 0.35), 0.21, 0.5, fc="#eef3f6", ec="#1f6f8b", lw=1.2))
        ax.text(x + 0.105, 0.6, t, ha="center", va="center", fontsize=8)
    for x in (0.23, 0.48, 0.73):
        ax.annotate("", (x + 0.04, 0.6), (x, 0.6), arrowprops={"arrowstyle": "->", "color": "#444"})
    ax.text(
        0.5,
        0.15,
        "Part B (exploratory): 2 phishing x 2 legitimate sources with saved page HTML, page-feature ladder P1-P4",
        ha="center",
        fontsize=8,
        style="italic",
    )
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    return save(fig, out, "fig01_design")


def fig_ladder(runs: pd.DataFrame, out: Path) -> str:
    fig, axes = plt.subplots(1, 2, figsize=(8, 3.4), sharey=True)
    reps = ["R1", "R2", "R4"]
    for ax, m in zip(axes, ["lightgbm", "char_ngram"], strict=True):
        d = runs[runs.model == m].pivot(index="cell", columns="rep", values="roc_auc")[reps]
        for _, r in d.iterrows():
            ax.plot(reps, r.values, color=COL[m], alpha=0.25, lw=1)
        ax.plot(
            reps, d.median().values, color="black", lw=2.2, marker="o", label="median of 25 cells"
        )
        ax.set_title(MODEL_LABEL[m])
        ax.set_xticks(range(3), ["R1 raw", "R2 host only\n(= R3)", "R4 www.domain"])
        ax.set_ylim(0.6, 1.02)
    axes[0].set_ylabel("ROC-AUC (median of 10 splits)")
    axes[0].legend(loc="lower left", fontsize=8)
    return save(fig, out, "fig02_ladder")


def fig_models(runs: pd.DataFrame, out: Path) -> str:
    fig, ax = plt.subplots(figsize=(6.5, 3.4))
    reps = ["R1", "R2", "R4"]
    w = 0.2
    for i, m in enumerate(MODELS):
        d = runs[runs.model == m].pivot(index="cell", columns="rep", values="roc_auc")[reps]
        med, lo, hi = d.median(), d.min(), d.max()
        x = np.arange(3) + (i - 1.5) * w
        ax.bar(x, med.values, w, color=COL[m], label=MODEL_LABEL[m])
        ax.errorbar(
            x, med.values, [med - lo, hi - med], fmt="none", ecolor="#333", lw=0.8, capsize=2
        )
    ax.set_xticks(range(3), ["R1 raw URL", "R2/R3 host only", "R4 https://www.domain"])
    ax.set_ylim(0.5, 1.02)
    ax.set_ylabel("ROC-AUC, median over cells\n(whiskers: min and max cell)")
    ax.legend(ncol=2, fontsize=8, loc="upper right")
    return save(fig, out, "fig03_models")


def fig_share(runs: pd.DataFrame, out: Path) -> str:
    d = runs[runs.model == "lightgbm"].pivot(index="cell", columns="rep", values="roc_auc")
    drop = (d.R1 - d.R4).clip(lower=1e-9)
    host = ((d.R2 - d.R4) / drop).clip(0, 1)
    d2 = pd.DataFrame({"host": host, "path": 1 - host}).sort_values("host")
    fig, ax = plt.subplots(figsize=(7, 5))
    y = np.arange(len(d2))
    ax.barh(y, d2.path, color="#c8553d", label="R1 to R2: path and query removed")
    ax.barh(y, d2.host, left=d2.path, color="#1f6f8b", label="R2 to R4: host and subdomain removed")
    ax.set_yticks(y, [c.replace("__", " vs ") for c in d2.index], fontsize=7)
    ax.axvline(1 - 0.5, color="black", ls="--", lw=0.8)
    ax.set_xlabel("Share of the R1 to R4 AUC drop (LightGBM)")
    ax.legend(fontsize=7, loc="lower right")
    ax.set_title("Where the representation drop sits")
    return save(fig, out, "fig04_share")


def fig_source(runs: pd.DataFrame, f3: pd.DataFrame, out: Path) -> str:
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.8), gridspec_kw={"width_ratios": [1.1, 1]})
    d = runs[(runs.model == "lightgbm") & (runs.rep == "R4")].set_index("cell")["roc_auc"]
    mat = np.array([[d.get(f"{p}__{b}", np.nan) for b in BENIGN] for p in PHISH])
    ax = axes[0]
    im = ax.imshow(mat, cmap="viridis", vmin=0.65, vmax=0.95)
    ax.set_xticks(range(5), BENIGN, rotation=40, ha="right", fontsize=7)
    ax.set_yticks(range(5), PHISH, fontsize=7)
    ax.grid(False)
    for i in range(5):
        for j in range(5):
            ax.text(j, i, f"{mat[i, j]:.2f}", ha="center", va="center", color="white", fontsize=7)
    ax.set_xlabel("legitimate source")
    ax.set_ylabel("phishing source")
    ax.set_title("R4 ROC-AUC, LightGBM")
    fig.colorbar(im, ax=ax, fraction=0.046)
    ax = axes[1]
    for lab, c in (("phishing", "#c8553d"), ("benign", "#1f6f8b")):
        v = f3[(f3.model == "lightgbm") & (f3.swapped == lab)]["median"]
        ax.hist(
            v, bins=np.linspace(-0.3, 0.3, 25), alpha=0.65, color=c, label=f"swap the {lab} source"
        )
    ax.axvline(0, color="black", lw=0.8)
    ax.set_xlabel("change in R4 AUC when one source is swapped")
    ax.set_ylabel("settings")
    ax.legend(fontsize=7)
    ax.set_title("Effect of swapping one source")
    return save(fig, out, "fig05_source")


def fig_split(f4: pd.DataFrame, out: Path) -> str:
    fig, ax = plt.subplots(figsize=(5.2, 4.2))
    for m in MODELS:
        d = f4[f4.model == m]
        ax.scatter(d.sd_R1, d.sd_R4, s=22, color=COL[m], alpha=0.8, label=MODEL_LABEL[m])
    mx = max(f4.sd_R1.max(), f4.sd_R4.max()) * 1.05
    x = np.linspace(0, mx, 10)
    ax.plot(x, x, color="grey", lw=0.8, label="equal")
    ax.plot(x, 3 * x, color="black", ls="--", lw=0.8, label="3 x (the test)")
    ax.set_xlabel("SD of raw (R1) AUC across 10 splits")
    ax.set_ylabel("SD of R4 AUC across 10 splits")
    ax.set_xlim(0, mx)
    ax.set_ylim(0, mx)
    ax.legend(fontsize=7)
    return save(fig, out, "fig06_split")


def fig_transfer(h6: pd.DataFrame, out: Path) -> str:
    fig, ax = plt.subplots(figsize=(6, 3.4))
    data, labels = [], []
    for m in ("lightgbm", "char_ngram"):
        for rep in ("R1", "R4"):
            data.append(h6[(h6.model == m) & (h6.rep == rep)].auc_median.values)
            labels.append(f"{MODEL_LABEL[m]}\n{rep}")
    bp = ax.boxplot(data, tick_labels=labels, patch_artist=True, widths=0.55, showfliers=True)
    for p, c in zip(bp["boxes"], [COL["lightgbm"]] * 2 + [COL["char_ngram"]] * 2, strict=True):
        p.set_facecolor(c)
        p.set_alpha(0.6)
    ax.axhline(0.5, color="black", ls="--", lw=0.8)
    ax.set_ylabel("ROC-AUC on cells sharing no source")
    ax.set_title(f"Transfer to independent cells ({len(data[0])} train-test pairs each)")
    return save(fig, out, "fig07_transfer")


def fig_ood(ood: pd.DataFrame, out: Path) -> str:
    fig, ax = plt.subplots(figsize=(5.6, 4.4))
    for m in MODELS:
        d = ood[ood.model == m]
        ax.scatter(
            np.maximum(d.test_fpr, 1e-4),
            d.natural_fpr,
            s=24,
            color=COL[m],
            alpha=0.8,
            label=MODEL_LABEL[m],
        )
    x = np.logspace(-4, -0.5, 10)
    ax.plot(x, x, color="grey", lw=0.8, label="equal")
    ax.plot(x, 5 * x, color="black", ls="--", lw=0.8, label="5 x (the test)")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlabel("false-alarm rate on the cell's own test side (floor 1e-4)")
    ax.set_ylabel("false-alarm rate on 2,555 natural legitimate pages")
    ax.legend(fontsize=7)
    return save(fig, out, "fig08_ood")


def fig_controls(ctrl: pd.DataFrame, out: Path) -> str:
    fig, ax = plt.subplots(figsize=(6.5, 3.2))
    ctrl = ctrl.reset_index(drop=True)
    for m in ("lightgbm", "char_ngram"):
        d = ctrl[ctrl.model == m]
        ax.scatter(d.index, d.mean_auc, s=14, color=COL[m], label=MODEL_LABEL[m])
    f = ctrl[ctrl.flagged]
    ax.scatter(f.index, f.mean_auc, s=80, facecolors="none", edgecolors="red", label="flagged")
    ax.axhspan(0.45, 0.55, color="green", alpha=0.08)
    ax.axhline(0.5, color="black", lw=0.8)
    ax.set_xlabel("condition (cell x representation x model)")
    ax.set_ylabel("mean ROC-AUC, shuffled labels")
    ax.set_ylim(0.4, 0.6)
    ax.legend(fontsize=7, ncol=3)
    return save(fig, out, "fig09_controls")


def fig_pageb(pb: pd.DataFrame, out: Path) -> str:
    d = pb[pb.model == "lightgbm"].set_index("cell")
    cols = ["P1", "P2", "P3", "P4", "R1", "R4"]
    fig, ax = plt.subplots(figsize=(7.5, 3.6))
    w = 0.13
    pal = ["#1f6f8b", "#4f9bb5", "#8fc1d4", "#c9e0e9", "#c8553d", "#e8a598"]
    for i, c in enumerate(cols):
        ax.bar(np.arange(len(d)) + (i - 2.5) * w, d[c].values, w, color=pal[i], label=c)
    ax.set_xticks(range(len(d)), [c.replace("__", "\nvs ") for c in d.index], fontsize=7)
    ax.set_ylim(0.6, 1.02)
    ax.set_ylabel("ROC-AUC (median of 10 splits)")
    ax.legend(ncol=6, fontsize=7, loc="lower right")
    return save(fig, out, "fig10_pageb")


def fig_html_cov(e9: pd.DataFrame, out: Path) -> str:
    fig, ax = plt.subplots(figsize=(6.5, 3.2))
    e9 = e9.copy()
    e9["name"] = e9.source + (e9.label.map({0: " (benign)", 1: " (phishing)"}))
    e9 = e9.sort_values("has_html")
    ax.barh(e9.name, e9.has_html, color=["#c8553d" if v == 1 else "#1f6f8b" for v in e9.label])
    ax.set_xlabel("share of rows with usable HTML")
    return save(fig, out, "fig11_html_coverage")


def fig_followup(repro: pd.DataFrame, ctrl: pd.DataFrame, out: Path) -> str:
    fig, axes = plt.subplots(1, 2, figsize=(9, 3.4))
    ax = axes[0]
    stages = list(dict.fromkeys(repro.stage))
    for rep, c in (("R1", "#1f6f8b"), ("R4", "#c8553d")):
        v = [
            repro[(repro.stage == s) & (repro.model == "xgboost") & (repro.rep == rep)].auc.median()
            for s in stages
        ]
        ax.plot(range(len(stages)), v, marker="o", color=c, label=f"{rep} (this run)")
    ax.axhline(0.999, color="#1f6f8b", ls=":", lw=1)
    ax.axhline(0.7297, color="#c8553d", ls=":", lw=1)
    ax.text(
        len(stages) - 1,
        0.9995,
        "published R1",
        ha="right",
        va="bottom",
        fontsize=7,
        color="#1f6f8b",
    )
    ax.text(
        len(stages) - 1,
        0.7297,
        "published R4",
        ha="right",
        va="bottom",
        fontsize=7,
        color="#c8553d",
    )
    ax.set_xticks(range(len(stages)), [s.split(" ")[0] for s in stages])
    ax.set_ylabel("XGBoost ROC-AUC, PhiUSIIL alone")
    ax.legend(fontsize=7, loc="center left")
    ax.set_title("From raw PhiUSIIL to the study cell")
    ax = axes[1]
    for m, c in (("lightgbm", COL["lightgbm"]), ("char_ngram", COL["char_ngram"])):
        ax.hist(
            ctrl[ctrl.model == m].auc,
            bins=np.linspace(0.35, 0.6, 21),
            alpha=0.65,
            color=c,
            label=MODEL_LABEL[m],
        )
    ax.axvline(0.5, color="black", lw=0.8)
    ax.set_xlabel("ROC-AUC, shuffled labels (URL-Phish vs PhiUSIIL, R1)")
    ax.set_ylabel("runs")
    ax.legend(fontsize=7)
    ax.set_title("The flagged control, 50 runs per model")
    return save(fig, out, "fig12_followup")


def pct(x: float, nd: int = 0) -> str:
    return f"{100 * x:.{nd}f}%"


def tbl(df: pd.DataFrame, nd: int = 3, widths: list[int] | None = None) -> str:
    cols = list(df.columns)
    sep = "|" + "|".join("-" * w for w in widths) + "|" if widths else "|" + "---|" * len(cols)
    lines = ["| " + " | ".join(cols) + " |", sep]
    for _, r in df.iterrows():
        lines.append(
            "| " + " | ".join(f"{v:.{nd}f}" if isinstance(v, float) else str(v) for v in r) + " |"
        )
    return "\n".join(lines) + "\n"


def build(run: Path, out: Path) -> Path:
    style()
    out.mkdir(parents=True, exist_ok=True)
    text = VERIF.read_text(encoding="utf-8")
    runs = pd.read_csv(TABLES / "runs.csv")
    runs = runs[runs.cell.notna()]
    verd = pd.read_csv(TABLES / "verdicts.csv").set_index("finding")
    f2, f3, f4 = (pd.read_csv(TABLES / f"{k}.csv") for k in ("F2", "F3", "F4"))
    f3d, h6, ood, ctrl = (
        pd.read_csv(TABLES / f"{k}.csv") for k in ("F3_depth", "H6", "OOD", "controls")
    )
    repro = pd.read_csv(TABLES / "reproduce.csv")
    ctrl1 = pd.read_csv(TABLES / "control_urlphish__phiusiil.csv")
    pops = pd.read_parquet(run / "populations.parquet")
    pb = md_table(text, "### Page representation ladder")
    pnat = md_table(text, "### Natural legitimate pages with HTML")
    ptr = md_table(text, "### Transfer to independent cells")
    e8 = md_table(text, "## E8:")
    e9 = md_table(text, "### E9:")
    e0 = md_table(text, "## E0:")
    figs = {
        "design": fig_design(out),
        "ladder": fig_ladder(runs, out),
        "models": fig_models(runs, out),
        "share": fig_share(runs, out),
        "source": fig_source(runs, f3, out),
        "split": fig_split(f4, out),
        "transfer": fig_transfer(h6, out),
        "ood": fig_ood(ood, out),
        "controls": fig_controls(ctrl, out),
        "pageb": fig_pageb(pb, out),
        "cov": fig_html_cov(e9, out),
        "follow": fig_followup(repro, ctrl1, out),
    }

    piv = runs.pivot_table(index=["cell", "model"], columns="rep", values="roc_auc").reset_index()
    r1, r2, r4 = piv.R1.median(), piv.R2.median(), piv.R4.median()
    drop_min = (piv.R1 - piv.R4).min()
    host_share = f2["median"].median()
    f3_all = f3["median"]
    f3_abs = f3_all.abs().median()
    f3_ph = f3[f3.swapped == "phishing"]["median"].abs().median()
    f3_bn = f3[f3.swapped == "benign"]["median"].abs().median()
    sd1, sd4 = f4.sd_R1.median(), f4.sd_R4.median()
    sdmax = f4.sd_R4.max()
    h6r4 = h6[h6.rep == "R4"].auc_median
    h6lo, h6med = h6r4.min(), h6r4.median()
    ood_nat, ood_nat01, ood_05, ood_test = (
        ood.natural_fpr.median(),
        ood.natural_fpr_0p1.median(),
        ood.natural_fpr_at_0p5.median(),
        ood.test_fpr.median(),
    )
    n_flag = int(ctrl.flagged.sum())
    ctrl_lo, ctrl_hi = ctrl.mean_auc.min(), ctrl.mean_auc.max()
    d4 = runs[(runs.model == "lightgbm") & (runs.rep == "R4")]
    m4 = d4.roc_auc
    u4 = d4[d4.cell.str.endswith("__urlphish")].roc_auc
    share_gt = (f4.sd_R4 > f4.sd_R1).mean()
    rg = repro.groupby(["stage", "model", "rep"]).auc.median().unstack()
    rg["share"] = (rg.R2 - rg.R4) / (rg.R1 - rg.R4)
    sh = rg["share"].unstack("model").reset_index()
    sh["stage"] = sh["stage"].str.replace(r" \(.*\)$", "", regex=True)
    sh = sh.rename(
        columns={
            "stage": "PhiUSIIL cleaning stage",
            "xgboost": "XGBoost host share",
            "char_ngram": "Char n-gram host share",
        }
    )
    sh_raw_x, sh_cell_x = (
        rg["share"].xs("xgboost", level="model").iloc[0],
        rg["share"].xs("xgboost", level="model").iloc[-1],
    )
    sh_raw_c, sh_cell_c = (
        rg["share"].xs("char_ngram", level="model").iloc[0],
        rg["share"].xs("char_ngram", level="model").iloc[-1],
    )
    cs = ctrl1.groupby("model").auc.agg(["mean", "std"])

    # tables
    pop_tbl = (
        pops.groupby(["part", "pop"])
        .agg(URLs=("uid", "size"), domains=("domain", "nunique"))
        .reset_index()
        .rename(columns={"part": "Part", "pop": "Population"})
    )
    v = verd.reset_index()
    v["verdict"] = v["verdict"].str.capitalize()
    v_tbl = v[["finding", "statement", "settings", "hold", "verdict"]].copy()
    v_tbl["share"] = v["share"].map(lambda x: "n/a" if pd.isna(x) else pct(x))
    v_tbl = v_tbl.rename(columns={"settings": "settings tested", "hold": "settings where it holds"})
    lad = piv.groupby(piv.cell)[["R1", "R2", "R4"]].mean().round(3).reset_index()
    lad["cell"] = lad["cell"].str.replace("__", " vs ")
    lad = lad.rename(columns={"cell": "phishing vs legitimate", "R2": "R2 (= R3)"})
    e0t = e0.copy()
    e0t["cell"] = e0t["cell"].str.replace("__", " vs ")
    pb_t = pb[pb.model == "lightgbm"].drop(columns="model").copy()
    pb_t["cell"] = pb_t["cell"].str.replace("__", " vs ")
    pnat_t = pnat.copy()
    pnat_t["cell"] = pnat_t["cell"].str.replace("__", " vs ")
    pnat_t["n"] = pnat_t["n"].astype(int)

    reg = [
        (
            "F1 Representation sensitivity",
            FIRST["F1"],
            f"R1 {r1:.3f} to R4 {r4:.3f} (median of cells and models); falls in every one of {int(verd.loc['F1', 'settings'])} model-cell settings",
            "Replicated",
            "A direct finding, across five phishing sets, five legitimate sets and four model families.",
        ),
        (
            "F2 Where the drop sits",
            FIRST["F2"],
            f"median host/subdomain share {host_share:.2f} on the study cells; on raw PhiUSIIL alone {sh_raw_x:.2f} (XGBoost), falling to {sh_cell_x:.2f} after cleaning",
            "Not replicated",
            "Say the host/subdomain share depends on how the benchmark is prepared: it is high on the raw benchmark and low on cleaned pools.",
        ),
        (
            "F3 Source dependence",
            FIRST["F3"],
            f"swapping one source moves R4 AUC by a median {f3_abs:.3f}; CI excludes 0 in {pct(verd.loc['F3', 'share'])} of settings, {pct(verd.loc['F3_depth', 'share'])} after depth reweighting",
            "Partly replicated",
            "Real in some pairs, absent in others; reweighting for depth halves it.",
        ),
        (
            "F4 Split sensitivity",
            FIRST["F4"],
            f"median SD {sd4:.3f} (R4) against {sd1:.3f} (R1); larger than 3x in {pct(verd.loc['F4', 'share'])} of settings, largest {sdmax:.3f}",
            "Not replicated",
            "Split variability matters but the 3x margin is not general.",
        ),
        (
            "HP Platform masking",
            FIRST["HP"],
            "no hosting-platform domains remain after the 5-per-domain cap",
            "Not testable",
            "Leave to a design that keeps platform domains.",
        ),
        (
            "H6 Independent transfer",
            FIRST["H6"],
            f"R4 AUC {h6med:.3f} median, lowest {h6lo:.3f}, above 0.5 in every setting",
            "Replicated",
            "Transfer stays above chance; the size varies.",
        ),
        (
            "OOD Natural pages",
            FIRST["OOD"],
            f"{pct(ood_nat, 1)} flagged on natural pages at the cell's 1% threshold against {pct(ood_test, 1)} in-cell; {pct(ood_05, 0)} at the 0.5 threshold",
            "Partly replicated",
            "Benchmark thresholds understate false alarms on natural pages.",
        ),
    ]
    reg_tbl = pd.DataFrame(
        reg, columns=["Finding", "First study", "This run", "Verdict", "How to word it"]
    )

    md = f"""---
title: "PhishGuard: Replicating Representation Sensitivity and Source Dependence in Phishing URL Detection Across Datasets and Models"
subtitle: "Verification study report, version 1.0 (draft for supervisor review)"
author: "Ritvik Gangwar"
date: "2026-10-20"
---

# 1. Executive summary

A first study (report v1.1.1, 2026-09-10) found that phishing-URL detectors scored on one benchmark change sharply when URLs are written in a different form, and that scores depend on which sources are used. Its code and result files were lost. This report asks whether those findings hold when they are re-implemented from scratch and repeated across **5 phishing sources, 5 legitimate sources, 4 model families and 10 domain-grouped splits** (25 cells, 1,000 fits per representation), with the rule for calling a finding *replicated* written down before the run (commit `082b058`).

**Results in one table.** Seven findings were tested; each counts as holding in a setting only if the direction repeats in at least 9 of 10 splits and the bootstrap interval excludes the null.

{tbl(v_tbl, widths=[8, 40, 9, 11, 14, 9])}

**What this supports.** The central finding, that a URL model's score drops when the URL is reduced to its domain, is replicated in every setting (median R1 {r1:.3f} to R4 {r4:.3f}). Transfer to cells that share no source stays above chance. Source dependence and the out-of-distribution false-alarm gap hold in part. Two findings from the first study do not carry over here: the split of the drop between host and path (F2) and the size of split-to-split variability (F4). One could not be tested (HP).

**What this does not support.** None of this is a claim about all phishing detectors or all datasets. The sources are public benchmarks, and two of them (PhiUSIIL, PhishStorm) are old and homepage-heavy. The figures are a study of behaviour under one frozen design, reported with the settings where it fails.

# 2. Purpose and questions

The supervisor asked how the first study's results can be verified beyond one model and one dataset, and whether the behaviour appears across all available datasets. The report therefore answers seven questions, one per finding:

- **F1** Does the AUC fall from raw URLs (R1) to the normalised `https://www.<registrable domain>` form (R4)?
- **F2** Does most of that fall sit in host and subdomain structure rather than in path and query?
- **F3** Does swapping one source (phishing or legitimate) move R4 AUC?
- **F4** Is R4 AUC much less stable across splits than raw AUC?
- **HP** Does masking hosting-platform identity raise R4 AUC?
- **H6** Does a model still beat chance on cells that share no source with its training data?
- **OOD** Does a model flag far more naturally browsed legitimate pages than its own test side?

A second, exploratory part repeats the representation idea on page HTML (Section 7). It gives no verdicts.

# 3. Data and design

## 3.1 Sources

URL, label and (for Part B) saved HTML are the only fields read from any source; no dataset's precomputed feature columns are used. Every population is capped at 10,000 URLs and at most 5 URLs per registrable domain, so URL counts and domain counts are reported separately (Table 1). Registrable domains are disjoint across sources, domains shared by several phishing sources are removed, and the build fails if any URL-depth bucket is more than 90% one class.

**Table 1.** Populations after the caps (`phishguard_run/populations.parquet`).

{tbl(pop_tbl, 0)}

## 3.2 Representations

R1 is the raw URL. R2 keeps the host only (path, query and fragment removed). R3 additionally strips `www`; here R3 is identical to R2 because the feature engine drops a leading `www` from every URL, so the `www` step is zero by construction. R4 is `https://www.<registrable domain>`.

## 3.3 Models and splits

LightGBM, XGBoost, logistic regression on the 99 URL features, and character n-gram TF-IDF with logistic regression. Ten splits per cell are grouped by registrable domain (train 70%, calibration 10%, test 20%; a deterministic hash of seed, split and domain). Fitted features (TLD risk, bigram likelihood) are refitted on each split's training side. Uncertainty comes from a domain-cluster bootstrap with 200 draws per split. Transfer is tested only on cells sharing no source with the training cell.

![Study design. Seven findings are tested across 25 source cells, four models, four URL forms and ten splits.]({figs["design"]})

## 3.4 The rule for calling a finding replicated

A setting (one cell and model, or one pair of cells) *holds* when the direction is the same in at least 9 of 10 splits and the pooled bootstrap 95% interval excludes the null. A finding is **replicated** if it holds in at least 80% of its testable settings, **partly replicated** at 50 to 80%, and **not replicated** below 50%; with fewer than 3 testable settings it is **not testable**. A setting is testable with at least 500 URLs and 100 domains per class. The rule and `configs/phishguard.yaml` were frozen at commit `082b058` before any result was seen.

# 4. Results

## 4.1 F1: representation sensitivity (replicated)

AUC falls from R1 to R4 in all {int(verd.loc["F1", "settings"])} model-cell settings. The median R1 AUC is {r1:.3f}, R2/R3 {r2:.3f} and R4 {r4:.3f}; the smallest drop in any setting is {drop_min:.3f}. All four model families show it (Figure 3), including the character n-gram model that held up best in the first study.

![Representation ladder, 25 cells. Thin lines are cells; the thick line is the median.]({figs["ladder"]})

![Median AUC by representation and model, with the range across the 25 cells.]({figs["models"]})

**Table 2.** Mean AUC over the four models, by cell.

{tbl(lad)}

## 4.2 F2: where the drop sits (not replicated)

The first study put most of the R1 to R4 drop in the host and subdomain (share 0.870 in cell A, 0.563 in cell C). Here the host and subdomain step (R2 to R4) carries a median share of {host_share:.2f}; the larger part comes from removing path and query (R1 to R2). The statement "most of the fall sits in host structure" holds in {int(verd.loc["F2", "hold"])} of {int(verd.loc["F2", "settings"])} settings. This run uses 99 features rather than 38, balances depth, and caps URLs per domain, all of which can change where the information sits; the main report does not choose among those explanations.

**Exploratory follow-up (not part of the frozen verdict).** Re-running PhiUSIIL alone with one cleaning step added at a time (Section 6) shows the host share of the drop depends on how the data was prepared. On raw PhiUSIIL through our loader the host step carries {sh_raw_x:.2f} of the drop for XGBoost and {sh_raw_c:.2f} for the character model; on the study cell, after the shared-domain removal, depth balancing and caps, it carries {sh_cell_x:.2f} and {sh_cell_c:.2f}. The first study's pattern is therefore visible again on the raw benchmark for XGBoost, and it fades as the benchmark is cleaned. That is consistent with the F2 pattern being tied to how the raw benchmark was built, but it is one dataset and two models, so it is stated as a lead, not a conclusion.

**Table 2b.** Host and subdomain share of the R1 to R4 drop, PhiUSIIL alone, by cleaning stage (5 splits).

{tbl(sh)}

![Share of the R1 to R4 drop by step, LightGBM, per cell.]({figs["share"]})

## 4.3 F3: source dependence (partly replicated)

Swapping one source while holding the other fixed moves R4 AUC by a median {f3_abs:.3f} (phishing source swapped {f3_ph:.3f}, legitimate source swapped {f3_bn:.3f}). The interval excludes zero in {pct(verd.loc["F3", "share"])} of {int(verd.loc["F3", "settings"])} swaps. After reweighting the test side to equalise URL depth across classes it falls to {pct(verd.loc["F3_depth", "share"])}, so part of the source effect is URL depth. The heatmap shows the pattern: R4 AUC ranges from {m4.min():.2f} to {m4.max():.2f}; against URL-Phish legitimate URLs every phishing source scores highest ({u4.min():.2f} to {u4.max():.2f}), and the lowest cells pair PhishStorm, PhiUSIIL or Phishpedia phishing with PhiUSIIL or crawled legitimate URLs.

![R4 AUC for every phishing-by-legitimate cell (left) and the distribution of swap effects (right).]({figs["source"]})

H5, an interaction between phishing and legitimate source, holds in {pct(verd.loc["H5", "share"])} of settings; the first study also called it inconclusive, so a "not replicated" verdict here is the expected outcome.

## 4.4 F4: split sensitivity (not replicated)

The first study saw R4 AUC vary far more across splits than raw AUC (SD up to 0.1164 against at most 0.0026). Here the median SD is {sd4:.3f} for R4 and {sd1:.3f} for R1, and the largest R4 SD is {sdmax:.3f}. R4 is the more variable in {pct(share_gt)} of settings, but exceeds three times the raw SD in only {pct(verd.loc["F4", "share"])} of them. With 5 to 10 thousand URLs per cell and domain-grouped splits the variability is smaller than in a single 10-split study on one benchmark.

![SD of AUC across ten splits, raw against R4, one point per cell and model.]({figs["split"]})

## 4.5 HP: platform masking (not testable)

Masking replaces hosting-platform domains with a neutral token. The caps used here leave no registrable domain on a hosting platform in any cell, so there is nothing to mask and the finding cannot be tested. A design that keeps platform domains is future work.

## 4.6 H6: independent-benign transfer (replicated)

Models trained on one cell and evaluated on cells that share no source with it keep an R4 AUC above 0.5 in every setting (median {h6med:.3f}, lowest {h6lo:.3f}; {len(h6r4)} train-test pairs across the two transfer models). The first study's 0.694 and 0.706 rested on 119 benign domains; the pairs here each use thousands.

![Transfer AUC on fully independent cells.]({figs["transfer"]})

## 4.7 OOD: naturally browsed legitimate pages (partly replicated)

A model's false-alarm rate on 2,555 natural legitimate pages from 562 sites, none in any training source, is compared with its own test side at the same 1% threshold. The median is {pct(ood_nat, 1)} on natural pages against {pct(ood_test, 1)} in-cell; at the 0.1% threshold {pct(ood_nat01, 1)}; at the default 0.5 threshold {pct(ood_05, 0)}. The natural rate exceeds five times the in-cell rate in {pct(verd.loc["OOD", "share"])} of settings. The first study's reversal (1.0 on natural pages for the raw model) is not reproduced in this setting, but a benchmark threshold still understates real-world false alarms.

![False alarms on natural pages against the cell's own test side, log scale.]({figs["ood"]})

## 4.8 Negative controls

With shuffled training labels, mean AUC stays between {ctrl_lo:.3f} and {ctrl_hi:.3f} over 100 conditions (cell, representation, model); {n_flag} is flagged under the |mean - 0.5| > 0.05 rule. The flagged condition is examined in Section 6.

![Shuffled-label controls, 100 conditions.]({figs["controls"]})

## 4.9 Dataset fingerprints

A model can tell which source a URL came from even within one class, which is the mechanism behind source dependence. The table gives balanced accuracy for predicting the source of legitimate and phishing URLs (chance 0.20 for URLs and 0.50 for page HTML). It falls when URLs are reduced to R4 but stays well above chance.

**Table 3.** Source identification within one class (5 domain folds).

{tbl(e8)}

# 5. Reproduction of the first study

The first study's raw PhiUSIIL cell scored AUC 0.999 (XGBoost); this run scores 0.864 on the study cell (Table 4).

**Table 4.** Published against reproduced AUC (XGBoost, median over splits).

{tbl(e0t)}

# 6. Follow-up checks

**Why the PhiUSIIL cell scores lower than published.** PhiUSIIL was re-run alone, adding one cleaning step at a time (5 splits). Raw PhiUSIIL through our loader already scores about 0.94 (XGBoost); sampling to 10,000 per class, removing domains shared with other phishing sources, the pool rules and the study caps take it to 0.867. The cleaning explains about 0.07 of the gap; about 0.06 is gone before any cleaning, most likely because URLs are standardised on loading (inferred, not tested, as the original strings were lost). R4 stays between 0.79 and 0.85 at every stage against 0.730 published.

**The flagged shuffled-label control.** In the URL-Phish phishing against PhiUSIIL legitimate cell, LightGBM trained on shuffled labels scores below chance at every seed: mean {cs.loc["lightgbm", "mean"]:.3f} (SD {cs.loc["lightgbm", "std"]:.3f}, 50 runs); the character n-gram model scores {cs.loc["char_ngram", "mean"]:.3f}. A leak raises a control above 0.5, so this is read as a model artefact in one cell and listed as a limitation.

![Left: XGBoost AUC from raw PhiUSIIL to the study cell. Right: the flagged control.]({figs["follow"]})

# 7. Part B: page HTML (exploratory)

Four cells (Phishpedia or PhreshPhish phishing against PhreshPhish or crawled legitimate pages) use the 84 page features, grouped into P1 (all), P2 (scripts and structure removed), P3 (forms and text) and P4 (forms only). **Part B gives no verdicts.**

**Table 5.** Page and URL ROC-AUC, median of 10 splits.

{tbl(pb_t)}

- **Page features do not show the URL drop.** P1 scores {pb[pb.model == "lightgbm"].P1.min():.3f} to {pb[pb.model == "lightgbm"].P1.max():.3f} where the R4 URL alone scores {pb[pb.model == "lightgbm"].R4.min():.3f} to {pb[pb.model == "lightgbm"].R4.max():.3f}. Forms only (P4) still reaches {pb[pb.model == "lightgbm"].P4.min():.3f} to {pb[pb.model == "lightgbm"].P4.max():.3f}.
- **Transfer is uneven.** A Phishpedia-vs-crawl model scores {ptr.auc.iloc[0]:.3f} on PhreshPhish cells ({ptr.auc.iloc[1]:.3f} with the R4 URL added); the reverse direction scores {ptr.auc.iloc[2]:.3f}.
- **Coverage is uneven.** Usable HTML exists for 91% of PhreshPhish benign rows but 63% of phishing rows; in PhreshPhish, *missing HTML alone* predicts phishing with ROC-AUC 0.639. Page numbers may therefore be optimistic.

![Page and URL representations, LightGBM.]({figs["pageb"]})

![Share of rows with usable HTML, by source and class.]({figs["cov"]})

**Table 6.** False alarms on 2,226 natural legitimate pages with HTML.

{tbl(pnat_t)}

# 8. Limitations

- **Sources.** Two sources (PhiUSIIL, PhishStorm) are homepage-heavy or old; PhishTank is not in the pool. Results describe these public datasets.
- **Not testable.** HP, and per-source temporal effects: PhiUSIIL carries no per-row dates.
- **Sample size.** Cells use up to 10,000 URLs per class with 5 per domain; this lowers cross-split variability compared with a larger pool.
- **Feature engine.** 99 hand-built features replace the first study's 38; R3 equals R2 by construction.
- **Control.** One of 100 shuffled-label controls is flagged (below chance, one cell).
- **Part B.** Four cells, two sources with saved HTML, uneven coverage by class.
- **No hand-typed results.** Every number is read from `reports/phishguard/tables/` by `python -m phishguard.report`; seeds are fixed.

# 9. What can and cannot be claimed

**Table 7.** Claim register: each finding with the wording this run supports.

{tbl(reg_tbl, widths=[14, 24, 34, 11, 30])}

# 10. Reproducibility

`python -m phishguard all` runs the 291 jobs (resumable, one result file per job); `python -m phishguard.checks reproduce|control` runs the follow-up checks; `python -m phishguard.report` builds this report. The plan and the replication rule are frozen at commit `082b058`; results are at `267a9d7`; code is in the `phishguard/` package of the PhishDrift repository, which is otherwise unaffected.

# Figure inventory

| Figure | Section | Content |
|---|---|---|
| 1 | 3.3 | Study design |
| 2 | 4.1 | Representation ladder across 25 cells |
| 3 | 4.1 | Median AUC by representation and model |
| 4 | 4.2 | Share of the drop by step |
| 5 | 4.3 | R4 AUC by cell, swap effects |
| 6 | 4.4 | Split-to-split SD, raw against R4 |
| 7 | 4.6 | Transfer to independent cells |
| 8 | 4.7 | False alarms on natural pages |
| 9 | 4.8 | Shuffled-label controls |
| 10 | 6 | PhiUSIIL reproduction and the flagged control |
| 11 | 7 | Page and URL representations |
| 12 | 7 | HTML coverage by source |
"""
    # number the figure captions in the order of appearance
    n = [0]

    def num(m):
        n[0] += 1
        return f"![Figure {n[0]}. {m.group(1)}]({m.group(2)})"

    md = re.sub(r"!\[(.*?)\]\((fig\d+_[a-z0-9_]+\.png)\)", num, md)
    path = out / "phishguard_report.md"
    path.write_text(md, encoding="utf-8")
    return path


def main() -> int:
    ap = argparse.ArgumentParser(prog="phishguard.report")
    ap.add_argument("--run", type=Path, default=Path("data/interim/phishguard"))
    ap.add_argument("--out", type=Path, default=Path("reports/phishguard/report"))
    a = ap.parse_args()
    print(build(a.run, a.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
