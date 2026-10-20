# ruff: noqa: E501, B905
"""Figures for the PBL report chapters on PhishDrift (chapters 5-9).

Reads only the generated tables in reports/*.md (no training, no hand-typed results) and writes
PNG files at 200 dpi, 6.5 inch wide. The layer diagram (fig06) contains no data.

Run: python scripts/pbl_figures.py [--out DIR]
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
DEFAULT_OUT = Path("/mnt/project-files/phishdrift/paper/pbl/figures")

# Okabe-Ito colour-blind-safe palette, fixed for every figure.
C = {
    "blue": "#0072B2",
    "orange": "#E69F00",
    "green": "#009E73",
    "red": "#D55E00",
    "purple": "#CC79A7",
    "sky": "#56B4E9",
    "grey": "#7F7F7F",
    "dark": "#222222",
}
WIDTH = 6.5
DPI = 200

plt.rcParams.update(
    {
        "figure.dpi": DPI,
        "savefig.dpi": DPI,
        "font.size": 8.5,
        "axes.titlesize": 9,
        "axes.labelsize": 8.5,
        "legend.fontsize": 7.5,
        "xtick.labelsize": 8,
        "ytick.labelsize": 8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.alpha": 0.25,
        "axes.axisbelow": True,
        "font.family": "DejaVu Sans",
    }
)


# ---------------------------------------------------------------------------
# Markdown table reader
# ---------------------------------------------------------------------------
def read_tables(name: str) -> list[tuple[str, list[str], list[dict[str, str]]]]:
    """Return (section heading, header, rows) for every pipe table in reports/<name>."""
    lines = (REPORTS / name).read_text(encoding="utf-8").splitlines()
    out = []
    heading = ""
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("#"):
            heading = line.lstrip("# ").strip()
        if (
            line.startswith("|")
            and i + 1 < len(lines)
            and re.match(r"^\|[\s\-|:]+\|$", lines[i + 1])
        ):
            header = []
            for c in line.strip().strip("|").split("|"):
                c = c.strip()
                header.append(c + "_2" if c in header else c)
            rows = []
            i += 2
            while i < len(lines) and lines[i].startswith("|"):
                cells = [c.strip().strip("`") for c in lines[i].strip().strip("|").split("|")]
                if len(cells) == len(header):
                    rows.append(dict(zip(header, cells)))
                i += 1
            out.append((heading, header, rows))
            continue
        i += 1
    return out


def rows_of(name: str, heading: str | None = None) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for h, _, r in read_tables(name):
        if heading is None or h == heading:
            rows += r
    return rows


def pick(tbl: list[dict[str, str]], /, **kw: str) -> dict[str, str]:
    hit = [r for r in tbl if all(r.get(k) == v for k, v in kw.items())]
    if len(hit) != 1:
        raise KeyError(f"expected one row for {kw}, found {len(hit)}")
    return hit[0]


NUM = r"-?\d+(?:\.\d+)?"


def med(cell: str) -> float:
    return float(re.search(NUM, cell).group())


def span(cell: str) -> tuple[float, float]:
    m = re.search(rf"\[({NUM}), ({NUM})\]", cell)
    if not m:
        v = med(cell)
        return v, v
    return float(m.group(1)), float(m.group(2))


def second(cell: str) -> float:
    """'73.8 / 20.1' -> 20.1"""
    return float(re.findall(NUM, cell)[1])


def save(fig: plt.Figure, out: Path, name: str) -> None:
    fig.savefig(out / name, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("wrote", out / name)


# ---------------------------------------------------------------------------
# Fig 1: recall at fixed FPR by model and set
# ---------------------------------------------------------------------------
def fig_recall(out: Path) -> None:
    sets = [
        ("test", "test", "test"),
        ("heldout_source", "heldout_source", "held-out source\n(PhishStorm)"),
        ("time_slice", "time_slice", "newest time\nslice"),
    ]
    models = []  # (label, colour, getter(set_key) -> row)
    ta = {s: rows_of("tier_a.md", s) for s, _, _ in sets}
    hy = rows_of("hybrid2.md")
    st = rows_of("stack_a.md")
    bl = rows_of("blend2.md")
    models.append(("LightGBM", C["grey"], lambda s: pick(ta[s], model="lightgbm", features="all")))
    models.append(("char n-gram + LR", C["sky"], lambda s: pick(ta[s], model="char_ngram")))
    models.append(("stack (A)", C["purple"], lambda s: pick(st, set=s)))
    models.append(("hybrid2 (A)", C["blue"], lambda s: pick(hy, set=s)))
    models.append(("blend (A + B)", C["green"], lambda s: pick(bl, set=s, model="blend")))
    fig, axes = plt.subplots(1, 2, figsize=(WIDTH, 3.0), sharey=False)
    for ax, col, title in zip(
        axes, ["recall @1% FPR", "recall @0.1% FPR"], ["Recall at FPR 1%", "Recall at FPR 0.1%"]
    ):
        n = len(models)
        w = 0.8 / n
        for j, (lab, colr, get) in enumerate(models):
            vals, lo, hi = [], [], []
            for s, _, _ in sets:
                cell = get(s)[col]
                v = med(cell)
                a, b = span(cell)
                vals.append(v)
                lo.append(v - a)
                hi.append(b - v)
            xs = [i + (j - (n - 1) / 2) * w for i in range(len(sets))]
            ax.bar(
                xs,
                vals,
                w * 0.92,
                yerr=[lo, hi],
                color=colr,
                label=lab,
                error_kw={"lw": 0.7, "capsize": 1.5},
            )
        ax.set_xticks(range(len(sets)))
        ax.set_xticklabels([t for _, _, t in sets])
        ax.set_ylabel("recall (%)")
        ax.set_ylim(0, 100)
        ax.set_title(title)
    h, lab = axes[0].get_legend_handles_labels()
    fig.legend(h, lab, loc="lower center", ncol=5, frameon=False, bbox_to_anchor=(0.5, -0.04))
    fig.suptitle(
        "Median of 10 domain-grouped splits, whiskers = min and max (allowlist and blocklist off)",
        y=1.0,
        fontsize=8,
    )
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    save(fig, out, "fig01_recall_by_model.png")


# ---------------------------------------------------------------------------
# Fig 2: address model vs blend, with and without HTML
# ---------------------------------------------------------------------------
def fig_html(out: Path) -> None:
    bl = rows_of("blend2.md")
    groups = [
        ("test", "test:html", "test\nwith HTML"),
        ("test", "test:nohtml", "test\nno HTML"),
        ("time", "time_slice:html", "time slice\nwith HTML"),
        ("time", "time_slice:nohtml", "time slice\nno HTML"),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(WIDTH, 2.9))
    for ax, col, title in zip(
        axes, ["recall @1% FPR", "recall @0.1% FPR"], ["Recall at FPR 1%", "Recall at FPR 0.1%"]
    ):
        for j, (model, lab, colr) in enumerate(
            [
                ("a_only", "address model only (tier A)", C["blue"]),
                ("blend", "blend (page model where HTML)", C["green"]),
            ]
        ):
            vals, lo, hi = [], [], []
            for _, s, _ in groups:
                cell = pick(bl, set=s, model=model)[col]
                v = med(cell)
                a, b = span(cell)
                vals.append(v)
                lo.append(v - a)
                hi.append(b - v)
            xs = [i + (j - 0.5) * 0.38 for i in range(len(groups))]
            ax.bar(
                xs,
                vals,
                0.36,
                yerr=[lo, hi],
                color=colr,
                label=lab,
                error_kw={"lw": 0.7, "capsize": 1.5},
            )
        ax.set_xticks(range(len(groups)))
        ax.set_xticklabels([t for _, _, t in groups])
        ax.set_ylim(0, 100)
        ax.set_ylabel("recall (%)")
        ax.set_title(title)
    axes[0].legend(loc="upper right", frameon=False, fontsize=7)
    fig.tight_layout()
    save(fig, out, "fig02_html_gain.png")


# ---------------------------------------------------------------------------
# Fig 3: leave-one-source-out threshold transfer
# ---------------------------------------------------------------------------
def fig_loso(out: Path) -> None:
    rows = rows_of("loso.md", "leave_out")
    srcs = [
        ("phreshphish", "PhreshPhish"),
        ("phiusiil", "PhiUSIIL"),
        ("urlphish", "URL-Phish"),
        ("live", "Live feeds"),
    ]
    models = [
        ("lightgbm", "LightGBM", C["grey"]),
        ("char_ngram", "char n-gram + LR", C["sky"]),
        ("baseline", "tld_risk baseline", C["orange"]),
    ]
    fig, ax = plt.subplots(figsize=(WIDTH, 2.8))
    w = 0.26
    for j, (m, lab, colr) in enumerate(models):
        vals = [second(pick(rows, source=s, model=m)["cal 1%: recall / FPR"]) for s, _ in srcs]
        xs = [i + (j - 1) * w for i in range(len(srcs))]
        bars = ax.bar(xs, vals, w * 0.92, color=colr, label=lab)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.3, f"{v:g}", ha="center", fontsize=6.5)
    ax.axhline(1.0, color=C["red"], lw=1, ls="--")
    ax.text(len(srcs) - 0.45, 1.5, "target 1%", color=C["red"], fontsize=7, ha="right")
    ax.set_xticks(range(len(srcs)))
    ax.set_xticklabels([n for _, n in srcs])
    ax.set_ylabel("false-positive rate (%) on the left-out source")
    ax.set_title(
        "Leave-one-source-out: FPR at the threshold chosen for 1% on the other sources\n(tier A, splits 0 to 2 only)"
    )
    ax.legend(frameon=False)
    fig.tight_layout()
    save(fig, out, "fig03_loso_threshold_transfer.png")


# ---------------------------------------------------------------------------
# Fig 4: false alarms on naturally browsed legitimate pages
# ---------------------------------------------------------------------------
def fig_falsealarms(out: Path) -> None:
    ood = rows_of("ood_fpr.md")
    r2 = rows_of("blend2_rules.md")
    bo = rows_of("blend_ood.md")
    sv = rows_of("shipped_verdicts.md")
    pf = rows_of("page_fixes_fpr.md")

    def o(model: str) -> float:
        return med(
            pick(ood, model=model, **{"threshold from": "cal", "target FPR": "1.0%"})[
                "OOD FPR (all)"
            ]
        )

    def pf_val(allow: str) -> float:
        r = pick(pf, allowlist=allow, subset="pages the page model reads", side="after")
        return med(r["%"])

    sv_row = pick(sv, set="natural legitimate pages (ood_urls)")
    items = [
        ("LightGBM, URL only", o("lightgbm"), C["grey"]),
        ("XGBoost, URL only", o("xgboost"), C["grey"]),
        ("char n-gram + LR, URL only", o("char_ngram"), C["grey"]),
        (
            "hybrid2, URL only",
            med(pick(r2, set="ood_urls", rule="a_only")["legit warned"]),
            C["blue"],
        ),
        (
            "page model blend, pages with HTML",
            med(pick(bo, set="ood_html", model="blend", **{"target FPR": "1.0%"})["OOD FPR"]),
            C["green"],
        ),
        (
            "'agree' rule, pages with HTML",
            med(pick(r2, set="ood_html", rule="agree")["legit warned"]),
            C["green"],
        ),
        ("shipped, no allowlist (page pipeline)", pf_val("off"), C["purple"]),
        (
            "shipped URL layers + allowlist",
            med(re.search(r"\((\d+\.\d+)%", sv_row["shipped flagged"]).group(1)),
            C["orange"],
        ),
        ("shipped + page pipeline + allowlist", pf_val("on"), C["orange"]),
    ]
    fig, ax = plt.subplots(figsize=(WIDTH, 3.1))
    labels = [i[0] for i in items][::-1]
    vals = [i[1] for i in items][::-1]
    cols = [i[2] for i in items][::-1]
    bars = ax.barh(labels, vals, color=cols)
    for b, v in zip(bars, vals):
        ax.text(v + 0.08, b.get_y() + b.get_height() / 2, f"{v:g}", va="center", fontsize=7)
    ax.axvline(1.0, color=C["red"], ls="--", lw=1)
    ax.text(1.05, -0.9, "1% target", color=C["red"], fontsize=7)
    ax.set_xlabel("share of ordinary legitimate pages flagged (%)")
    ax.set_title(
        "False alarms on naturally browsed legitimate pages (2,555 URLs / 562 sites; 2,226 with HTML)"
    )
    ax.set_xlim(0, 6.5)
    ax.grid(axis="y", alpha=0)
    fig.tight_layout()
    save(fig, out, "fig04_false_alarms_natural_pages.png")


# ---------------------------------------------------------------------------
# Fig 5: evasion before and after adversarial training
# ---------------------------------------------------------------------------
def fig_evasion(out: Path) -> None:
    ev = rows_of("robustness.md", "Evasion rate of phishing URLs")
    fa = rows_of("robustness.md", "False alarms on rewritten and long legitimate URLs")
    fams = [
        ("homoglyph", "homo-\nglyph"),
        ("subdomain", "sub-\ndomain"),
        ("brand", "brand\nin path"),
        ("padding", "path\npadding"),
        ("shortener", "short-\nener"),
        ("tld", "TLD\nswap"),
    ]
    col = "evaded at suspicious (1% FPR)"
    col2 = "flagged at suspicious"
    fig, axes = plt.subplots(1, 2, figsize=(WIDTH, 3.0))
    series_l = [
        ("base (shipped)", C["blue"], lambda f: pick(ev, family=f, model="base")[col]),
        (
            "adv, seen in training",
            C["green"],
            lambda f: pick(ev, family=f"{f} (seen in training)", model="adv")[col],
        ),
        (
            "adv, family held out",
            C["orange"],
            lambda f: pick(ev, family=f"{f} (held out)", model="adv")[col],
        ),
    ]
    series_r = [
        ("base (shipped)", C["blue"], lambda f: pick(fa, set=f"{f}:benign", model="base")[col2]),
        (
            "adv, seen in training",
            C["green"],
            lambda f: pick(fa, set=f"{f}:benign (seen in training)", model="adv")[col2],
        ),
        (
            "adv, family held out",
            C["orange"],
            lambda f: pick(fa, set=f"{f}:benign (held out)", model="adv")[col2],
        ),
    ]
    for ax, series, title, ylab in [
        (axes[0], series_l, "Rewritten phishing URLs not flagged", "evaded (%)"),
        (axes[1], series_r, "Rewritten legitimate URLs flagged", "false alarms (%)"),
    ]:
        w = 0.26
        for j, (lab, colr, get) in enumerate(series):
            vals = [med(get(f)) for f, _ in fams]
            xs = [i + (j - 1) * w for i in range(len(fams))]
            ax.bar(xs, vals, w * 0.92, color=colr, label=lab)
        ax.set_xticks(range(len(fams)))
        ax.set_xticklabels([n for _, n in fams], fontsize=7)
        ax.set_ylim(0, 125)
        ax.set_ylabel(ylab)
        ax.set_title(title)
    clean = med(pick(ev, family="clean", model="base")[col])
    axes[0].axhline(
        clean, color=C["grey"], ls=":", lw=1, label=f"unmodified phishing, base ({clean:g}%)"
    )
    axes[1].axhline(1.0, color=C["red"], ls="--", lw=0.8, label="1% target on clean URLs")
    axes[0].legend(frameon=False, fontsize=6.3, loc="upper left")
    axes[1].legend(frameon=False, fontsize=6.3, loc="upper left")
    fig.suptitle(
        "Tier A (hybrid2) at the suspicious threshold; median over 6 splits, held-out columns rest on one split each",
        y=1.0,
        fontsize=7.5,
    )
    fig.tight_layout()
    save(fig, out, "fig05_evasion_adversarial.png")


# ---------------------------------------------------------------------------
# Fig 6: layer diagram (no data)
# ---------------------------------------------------------------------------
def box(ax, x, y, w, h, text, fc, ec=None, fs=7.5, bold=False):
    p = FancyBboxPatch(
        (x, y),
        w,
        h,
        boxstyle="round,pad=0.02,rounding_size=0.08",
        fc=fc,
        ec=ec or C["dark"],
        lw=0.8,
    )
    ax.add_patch(p)
    ax.text(
        x + w / 2,
        y + h / 2,
        text,
        ha="center",
        va="center",
        fontsize=fs,
        weight="bold" if bold else "normal",
        color=C["dark"],
    )


def arrow(ax, x1, y1, x2, y2, text=None, color=None):
    ax.annotate(
        "",
        xy=(x2, y2),
        xytext=(x1, y1),
        arrowprops={"arrowstyle": "->", "lw": 0.9, "color": color or C["dark"]},
    )
    if text:
        ax.text(
            (x1 + x2) / 2 + 0.08,
            (y1 + y2) / 2,
            text,
            fontsize=6.5,
            va="center",
            color=color or C["dark"],
        )


def fig_layers(out: Path) -> None:
    fig, ax = plt.subplots(figsize=(WIDTH, 6.2))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 12)
    ax.axis("off")
    ax.grid(False)
    dev, bk, tr = "#DCEBF7", "#FBEBD0", "#E7E7E7"
    lw_, lx = 5.6, 0.1
    box(
        ax,
        lx,
        10.9,
        lw_,
        0.8,
        "Navigation to a page\n(service worker: onBeforeNavigate, onCommitted)",
        tr,
        fs=6.4,
    )
    stack = [
        (
            9.5,
            "1  Allowlist: Tranco top 50,000, popular tenant hosts, user trust\nexact registrable domain; open-hosting zones excluded",
        ),
        (8.1, "2  Blocklist: synced hashes of feed URLs and domains\nshared hosts: full-URL match"),
        (
            6.7,
            "3  Address model (tier A hybrid2, about 1.6 ms) in the browser\nplus look-alike and brand rules, which only escalate",
        ),
        (
            4.3,
            "5  Page checks: content script reads the page\ntier B page model, 'agree' rule, password-form rule",
        ),
    ]
    for y, t in stack:
        box(ax, lx, y, lw_, 1.1, t, dev, fs=6.2)
    arrow(ax, 2.9, 10.9, 2.9, 10.6)
    arrow(ax, 2.9, 9.5, 2.9, 9.2)
    arrow(ax, 2.9, 8.1, 2.9, 7.8)
    arrow(ax, 2.9, 6.7, 2.9, 5.4)
    ax.text(3.05, 6.05, "judged by the page as well", fontsize=6.2, va="center")
    box(
        ax,
        6.3,
        9.5,
        3.6,
        1.1,
        "List builder, daily\nhashed lists, zones,\nsigned manifest",
        bk,
        fs=6.2,
    )
    arrow(ax, 6.3, 10.05, 5.7, 10.05)
    ax.text(6.0, 10.25, "sync", fontsize=6, ha="center")
    box(
        ax,
        6.3,
        6.7,
        3.6,
        1.1,
        "4  Domain checks (backend)\nRDAP, DNS, TLS rules\nreceives the domain only",
        bk,
        fs=6.2,
    )
    arrow(ax, 5.7, 7.25, 6.3, 7.25)
    ax.text(5.95, 7.5, "domain", fontsize=6, ha="center")
    ax.text(
        6.3, 6.2, "only for flagged addresses;\nfails open if slow or down", fontsize=6.2, va="top"
    )
    ax.text(
        6.3,
        5.0,
        "Not built: optional LLM\nsecond opinion (layer 6)",
        fontsize=6.2,
        va="top",
        color=C["grey"],
    )
    box(
        ax,
        lx,
        2.5,
        9.8,
        1.3,
        "Combiner: a blocklist hit always warns. Page and domain evidence can raise a verdict.\n"
        "A page with no credential field can lower an address warning. The address model alone\n"
        "does not open the warning page on a page that asks for nothing.",
        "#F3E6F0",
        fs=6.2,
    )
    arrow(ax, 2.9, 4.3, 2.9, 3.8)
    arrow(ax, 8.1, 6.7, 8.1, 3.8)
    ax.text(8.2, 5.3, "can raise", fontsize=6.2, va="center")
    verdicts = [
        (0.1, 2.9, "safe\n(no UI)", "#D8EFE5"),
        (3.3, 3.2, "suspicious\n(dismissable banner)", "#FCE9C0"),
        (6.7, 3.2, "dangerous\n(warning page,\n'proceed anyway')", "#F6D2C2"),
    ]
    for x, w, t, c in verdicts:
        box(ax, x, 0.5, w, 1.2, t, c, fs=6.6, bold=True)
        arrow(ax, x + w / 2, 2.5, x + w / 2, 1.7)
    ax.text(
        0.1,
        0.1,
        "Every warning carries plain-English reasons (TreeSHAP and rule hits).",
        fontsize=6.2,
        style="italic",
    )
    ax.add_patch(
        FancyBboxPatch(
            (6.3, 11.15), 0.3, 0.3, boxstyle="round,pad=0.01", fc=dev, ec=C["dark"], lw=0.6
        )
    )
    ax.text(6.7, 11.3, "runs on the device", fontsize=6.2, va="center")
    ax.add_patch(
        FancyBboxPatch(
            (6.3, 10.75), 0.3, 0.3, boxstyle="round,pad=0.01", fc=bk, ec=C["dark"], lw=0.6
        )
    )
    ax.text(6.7, 10.9, "runs on the backend", fontsize=6.2, va="center")
    save(fig, out, "fig06_layers.png")


# ---------------------------------------------------------------------------
# Fig 7: representation check
# ---------------------------------------------------------------------------
def fig_representation(out: Path) -> None:
    ta_raw = rows_of("tier_a.md", "test")
    ta_norm = rows_of("tier_a.md", "test_normalised")
    hy_raw = pick(rows_of("hybrid2.md"), set="test")
    hy_norm = rows_of("hybrid2_checks.md")[0]
    bc = rows_of("blend_checks.md")
    items = [
        (
            "LightGBM",
            pick(ta_raw, model="lightgbm", features="all"),
            pick(ta_norm, model="lightgbm", features="all"),
        ),
        ("char n-gram\n+ LR", pick(ta_raw, model="char_ngram"), pick(ta_norm, model="char_ngram")),
        ("hybrid2\n(A)", hy_raw, hy_norm),
        (
            "blend\n(A + B)",
            pick(bc, model="blend", rows="test"),
            pick(bc, model="blend_normalised", rows="test"),
        ),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(WIDTH, 2.8))
    for ax, col, title in zip(
        axes, ["recall @1% FPR", "recall @0.1% FPR"], ["Recall at FPR 1%", "Recall at FPR 0.1%"]
    ):
        w = 0.36
        for j, (lab, colr, k) in enumerate(
            [("raw URL", C["blue"], 1), ("normalised to https://www.<domain>", C["orange"], 2)]
        ):
            vals = [med(it[k][col]) for it in items]
            xs = [i + (j - 0.5) * w for i in range(len(items))]
            ax.bar(xs, vals, w * 0.92, color=colr, label=lab)
            for x, v in zip(xs, vals):
                ax.text(x, v + 1, f"{v:g}", ha="center", fontsize=6.5)
        ax.set_xticks(range(len(items)))
        ax.set_xticklabels([i[0] for i in items], fontsize=6.8)
        ax.set_ylim(0, 100)
        ax.set_ylabel("recall (%)")
        ax.set_title(title)
    axes[0].legend(frameon=False, fontsize=6.8, loc="upper left")
    fig.suptitle(
        "Representation check on the pooled test side (median of 10 splits)", y=1.0, fontsize=8
    )
    fig.tight_layout()
    save(fig, out, "fig07_representation.png")


# ---------------------------------------------------------------------------
# Fig 8: ROC-AUC by URL depth bucket
# ---------------------------------------------------------------------------
def fig_depth(out: Path) -> None:
    rows = rows_of("hybrid2_depth.md")
    depths = ["0", "1", "2", "3", "4+"]
    fig, ax = plt.subplots(figsize=(WIDTH, 2.8))
    for s, lab, colr, mk in [
        ("test", "test side", C["blue"], "o"),
        ("heldout_source", "held-out PhishStorm", C["orange"], "s"),
        ("time_slice", "newest time slice", C["green"], "^"),
    ]:
        vals = [med(pick(rows, set=s, depth=d)["ROC-AUC"]) for d in depths]
        ax.plot(depths, vals, marker=mk, color=colr, label=lab, lw=1.3)
        allv = med(pick(rows, set=s, depth="all")["ROC-AUC"])
        ax.axhline(allv, color=colr, ls=":", lw=0.8)
    ax.set_xlabel("URL path depth (non-empty path segments)")
    ax.set_ylabel("ROC-AUC (median of 10 splits)")
    ax.set_ylim(0.75, 1.0)
    ax.set_title(
        "hybrid2 by depth bucket (dotted line = all depths). Held-out depth 0 rests on 91 legitimate URLs"
    )
    ax.legend(frameon=False, loc="lower right")
    fig.tight_layout()
    save(fig, out, "fig08_depth_buckets.png")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    for f in (
        fig_recall,
        fig_html,
        fig_loso,
        fig_falsealarms,
        fig_evasion,
        fig_layers,
        fig_representation,
        fig_depth,
    ):
        f(args.out)


if __name__ == "__main__":
    main()
