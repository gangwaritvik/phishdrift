# ruff: noqa: E501
"""Assemble the final PBL report (Markdown) from the PhishGuard study report and the PhishDrift chapters.

    python scripts/build_pbl.py --guard reports/phishguard/report/phishguard_report.md \
        --drift /mnt/project-files/phishdrift/paper/pbl/phishdrift_chapters.md --out /tmp/pbl

Chapters 1, 2 (intro part) and 10 are written here; chapters 3-4 are the PhishGuard report, renumbered;
chapters 5-9 are the PhishDrift chapters. Numbers in chapters 1, 2 and 10 are read from the PhishGuard tables.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

import pandas as pd

TABLES = Path("reports/phishguard/tables")


def split_top(md: str) -> dict[str, str]:
    """Split a Markdown body at its top-level '# ' headings, keyed by the number at the start."""
    out: dict[str, str] = {}
    key, buf = "front", []
    for ln in md.splitlines():
        m = re.match(r"# (\d+)\. ", ln) or (re.match(r"# (Figure inventory)", ln))
        if m:
            out[key] = "\n".join(buf)
            key, buf = m.group(1), [ln]
        else:
            buf.append(ln)
    out[key] = "\n".join(buf)
    return out


def body(section: str) -> str:
    return "\n".join(section.splitlines()[1:]).strip()


def sub(text: str, old: str, new: str, *, regex: bool = False) -> str:
    """Replace one fragment and fail loudly if it is missing (the sources are generated)."""
    if regex:
        out, n = re.subn(old, new, text, flags=re.S)
        if not n:
            raise SystemExit(f"pattern not found: {old[:60]}")
        return out
    if old not in text:
        raise SystemExit(f"fragment not found: {old[:60]}")
    return text.replace(old, new)


VERDICT_WORDS = [
    ("Not replicated", "Does not hold"),
    ("Partly replicated", "Holds in part"),
    ("Replicated", "Holds"),
    ("not replicated", "does not hold"),
    ("partly replicated", "holds in part"),
    ("replicated", "holds"),
]
QUESTION_IDS = [("F1", "Q1"), ("F2", "Q2"), ("F3", "Q3"), ("F4", "Q4"), ("HP", "Q5"), ("H6", "Q6"), ("OOD", "Q7")]


def reframe_study(t: str) -> str:
    """Turn the study text into stand-alone findings: no earlier report, no replication wording."""
    t = sub(t, ", including the character n-gram model that held up best in the first study.", ".")
    t = sub(t, r"The first study put most of the R1 to R4 drop.*?Here the host and subdomain step", "The host and subdomain step", regex=True)
    t = sub(t, r"This run uses 99 features rather than 38, balances depth, and caps URLs per domain, all of which can change where the information sits; the main report does not choose among those explanations.", "The feature set, depth balancing and the per-domain cap can all change where the information sits; the main study does not choose among those explanations.")
    t = sub(t, r"The first study's pattern is therefore visible again on the raw benchmark for XGBoost, and it fades as the benchmark is cleaned. That is consistent with the F2 pattern being tied", "A host-dominated drop is therefore visible on the raw benchmark for XGBoost and fades as the benchmark is cleaned. That is consistent with the pattern being tied")
    t = sub(t, r'; the first study also called it inconclusive, so a "not replicated" verdict here is the expected outcome.', "; an interaction is hard to establish with this many settings, so it is treated as inconclusive.")
    t = sub(t, r"The first study saw R4 AUC vary far more across splits than raw AUC \(SD up to 0.1164 against at most 0.0026\). Here the median SD", "The median SD", regex=True)
    t = sub(t, " the variability is smaller than in a single 10-split study on one benchmark.", " the variability is small.")
    t = sub(t, r"The first study's 0.694 and 0.706 rested on 119 benign domains; the pairs here each use thousands.", "Each pair uses thousands of legitimate domains.")
    t = sub(t, r"The first study's reversal \(1.0 on natural pages for the raw model\) is not reproduced in this setting, but a benchmark threshold", "No model flags every natural page, but a benchmark threshold", regex=True)
    t = sub(t, r"\*\*Why the PhiUSIIL cell scores lower than published\.\*\*.*?(?=\n\n\*\*The flagged)", "**How data preparation changes the PhiUSIIL result.** PhiUSIIL was re-run alone, adding one cleaning step at a time (5 splits). Raw PhiUSIIL through our loader scores about 0.94 (XGBoost); sampling to 10,000 per class, removing domains shared with other phishing sources, the pool rules and the study caps take it to 0.867, so data preparation alone moves the raw score by about 0.07. R4 stays between 0.79 and 0.85 at every stage.", regex=True)
    t = sub(t, "- **Feature engine.** 99 hand-built features replace the first study's 38; R3 equals R2 by construction.", "- **Feature engine.** R3 equals R2 by construction, because the engine drops a leading `www`.")
    # claim register: drop the "First study" column
    def drop_col(m: re.Match) -> str:
        rows = []
        for ln in m.group(0).splitlines():
            if ln.startswith("|"):
                cells = ln.split("|")
                del cells[2]
                ln = "|".join(cells)
            rows.append(ln)
        return "\n".join(rows)

    t = sub(t, r"\| Finding \| First study.*?(?=\n\n|\Z)", drop_col, regex=True)
    for a, b in VERDICT_WORDS:
        t = t.replace(a, b)
    t = re.sub(r"\bF3_depth\b", "Q3 (depth)", t)
    for a, b in QUESTION_IDS:
        t = re.sub(rf"\b{a}\b", b, t)
    t = re.sub(r"\bH5\b", "the interaction check", t)
    t = t.replace("## 4.14 What can and cannot be claimed", "## 4.14 What can and cannot be claimed")
    return t


def reframe_drift(t: str) -> str:
    t = sub(t, "A separate research study that re-tests the prior report's findings (PhishGuard) is covered in its own chapter and is not repeated here.", "The evaluation study (Chapters 3 and 4) is not repeated here.")
    t = sub(t, r"The prior study \(`docs/prior_work/representation_sensitivity_report.pdf`\) found that.*?\(`docs/PROJECT_SPEC.md`, lessons L1 and L3\)\.", "The evaluation study (Chapter 4) shows that a benchmark score depends on how URLs are written, which sources make up each class and which split is used, and that a threshold set on a benchmark understates false alarms on ordinary pages (`docs/PROJECT_SPEC.md`).", regex=True)
    t = sub(t, "which matches the prior report's finding that hosting platforms and shorteners dominate the overlap between phishing corpora", "consistent with hosting platforms and shorteners dominating the overlap between phishing corpora")
    t = sub(t, ", following the prior report's result that masking raised held-out AUC in 60 of 60 comparisons", ", so that platform identity cannot stand in for phishing (the effect of masking was not testable in Chapter 4: no platform domains remain in the study cells)")
    t = sub(t, "The gap is smaller than the prior report's (0.9988 to 0.7297 on PhiUSIIL), but it is large.", "The gap is large.")
    t = sub(t, "No model collapsed the way the prior report's raw benchmark model did (all 11,895 natural URLs flagged), so the homepage shortcut has not returned.", "No model flags every natural page, so the homepage shortcut has not returned.")
    t = re.sub(r"^# PhishDrift chapters \(5 to 9\)\n+", "", t)
    t = re.sub(r"^---\n", "", t, flags=re.M)
    m = re.search(r"^# 5 .*$", t, flags=re.M)
    pre, rest = t[: m.start()].strip(), t[m.start() :]
    first, _, tail = rest.partition("\n")
    t = first + "\n\n" + pre + "\n" + tail
    t = re.sub(r"^# (\d) ", r"# \1. ", t, flags=re.M)
    return t


def build(guard: Path, drift: Path, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    g = split_top(guard.read_text(encoding="utf-8").split("\n---\n", 2)[-1])
    verd = pd.read_csv(TABLES / "verdicts.csv").set_index("finding")
    runs = pd.read_csv(TABLES / "runs.csv")
    runs = runs[runs.cell.notna()]
    piv = runs.pivot_table(index=["cell", "model"], columns="rep", values="roc_auc")
    r1, r4 = piv.R1.median(), piv.R4.median()
    ood = pd.read_csv(TABLES / "OOD.csv")
    ood_nat, ood_test = ood.natural_fpr.median(), ood.test_fpr.median()
    word = {"replicated": "holds", "partly replicated": "holds in part", "not replicated": "does not hold", "not testable": "not testable"}
    v = lambda k: word[verd.loc[k, "verdict"]]  # noqa: E731
    pct = lambda k: f"{100 * verd.loc[k, 'share']:.0f}%"  # noqa: E731

    abstract = f"""Phishing detectors are usually judged by one score on one benchmark. This project asks how far such scores can be trusted, and then builds a detector that is evaluated under the stricter rules the answer calls for. It has two parts. **Part I** is an evaluation study: seven questions about how a detector's score depends on URL form, source composition, the split and the legitimate pages it meets, tested across five phishing sources, five legitimate sources, four model families and ten domain-grouped splits, with the rule for calling a result consistent fixed before the run. **Part II** is the detector itself: a pooled, tiered phishing detector (URL model, page model, domain checks) shipped as a Chrome extension with a FastAPI backend, with allowlist and blocklist layers and plain-English reasons for every warning.

In Part I, the median score falls from {r1:.3f} on raw URLs to {r4:.3f} when a URL is reduced to its domain, and the fall appears in {pct("F1")} of settings; transfer to datasets that share no source stays above chance. Source dependence {v("F3")} ({pct("F3")} of settings) and the gap in false alarms on naturally browsed legitimate pages {v("OOD")} ({pct("OOD")}): at the 1% threshold {100 * ood_nat:.1f}% of those pages are flagged against {100 * ood_test:.1f}% on the model's own test side. The share of the fall that sits in the host name {v("F2")} across cells and depends on how the benchmark is prepared, and the larger split-to-split spread of the normalised score {v("F4")}. The effect of masking hosting platforms could not be tested. Each result is stated as behaviour under one frozen design, not as a general claim."""

    ch1 = f"""# 1. Introduction

## 1.1 Motivation

Phishing sites steal passwords and payment details, and new ones appear every hour. Machine-learning detectors are an obvious defence, and many published ones report accuracy above 99% on a public dataset. A detector that reaches that on one dataset can still fail on the pages a person actually browses. In this project the median AUC falls from {r1:.3f} on raw URLs to {r4:.3f} once URLs are reduced to their domain, and at the 1% threshold set on a benchmark, {100 * ood_nat:.1f}% of ordinary legitimate pages are flagged against {100 * ood_test:.1f}% on the benchmark itself.

## 1.2 Objectives

1. **Measure** how far a detector's score depends on URL form, source composition, the split and the legitimate pages it meets, across many datasets and several model families (Part I).
2. **Build** a practical detector, evaluated only under protocols that guard against those failures, and ship it as a working Chrome extension with a backend (Part II).
3. **Report** every number from a script that writes to `reports/`, with fixed seeds, and say plainly where a result is measured, inferred or not tested.

## 1.3 What is new

A plain "classifier on a static phishing dataset" is common. Novelty here is in the protocol: domain-grouped splits repeated ten times, leave-one-source-out and out-of-distribution false-alarm reporting, negative controls with shuffled labels, URL-depth checks, and tiered models whose missing inputs never reveal the data source; then a deployed, explainable system built on that protocol.

## 1.4 Scope and structure

Chapter 2 gives the background and the questions. Chapters 3 and 4 are Part I, the evaluation study. Chapters 5 to 9 are Part II: data, features and models, the extension and backend, the evaluation of the detector, and the limitations. Chapter 10 concludes. Results from Part I are not used as evidence for Part II, or the reverse.
"""

    ch2 = f"""# 2. Background and questions

## 2.1 Why one benchmark score misleads

A phishing-URL detector is normally scored once, on one dataset, with one split. Three things can make that number unrepresentative: the *form* of the URL (a raw URL carries path, query and host quirks that differ between sources), the *composition* of the data (which sources supply each class, and how deep their URLs are), and the *split* (which domains happen to land in the test side). A fourth gap opens at deployment: the legitimate pages a person browses are not the legitimate pages of the benchmark. This study measures each of these directly.

## 2.2 Questions asked

The study answers seven questions, one for each way a single score can mislead:

{body(g["2"]).split("one per finding:", 1)[-1].strip() if "one per finding:" in g["2"] else body(g["2"])}

## 2.3 Related datasets and tools

The study and the detector draw on public datasets (PhreshPhish, PhiUSIIL, URL-Phish, PhishStorm, Phishpedia, Phish-Blitz) and live feeds (OpenPhish, Phishing.Database). Only the URL, label, date and page HTML are read from any of them; no dataset's precomputed feature columns are used, because one such column (a similarity index) alone identifies PhiUSIIL's legitimate class. Features follow the published definitions of Hannousse and Yahiouche and of PhiUSIIL, re-implemented in one engine. Models are LightGBM, XGBoost, logistic regression and a character n-gram TF-IDF linear model.
"""
    rule = "A setting (one cell and model, or one pair of cells) *holds* when the direction is the same in at least 9 of 10 splits and the pooled bootstrap 95% interval excludes the null. A question's answer **holds** if it holds in at least 80% of its testable settings, **holds in part** at 50 to 80%, and **does not hold** below 50%; with fewer than 3 testable settings it is **not testable**. A setting is testable with at least 500 URLs and 100 domains per class. The rule and `configs/phishguard.yaml` were frozen at commit `082b058` before any result was seen. \"Does not hold\" describes this design's data; it is not a claim that the effect is absent elsewhere."
    ch3 = "# 3. Part I: design and method\n\n" + body(g["3"])
    ch3 = sub(ch3, r"## 3\.4 The rule for calling a finding replicated.*", "## 3.4 The rule for calling a result consistent\n\n" + rule, regex=True)
    ch4_parts = [
        "# 4. Part I: results\n",
        body(g["4"]),
        "\n## 4.10 Follow-up checks\n\n" + body(g["6"]),
        "\n## 4.11 Page HTML (exploratory)\n\n" + body(g["7"]),
        "\n## 4.12 Limitations of the study\n\n" + body(g["8"]),
        "\n## 4.13 What can and cannot be claimed\n\n" + body(g["9"]),
    ]
    ch4 = "\n".join(ch4_parts)
    ch3 = ch3.replace("Seven findings are tested", "Seven questions are tested")
    ch4 = reframe_study(ch4)
    ch4 = re.sub(r"\(Section 7\)", "(Section 4.11)", ch4)
    ch2 = ch2.replace("(Section 7)", "(Section 4.11)")
    ch4 = re.sub(r"Section 6\b", "Section 4.10", ch4)
    ch2 = re.sub(r"(Figure|Table) (\d+)\b", r"\1 4.\2", ch2)
    ch3 = re.sub(r"(Figure|Table) (\d+)\b", r"\1 4.\2", ch3)
    ch4 = re.sub(r"(Figure|Table) (\d+)\b", r"\1 4.\2", ch4)
    for a, b in QUESTION_IDS:
        ch2 = re.sub(rf"\*\*{a}\*\*", f"**{b}**", ch2)
    ch2 = re.sub(r"\*\*H5\*\*", "**Interaction**", ch2)

    drift_txt = (
        reframe_drift(drift.read_text(encoding="utf-8"))
        if drift.exists()
        else "# 5. PhishDrift (chapters pending)\n"
    )

    ch10 = f"""# 10. Conclusion and future work

## 10.1 What was achieved

- **An evaluation study.** A URL model's score depends heavily on URL form: it {v("F1")} across 25 source cells, four model families and ten splits. Transfer to independent datasets stays above chance ({v("H6")}). Source dependence {v("F3")} and the natural-page false-alarm gap {v("OOD")}. The share of the fall that sits in the host name and the size of the split-to-split spread did not hold across the cells, and an extra check ties the first to how the raw benchmark is prepared.
- **A working detector.** PhishDrift runs as a Chrome extension with a FastAPI backend and layered checks (allowlist, blocklist, URL model, page model, domain checks), evaluated with recall at fixed false-alarm rates, a held-out source, a newest time slice and natural-page false alarms (Chapter 8).
- **A reproducible record.** Every reported number comes from a script in the repository that writes to `reports/`; seeds are fixed; the study's plan and consistency rule were frozen before the run.

## 10.2 Limitations

See Sections 4.12 and Chapter 9. In short: public benchmarks only, two of them old or homepage-heavy; the HTML part rests on two sources with uneven coverage; one shuffled-label control is flagged; platform masking is untested; tier C of the detector rests on a small live capture; and the extension has been checked in test harnesses and on stored pages, not in a long field trial.

## 10.3 Future work

1. Add PhishTank and further live-feed sources to the study, and re-run it with hosting-platform domains kept so platform masking can be tested.
2. Test the benchmark-preparation explanation for the host-share result on more datasets.
3. Add a held-out source that has page HTML, so the page model's gain can be measured out of source.
4. Grow the tier C capture over more days, and measure blocklist coverage forward in time.
5. Optional second-opinion layer for the grey zone (planned, not built).

# References

1. A. Hannousse and S. Yahiouche, "Towards benchmark datasets for machine learning based website phishing detection", *Engineering Applications of Artificial Intelligence*, 2021.
2. A. Prasad and S. Chandra, "PhiUSIIL: a diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning", *Computers & Security*, 2024.
3. PhreshPhish dataset, Hugging Face `phreshphish/phreshphish`.
4. URL-Phish dataset (Mendeley Data); PhishStorm dataset (Aalto University); Phish-Blitz and Phishpedia datasets as released by their authors.
5. G. Ke et al., "LightGBM: a highly efficient gradient boosting decision tree", *NeurIPS*, 2017.
6. T. Chen and C. Guestrin, "XGBoost: a scalable tree boosting system", *KDD*, 2016.
7. V. Le Pochat et al., "Tranco: a research-oriented top sites ranking hardened against manipulation", *NDSS*, 2019.
8. OpenPhish community feed; Phishing.Database (MIT licence); Google Safe Browsing Update API.

*Citation details should be checked against the originals before submission.*
"""

    title = """---
title: "PhishDrift"
subtitle: "Evaluating Phishing-URL Detection Across Sources, Representations and Splits, and an Explainable Chrome-Extension Detector"
author: "Ritvik Gangwar"
date: "Project-Based Learning final report, 6th semester, October 2026"
---

"""
    heads = [
        ln[2:].strip()
        for ln in (ch1 + ch2 + ch3 + ch4 + drift_txt + ch10).splitlines()
        if ln.startswith("# ")
    ]
    contents = "# Contents\n\n" + "\n".join(f"- {h}" for h in heads) + "\n\n"
    text = (
        title + contents + "# Abstract\n\n" + abstract + "\n\n" + ch1 + "\n" + ch2 + "\n"
        + ch3 + "\n" + ch4 + "\n" + drift_txt + "\n" + ch10
    )
    path = out / "pbl_report.md"
    path.write_text(text, encoding="utf-8")
    return path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--guard", type=Path, default=Path("reports/phishguard/report/phishguard_report.md")
    )
    ap.add_argument(
        "--drift",
        type=Path,
        default=Path("/mnt/project-files/phishdrift/paper/pbl/phishdrift_chapters.md"),
    )
    ap.add_argument("--out", type=Path, default=Path("reports/pbl"))
    a = ap.parse_args()
    print(build(a.guard, a.drift, a.out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
