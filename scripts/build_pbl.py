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


def build(guard: Path, drift: Path, out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    g = split_top(guard.read_text(encoding="utf-8").split("\n---\n", 2)[-1])
    verd = pd.read_csv(TABLES / "verdicts.csv").set_index("finding")
    v = lambda k: verd.loc[k, "verdict"]  # noqa: E731
    pct = lambda k: f"{100 * verd.loc[k, 'share']:.0f}%"  # noqa: E731

    abstract = f"""Phishing detectors are usually judged by one score on one benchmark. This project asks how far such scores can be trusted, and then builds a detector that is evaluated under the stricter rules the answer calls for. It has two parts. **PhishGuard** is a research study that re-implements and extends the author's earlier report on representation sensitivity in phishing-URL detection: seven findings are re-tested across five phishing sources, five legitimate sources, four model families and ten domain-grouped splits, with the rule for calling a finding replicated fixed before the run. **PhishDrift** is the software: a pooled, tiered phishing detector (URL model, page model, domain checks) shipped as a Chrome extension with a FastAPI backend, with allowlist and blocklist layers and plain-English reasons for every warning.

In the study, the drop in score when a URL is reduced to its domain is {v("F1")} in {pct("F1")} of settings, and transfer to datasets that share no source stays above chance ({v("H6")}). Source dependence is {v("F3")} ({pct("F3")} of settings) and the false-alarm gap on naturally browsed legitimate pages is {v("OOD")} ({pct("OOD")}). The first study's claims about where the drop sits and about split variability are {v("F2")} and {v("F4")}; an extra check shows the first of these depends on how the benchmark was prepared. Platform masking could not be tested. The report states each result as a study of behaviour under one frozen design, not as a general claim."""

    ch1 = """# 1. Introduction

## 1.1 Motivation

Phishing sites steal passwords and payment details, and new ones appear every hour. Machine-learning detectors are an obvious defence, and many published ones report accuracy above 99% on a public dataset. A detector that reaches 99% on one dataset can still fail on the pages a person actually browses. The author's earlier report showed this: a model that scored an AUC of 0.9988 on a benchmark fell to 0.7297 when URLs were rewritten into one fixed form, and flagged every one of 11,895 ordinary legitimate pages it was shown.

## 1.2 Objectives

1. **Verify** whether the findings of the earlier report hold when they are re-implemented from scratch and repeated across many datasets and several model families (the PhishGuard study).
2. **Build** a practical detector, evaluated only under protocols that guard against those failures, and ship it as a working Chrome extension with a backend (PhishDrift).
3. **Report** every number from a script that writes to `reports/`, with fixed seeds, and say plainly where a result is measured, inferred or not tested.

## 1.3 What is new

A plain "classifier on a static phishing dataset" was done in earlier semesters. Novelty here is in the protocol: domain-grouped splits repeated ten times, leave-one-source-out and out-of-distribution false-alarm reporting, negative controls with shuffled labels, URL-depth checks, and tiered models whose missing inputs never reveal the data source; then a deployed, explainable system built on that protocol.

## 1.4 Scope and structure

Chapter 2 gives the background and the questions. Chapters 3 and 4 are the PhishGuard study. Chapters 5 to 9 describe PhishDrift: data, features and models, the extension and backend, the evaluation, and the limitations. Chapter 10 concludes. The study is the priority part of the project; PhishDrift is the software deliverable. Results from one are never used as evidence for the other.
"""

    ch2 = f"""# 2. Background and questions

## 2.1 The earlier report

The author's earlier report (v1.1.1, 2026-09-10, "Representation Sensitivity and Cross-Source Generalization in Phishing URL Detection") studied one benchmark family with mostly one model and one split per setting. Its code and result files were later lost, so this project re-implements the study on the PhishDrift tooling. The findings carried forward are in Section 2.2.

## 2.2 Questions asked

{body(g["2"])}

## 2.3 Related datasets and tools

The study and the detector draw on public datasets (PhreshPhish, PhiUSIIL, URL-Phish, PhishStorm, Phishpedia, Phish-Blitz) and live feeds (OpenPhish, Phishing.Database). Only the URL, label, date and page HTML are read from any of them; no dataset's precomputed feature columns are used, because one such column (a similarity index) alone identifies PhiUSIIL's legitimate class. Features follow the published definitions of Hannousse and Yahiouche and of PhiUSIIL, re-implemented in one engine. Models are LightGBM, XGBoost, logistic regression and a character n-gram TF-IDF linear model.
"""

    ch3 = "# 3. PhishGuard: design and method\n\n" + re.sub(
        r"^## 3\.", "## 3.", body(g["3"]), flags=re.M
    )

    ch4_parts = [
        "# 4. PhishGuard: results\n",
        body(g["4"]),
        "\n## 4.10 Reproduction of the first study\n\n" + body(g["5"]),
        "\n## 4.11 Follow-up checks\n\n" + body(g["6"]),
        "\n## 4.12 Part B: page HTML (exploratory)\n\n" + body(g["7"]),
        "\n## 4.13 Limitations of the study\n\n" + body(g["8"]),
        "\n## 4.14 What can and cannot be claimed\n\n" + body(g["9"]),
    ]
    ch4 = "\n".join(ch4_parts)
    ch4 = re.sub(r"\(Section 7\)", "(Section 4.12)", ch4)
    ch4 = re.sub(r"Section 6\b", "Section 4.11", ch4)
    ch2 = re.sub(r"(Figure|Table) (\d+)\b", r"\1 4.\2", ch2)
    ch3 = re.sub(r"(Figure|Table) (\d+)\b", r"\1 4.\2", ch3)
    ch4 = re.sub(r"(Figure|Table) (\d+)\b", r"\1 4.\2", ch4)

    drift_txt = (
        drift.read_text(encoding="utf-8")
        if drift.exists()
        else "# 5. PhishDrift (chapters pending)\n"
    )

    ch10 = f"""# 10. Conclusion and future work

## 10.1 What was achieved

- **A verification study.** The earlier report's central finding, that a URL model's score depends heavily on URL form, is {v("F1")} across 25 source cells, four model families and ten splits. Transfer to independent datasets stays above chance ({v("H6")}). Source dependence is {v("F3")} and the natural-page false-alarm gap is {v("OOD")}. The claims about where the drop sits and about split variability did not repeat in this design, and an extra check traced the first to the way the raw benchmark was prepared.
- **A working detector.** PhishDrift runs as a Chrome extension with a FastAPI backend and layered checks (allowlist, blocklist, URL model, page model, domain checks), evaluated with recall at fixed false-alarm rates, a held-out source, a newest time slice and natural-page false alarms (Chapter 8).
- **A reproducible record.** Every reported number comes from a script in the repository that writes to `reports/`; seeds are fixed; the study's plan and replication rule were frozen before the run.

## 10.2 Limitations

See Sections 4.13 and Chapter 9. In short: public benchmarks only, two of them old or homepage-heavy; the HTML part rests on two sources with uneven coverage; one shuffled-label control is flagged; platform masking is untested; PhishDrift's tier C rests on a small live capture; and the extension has been checked in test harnesses and on stored pages, not in a long field trial.

## 10.3 Future work

1. Add PhishTank and further live-feed sources to the study, and re-run it with hosting-platform domains kept so platform masking can be tested.
2. Test the benchmark-construction explanation for the host-share finding on more datasets.
3. Add a held-out source that has page HTML, so the page model's gain can be measured out of source.
4. Grow the tier C capture over more days, and measure blocklist coverage forward in time.
5. Optional second-opinion layer for the grey zone (planned, not built).

# References

1. R. Gangwar, *Representation Sensitivity and Cross-Source Generalization in Phishing URL Detection*, technical report v1.1.1, 2026-09-10.
2. A. Hannousse and S. Yahiouche, "Towards benchmark datasets for machine learning based website phishing detection", *Engineering Applications of Artificial Intelligence*, 2021.
3. A. Prasad and S. Chandra, "PhiUSIIL: a diverse security profile empowered phishing URL detection framework based on similarity index and incremental learning", *Computers & Security*, 2024.
4. PhreshPhish dataset, Hugging Face `phreshphish/phreshphish`.
5. URL-Phish dataset (Mendeley Data); PhishStorm dataset (Aalto University); Phish-Blitz and Phishpedia datasets as released by their authors.
6. G. Ke et al., "LightGBM: a highly efficient gradient boosting decision tree", *NeurIPS*, 2017.
7. T. Chen and C. Guestrin, "XGBoost: a scalable tree boosting system", *KDD*, 2016.
8. V. Le Pochat et al., "Tranco: a research-oriented top sites ranking hardened against manipulation", *NDSS*, 2019.
9. OpenPhish community feed; Phishing.Database (MIT licence); Google Safe Browsing Update API.

*Citation details should be checked against the originals before submission.*
"""

    title = """---
title: "PhishGuard and PhishDrift: Verifying Representation Sensitivity in Phishing-URL Detection and Building an Explainable Chrome-Extension Detector"
subtitle: "Project-Based Learning (PBL) final report, 6th semester"
author: "Ritvik Gangwar"
date: "October 2026"
---

"""
    heads = [
        ln[2:].strip()
        for ln in (ch1 + ch2 + ch3 + ch4 + drift_txt + ch10).splitlines()
        if ln.startswith("# ")
    ]
    contents = "# Contents\n\n" + "\n".join(f"- {h}" for h in heads) + "\n\n"
    text = (
        title
        + contents
        + "# Abstract\n\n"
        + abstract
        + "\n\n"
        + ch1
        + "\n"
        + ch2
        + "\n"
        + ch3
        + "\n"
        + ch4
        + "\n"
        + drift_txt
        + "\n"
        + ch10
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
