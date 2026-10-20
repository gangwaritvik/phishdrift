---
title: "PhishGuard: Replicating Representation Sensitivity and Source Dependence in Phishing URL Detection Across Datasets and Models"
subtitle: "Verification study report, version 1.0 (draft for supervisor review)"
author: "Ritvik Gangwar"
date: "2026-10-20"
---

# 1. Executive summary

A first study (report v1.1.1, 2026-09-10) found that phishing-URL detectors scored on one benchmark change sharply when URLs are written in a different form, and that scores depend on which sources are used. Its code and result files were lost. This report asks whether those findings hold when they are re-implemented from scratch and repeated across **5 phishing sources, 5 legitimate sources, 4 model families and 10 domain-grouped splits** (25 cells, 1,000 fits per representation), with the rule for calling a finding *replicated* written down before the run (commit `082b058`).

**Results in one table.** Seven findings were tested; each counts as holding in a setting only if the direction repeats in at least 9 of 10 splits and the bootstrap interval excludes the null.

| finding | statement | settings tested | settings where it holds | verdict | share |
|--------|----------------------------------------|---------|-----------|--------------|---------|
| F1 | Representation sensitivity: AUC falls from R1 to R4 | 100 | 100 | Replicated | 100% |
| F2 | Most of the fall sits in host/subdomain structure (R3 to R4 share > 0.5) | 100 | 0 | Not replicated | 0% |
| F3 | Source dependence: swapping one population moves R4 AUC | 400 | 304 | Partly replicated | 76% |
| F3_depth | Source dependence survives depth reweighting | 400 | 211 | Partly replicated | 53% |
| H5 | A phishing x benign interaction is established (expected: inconclusive) | 400 | 105 | Not replicated | 26% |
| F4 | Split sensitivity: SD of R4 AUC > 3 x SD of R1 AUC | 100 | 45 | Not replicated | 45% |
| HP | Masking hosting-platform identity raises R4 AUC | 0 | 0 | Not testable | n/a |
| H6 | Transfer to fully independent cells stays above chance (R4) | 392 | 392 | Replicated | 100% |
| OOD | False alarms on natural legitimate pages > 5 x the in-cell rate | 100 | 76 | Partly replicated | 76% |


**What this supports.** The central finding, that a URL model's score drops when the URL is reduced to its domain, is replicated in every setting (median R1 0.977 to R4 0.850). Transfer to cells that share no source stays above chance. Source dependence and the out-of-distribution false-alarm gap hold in part. Two findings from the first study do not carry over here: the split of the drop between host and path (F2) and the size of split-to-split variability (F4). One could not be tested (HP).

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

| Part | Population | URLs | domains |
|---|---|---|---|
| A | benign:crawl | 4964 | 1204 |
| A | benign:phishstorm | 10000 | 7753 |
| A | benign:phiusiil | 10000 | 9996 |
| A | benign:phreshphish | 10000 | 9475 |
| A | benign:urlphish | 10000 | 9773 |
| A | phish:phishpedia | 8578 | 5897 |
| A | phish:phishstorm | 10000 | 7154 |
| A | phish:phiusiil | 10000 | 9149 |
| A | phish:phreshphish | 10000 | 8174 |
| A | phish:urlphish | 4307 | 3590 |
| B | benign:crawl | 4826 | 1177 |
| B | benign:phreshphish | 10000 | 9491 |
| B | phish:phishpedia | 3937 | 2980 |
| B | phish:phreshphish | 10000 | 7371 |


## 3.2 Representations

R1 is the raw URL. R2 keeps the host only (path, query and fragment removed). R3 additionally strips `www`; here R3 is identical to R2 because the feature engine drops a leading `www` from every URL, so the `www` step is zero by construction. R4 is `https://www.<registrable domain>`.

## 3.3 Models and splits

LightGBM, XGBoost, logistic regression on the 99 URL features, and character n-gram TF-IDF with logistic regression. Ten splits per cell are grouped by registrable domain (train 70%, calibration 10%, test 20%; a deterministic hash of seed, split and domain). Fitted features (TLD risk, bigram likelihood) are refitted on each split's training side. Uncertainty comes from a domain-cluster bootstrap with 200 draws per split. Transfer is tested only on cells sharing no source with the training cell.

![Figure 1. Study design. Seven findings are tested across 25 source cells, four models, four URL forms and ten splits.](fig01_design.png)

## 3.4 The rule for calling a finding replicated

A setting (one cell and model, or one pair of cells) *holds* when the direction is the same in at least 9 of 10 splits and the pooled bootstrap 95% interval excludes the null. A finding is **replicated** if it holds in at least 80% of its testable settings, **partly replicated** at 50 to 80%, and **not replicated** below 50%; with fewer than 3 testable settings it is **not testable**. A setting is testable with at least 500 URLs and 100 domains per class. The rule and `configs/phishguard.yaml` were frozen at commit `082b058` before any result was seen.

# 4. Results

## 4.1 F1: representation sensitivity (replicated)

AUC falls from R1 to R4 in all 100 model-cell settings. The median R1 AUC is 0.977, R2/R3 0.877 and R4 0.850; the smallest drop in any setting is 0.024. All four model families show it (Figure 3), including the character n-gram model that held up best in the first study.

![Figure 2. Representation ladder, 25 cells. Thin lines are cells; the thick line is the median.](fig02_ladder.png)

![Figure 3. Median AUC by representation and model, with the range across the 25 cells.](fig03_models.png)

**Table 2.** Mean AUC over the four models, by cell.

| phishing vs legitimate | R1 | R2 (= R3) | R4 |
|---|---|---|---|
| phishpedia vs crawl | 0.972 | 0.764 | 0.730 |
| phishpedia vs phishstorm | 0.975 | 0.846 | 0.831 |
| phishpedia vs phiusiil | 0.998 | 0.761 | 0.727 |
| phishpedia vs phreshphish | 0.968 | 0.786 | 0.769 |
| phishpedia vs urlphish | 0.993 | 0.885 | 0.872 |
| phishstorm vs crawl | 0.980 | 0.773 | 0.712 |
| phishstorm vs phishstorm | 0.972 | 0.837 | 0.798 |
| phishstorm vs phiusiil | 0.995 | 0.784 | 0.725 |
| phishstorm vs phreshphish | 0.978 | 0.815 | 0.776 |
| phishstorm vs urlphish | 0.991 | 0.882 | 0.854 |
| phiusiil vs crawl | 0.983 | 0.802 | 0.775 |
| phiusiil vs phishstorm | 0.988 | 0.853 | 0.841 |
| phiusiil vs phiusiil | 0.860 | 0.817 | 0.792 |
| phiusiil vs phreshphish | 0.948 | 0.818 | 0.812 |
| phiusiil vs urlphish | 0.923 | 0.906 | 0.895 |
| phreshphish vs crawl | 0.976 | 0.900 | 0.858 |
| phreshphish vs phishstorm | 0.983 | 0.929 | 0.907 |
| phreshphish vs phiusiil | 0.958 | 0.906 | 0.860 |
| phreshphish vs phreshphish | 0.955 | 0.892 | 0.870 |
| phreshphish vs urlphish | 0.970 | 0.952 | 0.935 |
| urlphish vs crawl | 0.974 | 0.904 | 0.887 |
| urlphish vs phishstorm | 0.977 | 0.934 | 0.923 |
| urlphish vs phiusiil | 0.985 | 0.909 | 0.886 |
| urlphish vs phreshphish | 0.967 | 0.911 | 0.903 |
| urlphish vs urlphish | 0.980 | 0.946 | 0.939 |


## 4.2 F2: where the drop sits (not replicated)

The first study put most of the R1 to R4 drop in the host and subdomain (share 0.870 in cell A, 0.563 in cell C). Here the host and subdomain step (R2 to R4) carries a median share of 0.21; the larger part comes from removing path and query (R1 to R2). The statement "most of the fall sits in host structure" holds in 0 of 100 settings. This run uses 99 features rather than 38, balances depth, and caps URLs per domain, all of which can change where the information sits; the main report does not choose among those explanations.

**Exploratory follow-up (not part of the frozen verdict).** Re-running PhiUSIIL alone with one cleaning step added at a time (Section 6) shows the host share of the drop depends on how the data was prepared. On raw PhiUSIIL through our loader the host step carries 0.76 of the drop for XGBoost and 0.42 for the character model; on the study cell, after the shared-domain removal, depth balancing and caps, it carries 0.36 and 0.21. The first study's pattern is therefore visible again on the raw benchmark for XGBoost, and it fades as the benchmark is cleaned. That is consistent with the F2 pattern being tied to how the raw benchmark was built, but it is one dataset and two models, so it is stated as a lead, not a conclusion.

**Table 2b.** Host and subdomain share of the R1 to R4 drop, PhiUSIIL alone, by cleaning stage (5 splits).

| PhiUSIIL cleaning stage | Char n-gram host share | XGBoost host share |
|---|---|---|
| S0 raw PhiUSIIL | 0.416 | 0.762 |
| S0b raw, sampled to 10,000 per class | 0.300 | 0.722 |
| S1 + domains shared with other sources removed | 0.305 | 0.514 |
| S2 + pool URL rules | 0.271 | 0.446 |
| S3 + study caps (5 per domain, 10,000 per class) = study cell | 0.212 | 0.359 |


![Figure 4. Share of the R1 to R4 drop by step, LightGBM, per cell.](fig04_share.png)

## 4.3 F3: source dependence (partly replicated)

Swapping one source while holding the other fixed moves R4 AUC by a median 0.058 (phishing source swapped 0.050, legitimate source swapped 0.067). The interval excludes zero in 76% of 400 swaps. After reweighting the test side to equalise URL depth across classes it falls to 53%, so part of the source effect is URL depth. The heatmap shows the pattern: R4 AUC ranges from 0.71 to 0.94; against URL-Phish legitimate URLs every phishing source scores highest (0.85 to 0.94), and the lowest cells pair PhishStorm, PhiUSIIL or Phishpedia phishing with PhiUSIIL or crawled legitimate URLs.

![Figure 5. R4 AUC for every phishing-by-legitimate cell (left) and the distribution of swap effects (right).](fig05_source.png)

H5, an interaction between phishing and legitimate source, holds in 26% of settings; the first study also called it inconclusive, so a "not replicated" verdict here is the expected outcome.

## 4.4 F4: split sensitivity (not replicated)

The first study saw R4 AUC vary far more across splits than raw AUC (SD up to 0.1164 against at most 0.0026). Here the median SD is 0.006 for R4 and 0.002 for R1, and the largest R4 SD is 0.019. R4 is the more variable in 100% of settings, but exceeds three times the raw SD in only 45% of them. With 5 to 10 thousand URLs per cell and domain-grouped splits the variability is smaller than in a single 10-split study on one benchmark.

![Figure 6. SD of AUC across ten splits, raw against R4, one point per cell and model.](fig06_split.png)

## 4.5 HP: platform masking (not testable)

Masking replaces hosting-platform domains with a neutral token. The caps used here leave no registrable domain on a hosting platform in any cell, so there is nothing to mask and the finding cannot be tested. A design that keeps platform domains is future work.

## 4.6 H6: independent-benign transfer (replicated)

Models trained on one cell and evaluated on cells that share no source with it keep an R4 AUC above 0.5 in every setting (median 0.699, lowest 0.554; 392 train-test pairs across the two transfer models). The first study's 0.694 and 0.706 rested on 119 benign domains; the pairs here each use thousands.

![Figure 7. Transfer AUC on fully independent cells.](fig07_transfer.png)

## 4.7 OOD: naturally browsed legitimate pages (partly replicated)

A model's false-alarm rate on 2,555 natural legitimate pages from 562 sites, none in any training source, is compared with its own test side at the same 1% threshold. The median is 15.2% on natural pages against 1.0% in-cell; at the 0.1% threshold 4.5%; at the default 0.5 threshold 33%. The natural rate exceeds five times the in-cell rate in 76% of settings. The first study's reversal (1.0 on natural pages for the raw model) is not reproduced in this setting, but a benchmark threshold still understates real-world false alarms.

![Figure 8. False alarms on natural pages against the cell's own test side, log scale.](fig08_ood.png)

## 4.8 Negative controls

With shuffled training labels, mean AUC stays between 0.448 and 0.525 over 100 conditions (cell, representation, model); 1 is flagged under the |mean - 0.5| > 0.05 rule. The flagged condition is examined in Section 6.

![Figure 9. Shuffled-label controls, 100 conditions.](fig09_controls.png)

## 4.9 Dataset fingerprints

A model can tell which source a URL came from even within one class, which is the mechanism behind source dependence. The table gives balanced accuracy for predicting the source of legitimate and phishing URLs (chance 0.20 for URLs and 0.50 for page HTML). It falls when URLs are reduced to R4 but stays well above chance.

**Table 3.** Source identification within one class (5 domain folds).

| part | class | input | balanced_accuracy | chance | n |
|---|---|---|---|---|---|
| A | benign | R1 | 0.621 | 0.200 | 44964 |
| A | benign | R4 | 0.315 | 0.200 | 44964 |
| A | phishing | R1 | 0.672 | 0.200 | 42885 |
| A | phishing | R4 | 0.414 | 0.200 | 42885 |
| B | benign | P1 | 0.820 | 0.500 | 14826 |
| B | phishing | P1 | 0.935 | 0.500 | 13937 |


# 5. Reproduction of the first study

The first study's raw PhiUSIIL cell scored AUC 0.999 (XGBoost); this run scores 0.864 on the study cell (Table 4).

**Table 4.** Published against reproduced AUC (XGBoost, median over splits).

| cell | rep | published | now | gap |
|---|---|---|---|---|
| phiusiil vs phiusiil | R1 | 0.999 | 0.864 | -0.135 |
| phiusiil vs phiusiil | R2 | 0.992 | 0.820 | -0.173 |
| phiusiil vs phiusiil | R3 | 0.964 | 0.820 | -0.144 |
| phiusiil vs phiusiil | R4 | 0.730 | 0.791 | 0.061 |
| phiusiil vs crawl | R1 | 0.999 | 0.986 | -0.012 |
| phiusiil vs crawl | R2 | 0.987 | 0.810 | -0.177 |
| phiusiil vs crawl | R3 | 0.972 | 0.810 | -0.161 |
| phiusiil vs crawl | R4 | 0.679 | 0.775 | 0.096 |


# 6. Follow-up checks

**Why the PhiUSIIL cell scores lower than published.** PhiUSIIL was re-run alone, adding one cleaning step at a time (5 splits). Raw PhiUSIIL through our loader already scores about 0.94 (XGBoost); sampling to 10,000 per class, removing domains shared with other phishing sources, the pool rules and the study caps take it to 0.867. The cleaning explains about 0.07 of the gap; about 0.06 is gone before any cleaning, most likely because URLs are standardised on loading (inferred, not tested, as the original strings were lost). R4 stays between 0.79 and 0.85 at every stage against 0.730 published.

**The flagged shuffled-label control.** In the URL-Phish phishing against PhiUSIIL legitimate cell, LightGBM trained on shuffled labels scores below chance at every seed: mean 0.449 (SD 0.031, 50 runs); the character n-gram model scores 0.506. A leak raises a control above 0.5, so this is read as a model artefact in one cell and listed as a limitation.

![Figure 10. Left: XGBoost AUC from raw PhiUSIIL to the study cell. Right: the flagged control.](fig12_followup.png)

# 7. Part B: page HTML (exploratory)

Four cells (Phishpedia or PhreshPhish phishing against PhreshPhish or crawled legitimate pages) use the 84 page features, grouped into P1 (all), P2 (scripts and structure removed), P3 (forms and text) and P4 (forms only). **Part B gives no verdicts.**

**Table 5.** Page and URL ROC-AUC, median of 10 splits.

| cell | P1 | P1+R1 | P1+R4 | P2 | P3 | P4 | R1 | R4 |
|---|---|---|---|---|---|---|---|---|
| phishpedia vs crawl | 0.997 | 0.999 | 0.998 | 0.997 | 0.992 | 0.903 | 0.966 | 0.740 |
| phishpedia vs phreshphish | 0.996 | 0.997 | 0.996 | 0.994 | 0.987 | 0.890 | 0.963 | 0.754 |
| phreshphish vs crawl | 0.988 | 0.996 | 0.987 | 0.982 | 0.955 | 0.837 | 0.981 | 0.857 |
| phreshphish vs phreshphish | 0.978 | 0.990 | 0.982 | 0.974 | 0.947 | 0.837 | 0.963 | 0.866 |


- **Page features do not show the URL drop.** P1 scores 0.978 to 0.997 where the R4 URL alone scores 0.740 to 0.866. Forms only (P4) still reaches 0.837 to 0.903.
- **Transfer is uneven.** A Phishpedia-vs-crawl model scores 0.687 on PhreshPhish cells (0.808 with the R4 URL added); the reverse direction scores 0.937.
- **Coverage is uneven.** Usable HTML exists for 91% of PhreshPhish benign rows but 63% of phishing rows; in PhreshPhish, *missing HTML alone* predicts phishing with ROC-AUC 0.639. Page numbers may therefore be optimistic.

![Figure 11. Page and URL representations, LightGBM.](fig10_pageb.png)

![Figure 12. Share of rows with usable HTML, by source and class.](fig11_html_coverage.png)

**Table 6.** False alarms on 2,226 natural legitimate pages with HTML.

| cell | rep | n | fpr_0p5 | fpr_0.01 | fpr_0.001 |
|---|---|---|---|---|---|
| phishpedia vs crawl | P1 | 2226 | 0.032 | 0.020 | 0.007 |
| phishpedia vs crawl | P1+R1 | 2226 | 0.027 | 0.016 | 0.003 |
| phishpedia vs phreshphish | P1 | 2226 | 0.027 | 0.023 | 0.004 |
| phishpedia vs phreshphish | P1+R1 | 2226 | 0.059 | 0.062 | 0.009 |
| phreshphish vs crawl | P1 | 2226 | 0.268 | 0.050 | 0.022 |
| phreshphish vs crawl | P1+R1 | 2226 | 0.125 | 0.040 | 0.010 |
| phreshphish vs phreshphish | P1 | 2226 | 0.201 | 0.061 | 0.010 |
| phreshphish vs phreshphish | P1+R1 | 2226 | 0.193 | 0.102 | 0.043 |


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

| Finding | First study | This run | Verdict | How to word it |
|--------------|------------------------|----------------------------------|-----------|------------------------------|
| F1 Representation sensitivity | cell A raw 0.9988 to R4 0.7297; all cells R4 0.63-0.86 | R1 0.977 to R4 0.850 (median of cells and models); falls in every one of 100 model-cell settings | Replicated | A direct finding, across five phishing sets, five legitimate sets and four model families. |
| F2 Where the drop sits | R1-R4 drop share in host/subdomain 0.870 (cell A), 0.563 (cell C) | median host/subdomain share 0.21 on the study cells; on raw PhiUSIIL alone 0.76 (XGBoost), falling to 0.36 after cleaning | Not replicated | Say the host/subdomain share depends on how the benchmark is prepared: it is high on the raw benchmark and low on cleaned pools. |
| F3 Source dependence | swapping the phishing source moves R4 by 0.13-0.16 | swapping one source moves R4 AUC by a median 0.058; CI excludes 0 in 76% of settings, 53% after depth reweighting | Partly replicated | Real in some pairs, absent in others; reweighting for depth halves it. |
| F4 Split sensitivity | R4 SD across 10 splits up to 0.1164 against at most 0.0026 for raw | median SD 0.006 (R4) against 0.002 (R1); larger than 3x in 45% of settings, largest 0.019 | Not replicated | Split variability matters but the 3x margin is not general. |
| HP Platform masking | masking raised held-out R4 AUC in 60 of 60 pairs | no hosting-platform domains remain after the 5-per-domain cap | Not testable | Leave to a design that keeps platform domains. |
| H6 Independent transfer | R4 0.694 and 0.706, on 119 benign domains | R4 AUC 0.699 median, lowest 0.554, above 0.5 in every setting | Replicated | Transfer stays above chance; the size varies. |
| OOD Natural pages | raw model 1.0 on natural legitimate pages against 0.00026 on the benchmark; normalised 0.090 | 15.2% flagged on natural pages at the cell's 1% threshold against 1.0% in-cell; 33% at the 0.5 threshold | Partly replicated | Benchmark thresholds understate false alarms on natural pages. |


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
