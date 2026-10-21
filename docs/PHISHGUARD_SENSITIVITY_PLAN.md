# Study of data preparation: second condition for Q2, Q4 and the interaction check

Written and committed before any run of this condition. Nothing below was chosen after seeing its results.

## Why

In the frozen study (`configs/phishguard.yaml`, commit `082b058`) Q2 (most of the fall sits in the host name), Q4 (R4 AUC far less
stable across splits than raw AUC) and the phishing-by-legitimate interaction check did not hold. The frozen populations are cleaned:
at most 5 URLs per registrable domain, domains shared by several phishing sources removed, depth balancing and near-duplicate HTML
removal in the pool. The follow-up on PhiUSIIL alone (`reports/phishguard/tables/reproduce.csv`) suggests the host share depends on
this cleaning. This second condition asks the question directly: **do these three results change when the populations are built
without the cleaning?** It is a study of data preparation, not a retry. The frozen verdicts stay as they are; both conditions are
reported side by side, and whatever holds in only one condition is reported as exactly that.

## Condition B ("uncleaned"), declared in advance

- Sources: the per-source interim files (`data/interim/<source>.parquet`), reading only URL, domain and label.
- Populations: phishing and legitimate URLs of PhreshPhish, PhiUSIIL, URL-Phish, PhishStorm and Phishpedia (phishing only), as in the
  frozen study, except the crawled inner-page population, which cannot be rebuilt from the interim files and is left out.
  Cells: every phishing source against every legitimate source in {phreshphish, phiusiil, urlphish, phishstorm}.
- Not applied: the cap on URLs per registrable domain, the removal of domains shared by several phishing sources, depth balancing.
  Still applied: removal of exact duplicate URLs and of URLs labelled both ways (label integrity), a random sample of at most
  10,000 URLs per class and population (same size cap as the frozen study), seed 42.
- Unchanged: the 99-feature engine, the representations R1 to R4, the four model families, 10 splits grouped by registrable domain,
  the bootstrap, the "holds" rule (same direction in at least 9 of 10 splits and a 95% interval that excludes the null), the
  testability rule, the cut-offs (replicated at 80% or more of settings, partly at 50 to 80%, not replicated below 50%, not
  testable with fewer than 3 settings), and the finding definitions (Q2 share above 0.5, Q4 SD ratio above 3, interaction
  established).
- Questions answered: Q2, Q4 and the interaction check. Q1 and Q3 are computed as context and are not part of the claim. Not rerun:
  transfer, natural pages, shuffled-label controls (they do not enter these three questions).
- The original report's 38-feature set is not available, so it cannot be restored; this is a limit of the comparison, not a
  choice.

## Reporting rule

1. Condition A (frozen, restricted to the same 20 cells so the comparison is like for like) and condition B are shown side by side
   for Q2, Q4 and the interaction check: settings tested, settings that hold, share and verdict.
2. If a result holds in B but not in A, the report says: it holds only without the cleaning, and what that means for data
   preparation. If it holds in neither, it says so. No cut-off, definition or model is changed after the results are seen.
3. Condition B does not replace the frozen verdicts.
