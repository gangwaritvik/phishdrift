# Platform masking (exploratory deviation from the frozen design)

Run on Ritvik's PC 2026-10-21 (copied from the pasted output). Settings: 10; masking raises held-out R4 AUC in 0 (0%); verdict: not replicated.
Platform rows kept per tenant host (at most 5 URLs); splits grouped by registrable domain; not part of the seven frozen questions.
Every cell uses the same legitimate population (PhreshPhish), so the cells are not independent.

| cell | model | splits | masked_auc | unmasked_auc | median_gain | ci_lo | ci_hi | splits_positive | holds |
|---|---|---|---|---|---|---|---|---|---|
| phishpedia__phreshphish | lightgbm | 10 | 0.7784 | 0.7879 | -0.0 | -0.0766 | 0.2041 | 5 | False |
| phishpedia__phreshphish | char_ngram | 10 | 0.7875 | 0.7988 | -0.0083 | -0.0686 | 0.3949 | 5 | False |
| phishstorm__phreshphish | lightgbm | 10 | 0.7993 | 0.8031 | -0.0076 | -0.0347 | 0.0235 | 2 | False |
| phishstorm__phreshphish | char_ngram | 10 | 0.8043 | 0.8194 | -0.0144 | -0.072 | 0.0035 | 0 | False |
| phiusiil__phreshphish | lightgbm | 10 | 0.8425 | 0.8207 | 0.012 | -0.0338 | 0.1235 | 9 | False |
| phiusiil__phreshphish | char_ngram | 10 | 0.8378 | 0.8384 | -0.0024 | -0.0438 | 0.0479 | 4 | False |
| phreshphish__phreshphish | lightgbm | 10 | 0.8864 | 0.8684 | 0.009 | -0.0304 | 0.0838 | 6 | False |
| phreshphish__phreshphish | char_ngram | 10 | 0.888 | 0.8878 | 0.0037 | -0.0314 | 0.0348 | 7 | False |
| urlphish__phreshphish | lightgbm | 10 | 0.8814 | 0.8729 | 0.0103 | -0.0269 | 0.079 | 6 | False |
| urlphish__phreshphish | char_ngram | 10 | 0.8941 | 0.8927 | -0.0042 | -0.0318 | 0.0525 | 4 | False |

Counts per source and class are in the `count` output (PhreshPhish legitimate: 1,019 platform URLs on 617 tenant hosts; the other legitimate sources are below the 500-URL bar).
