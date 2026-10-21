# Uncleaned-data condition for Q2, Q4 and the interaction check

Declared in `docs/PHISHGUARD_SENSITIVITY_PLAN.md` before the run. Same cells, models, splits and cut-offs in both columns; the only difference is whether the populations were cleaned (per-domain cap, shared-domain removal, depth balancing).
Cells compared: 20 (phishpedia__phishstorm, phishpedia__phiusiil, phishpedia__phreshphish, phishpedia__urlphish, phishstorm__phishstorm, phishstorm__phiusiil, phishstorm__phreshphish, phishstorm__urlphish, phiusiil__phishstorm, phiusiil__phiusiil, phiusiil__phreshphish, phiusiil__urlphish, phreshphish__phishstorm, phreshphish__phiusiil, phreshphish__phreshphish, phreshphish__urlphish, urlphish__phishstorm, urlphish__phiusiil, urlphish__phreshphish, urlphish__urlphish).

| question | cleaned: settings | cleaned: hold | cleaned: share | cleaned: verdict | uncleaned: settings | uncleaned: hold | uncleaned: share | uncleaned: verdict |
|---|---|---|---|---|---|---|---|---|
| Q1 | 80 | 80 | 1.0 | replicated | 80 | 79 | 0.9875 | replicated |
| Q2 | 80 | 0 | 0.0 | not replicated | 80 | 0 | 0.0 | not replicated |
| Q3 | 280 | 232 | 0.8285714285714286 | replicated | 280 | 27 | 0.09642857142857143 | not replicated |
| Q4 | 80 | 31 | 0.3875 | not replicated | 80 | 55 | 0.6875 | partly replicated |
| interaction | 240 | 78 | 0.325 | not replicated | 240 | 0 | 0.0 | not replicated |
Median host-and-subdomain share of the R1 to R4 drop: cleaned 0.21, uncleaned 0.27.
Median SD across splits (R4 / R1): cleaned 0.006 / 0.002; uncleaned 0.032 / 0.006.

## Representation ladder, median ROC-AUC per cell

| cell | cleaned R1 | cleaned R2 | cleaned R4 | uncleaned R1 | uncleaned R2 | uncleaned R4 |
|---|---|---|---|---|---|---|
| phishpedia__phishstorm | 0.975 | 0.846 | 0.831 | 0.981 | 0.901 | 0.886 |
| phishpedia__phiusiil | 0.998 | 0.761 | 0.727 | 0.996 | 0.811 | 0.773 |
| phishpedia__phreshphish | 0.968 | 0.786 | 0.769 | 0.97 | 0.85 | 0.837 |
| phishpedia__urlphish | 0.993 | 0.885 | 0.872 | 0.994 | 0.909 | 0.893 |
| phishstorm__phishstorm | 0.972 | 0.837 | 0.798 | 0.968 | 0.861 | 0.821 |
| phishstorm__phiusiil | 0.995 | 0.784 | 0.725 | 0.995 | 0.808 | 0.742 |
| phishstorm__phreshphish | 0.978 | 0.815 | 0.776 | 0.976 | 0.838 | 0.801 |
| phishstorm__urlphish | 0.991 | 0.882 | 0.854 | 0.991 | 0.891 | 0.853 |
| phiusiil__phishstorm | 0.988 | 0.853 | 0.841 | 0.99 | 0.924 | 0.899 |
| phiusiil__phiusiil | 0.86 | 0.817 | 0.792 | 0.931 | 0.908 | 0.868 |
| phiusiil__phreshphish | 0.948 | 0.818 | 0.812 | 0.972 | 0.888 | 0.861 |
| phiusiil__urlphish | 0.923 | 0.906 | 0.895 | 0.959 | 0.947 | 0.927 |
| phreshphish__phishstorm | 0.983 | 0.929 | 0.907 | 0.985 | 0.941 | 0.905 |
| phreshphish__phiusiil | 0.958 | 0.906 | 0.86 | 0.984 | 0.949 | 0.885 |
| phreshphish__phreshphish | 0.955 | 0.892 | 0.87 | 0.956 | 0.897 | 0.852 |
| phreshphish__urlphish | 0.97 | 0.952 | 0.935 | 0.986 | 0.968 | 0.941 |
| urlphish__phishstorm | 0.977 | 0.934 | 0.923 | 0.97 | 0.896 | 0.829 |
| urlphish__phiusiil | 0.985 | 0.909 | 0.886 | 0.99 | 0.936 | 0.863 |
| urlphish__phreshphish | 0.967 | 0.911 | 0.903 | 0.955 | 0.818 | 0.737 |
| urlphish__urlphish | 0.98 | 0.946 | 0.939 | 0.983 | 0.953 | 0.906 |
