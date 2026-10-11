"""Source-leakage check on the tier A feature table.

For every feature: mean per class and per source, and eta^2 of the feature explained by the source
and by the label. A feature whose source eta^2 clearly exceeds its label eta^2 is flagged: it
identifies the dataset better than the class. Writes reports/tables/feature_source_check.csv.
"""

from __future__ import annotations

import argparse
from pathlib import Path

import numpy as np
import pandas as pd

FLAG_RATIO = 2.0  # flag when eta2_source > FLAG_RATIO * eta2_label ...
FLAG_MIN = 0.05  # ... and eta2_source is at least this


def eta_squared(values: pd.Series, groups: pd.Series) -> float:
    v = values.to_numpy(dtype=float)
    ok = ~np.isnan(v)
    v, g = v[ok], groups.to_numpy()[ok]
    total = ((v - v.mean()) ** 2).sum() if len(v) else 0.0
    if total == 0:
        return 0.0
    between = sum((g == k).sum() * (v[g == k].mean() - v.mean()) ** 2 for k in np.unique(g))
    return float(between / total)


def run(processed: Path, out: Path) -> pd.DataFrame:
    feats = pd.read_parquet(processed / "features_a.parquet")
    meta = pd.read_parquet(processed / "pool.parquet", columns=["uid", "label", "source"])
    df = feats.merge(meta, on="uid")
    rows = []
    for name in [c for c in feats.columns if c != "uid"]:
        es, el = eta_squared(df[name], df["source"]), eta_squared(df[name], df["label"])
        rows.append(
            {
                "feature": name,
                "nan_rate": df[name].isna().mean(),
                "mean_benign": df.loc[df.label == 0, name].mean(),
                "mean_phishing": df.loc[df.label == 1, name].mean(),
                "eta2_label": el,
                "eta2_source": es,
                "flag": es >= FLAG_MIN and es > FLAG_RATIO * el,
            }
        )
    res = pd.DataFrame(rows).sort_values("eta2_source", ascending=False)
    out.parent.mkdir(parents=True, exist_ok=True)
    res.to_csv(out, index=False)
    print(f"{int(res['flag'].sum())} of {len(res)} features flagged -> {out}")
    return res


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--out", type=Path, default=Path("reports/tables/feature_source_check.csv"))
    a = ap.parse_args()
    run(a.processed, a.out)
