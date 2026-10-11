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

FLAG_RATIO = 2.0  # flag when eta2_source_within > FLAG_RATIO * eta2_label ...
FLAG_MIN = 0.05  # ... and eta2_source_within is at least this
MIN_SOURCE_ROWS = (
    200  # a source needs this many rows in a class to take part in the within-class test
)


def eta_squared(values: pd.Series, groups: pd.Series) -> float:
    v = values.to_numpy(dtype=float)
    ok = ~np.isnan(v)
    v, g = v[ok], groups.to_numpy()[ok]
    total = ((v - v.mean()) ** 2).sum() if len(v) else 0.0
    if total == 0:
        return 0.0
    between = sum((g == k).sum() * (v[g == k].mean() - v.mean()) ** 2 for k in np.unique(g))
    return float(between / total)


def eta_squared_within_class(df: pd.DataFrame, name: str) -> float:
    """Variance share explained by the source inside each class, weighted by class size.

    The plain source eta2 mixes in the label whenever sources have different class mixes
    (one source mostly benign, another mostly phishing). Inside one class only dataset
    style can separate the sources, which is the shortcut a model could learn.
    """
    total, weight = 0.0, 0
    for _, part in df.groupby("label"):
        counts = part["source"].value_counts()
        part = part[part["source"].isin(counts[counts >= MIN_SOURCE_ROWS].index)]
        if part["source"].nunique() < 2:
            continue
        total += eta_squared(part[name], part["source"]) * len(part)
        weight += len(part)
    return total / weight if weight else float("nan")


def run(processed: Path, out: Path) -> pd.DataFrame:
    feats = pd.read_parquet(processed / "features_a.parquet")
    meta = pd.read_parquet(processed / "pool.parquet", columns=["uid", "label", "source"])
    df = feats.merge(meta, on="uid")
    rows = []
    for name in [c for c in feats.columns if c != "uid"]:
        es, el = eta_squared(df[name], df["source"]), eta_squared(df[name], df["label"])
        ew = eta_squared_within_class(df, name)
        rows.append(
            {
                "feature": name,
                "nan_rate": df[name].isna().mean(),
                "mean_benign": df.loc[df.label == 0, name].mean(),
                "mean_phishing": df.loc[df.label == 1, name].mean(),
                "eta2_label": el,
                "eta2_source": es,
                "eta2_source_within": ew,
                "flag": ew >= FLAG_MIN and ew > FLAG_RATIO * el,
            }
        )
    res = pd.DataFrame(rows).sort_values("eta2_source_within", ascending=False)
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
