"""Domain-grouped splits.

Every split assigns whole registrable domains (U1, public-suffix-only) to one side, so
URLs of the same site, including every site on one hosting platform, never sit on both
sides. Overlap of domains or canonical URLs between sides is a hard failure (report §9).
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from phishdrift.domains import url_key

TRAIN, CAL, TEST = "train", "cal", "test"


class LeakageError(AssertionError):
    pass


def random_domain_split(df: pd.DataFrame, test_fraction: float, seed: int) -> pd.Series:
    """Assign each domain to train or test, stratified by the domain's majority label so
    class balance is similar on both sides. Returns a train/test Series aligned to ``df``."""
    rng = np.random.default_rng(seed)
    per_domain = df.groupby("domain")["label"].agg(["size", "mean"])
    per_domain["stratum"] = (per_domain["mean"] >= 0.5).astype(int)
    test_domains: list[str] = []
    for _, grp in per_domain.groupby("stratum", sort=True):
        order = grp.index.to_numpy()[rng.permutation(len(grp))]
        sizes = grp.loc[order, "size"].to_numpy()
        target = test_fraction * sizes.sum()
        if target <= 0:
            continue
        n_take = int(np.searchsorted(np.cumsum(sizes), target, side="left")) + 1
        test_domains.extend(order[: min(n_take, len(order))])
    return pd.Series(
        np.where(df["domain"].isin(set(test_domains)), TEST, TRAIN), index=df.index, name="split"
    )


def grouped_splits(
    df: pd.DataFrame, n_splits: int, test_fraction: float, cal_fraction: float, seed: int
) -> pd.DataFrame:
    """``n_splits`` domain-grouped train/cal/test assignments (columns split_0..split_{n-1}).
    Seeds vary the partition only. ``cal`` is a domain-grouped slice of the train side used
    for calibration and thresholds."""
    out = {}
    for k in range(n_splits):
        split = random_domain_split(df, test_fraction, seed + k)
        train = split == TRAIN
        cal = random_domain_split(df.loc[train], cal_fraction, seed + 1000 + k)
        split.loc[cal.index[cal == TEST]] = CAL
        assert_disjoint(df, split)
        out[f"split_{k}"] = split.to_numpy()
    return pd.DataFrame(out, index=df.index)


def assert_disjoint(
    df: pd.DataFrame, parts: pd.Series, names: tuple[str, ...] | None = None
) -> None:
    """Fail if any two parts share a registrable domain or a canonical URL."""
    names = names or tuple(sorted(pd.unique(parts)))
    keys = df["url"].map(url_key)
    for i, a in enumerate(names):
        for b in names[i + 1 :]:
            dom = set(df.loc[parts == a, "domain"]) & set(df.loc[parts == b, "domain"])
            if dom:
                raise LeakageError(
                    f"{len(dom)} domains in both {a!r} and {b!r}, e.g. {sorted(dom)[:5]}"
                )
            urls = set(keys[parts == a]) & set(keys[parts == b])
            if urls:
                raise LeakageError(f"{len(urls)} URLs in both {a!r} and {b!r}")
