"""Domain-disjoint random split and time split.

Both assign whole registered domains (eTLD+1) to one side, so near-duplicate URLs on the
same site can never sit in both train and test.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

TRAIN, TEST = "train", "test"
DROPPED_UNDATED = "dropped_undated"
DROPPED_OVERLAP = "dropped_domain_overlap"


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
        n_take = int(np.searchsorted(np.cumsum(sizes), target, side="left")) + 1
        test_domains.extend(order[: min(n_take, len(order))] if target > 0 else [])
    return pd.Series(
        np.where(df["domain"].isin(set(test_domains)), TEST, TRAIN), index=df.index, name="split"
    )


def resolve_cutoff(df: pd.DataFrame, cutoff: str | None, quantile: float) -> pd.Timestamp:
    if cutoff:
        return pd.Timestamp(cutoff, tz="UTC")
    dated = df["date"].dropna()
    if dated.empty:
        raise ValueError("no dated rows: time split impossible")
    return dated.quantile(quantile)


def time_split(
    df: pd.DataFrame, cutoff: pd.Timestamp, drop_test_domains_seen_in_train: bool = True
) -> pd.Series:
    """Train = dated rows before ``cutoff``; test = rows on/after it. Undated rows are
    dropped. Test rows whose domain also appears in train are dropped so the test set is
    both later in time and domain-disjoint."""
    split = pd.Series(DROPPED_UNDATED, index=df.index, name="split", dtype=object)
    dated = df["date"].notna()
    split[dated & (df["date"] < cutoff)] = TRAIN
    split[dated & (df["date"] >= cutoff)] = TEST
    if drop_test_domains_seen_in_train:
        train_domains = set(df.loc[split == TRAIN, "domain"])
        split[(split == TEST) & df["domain"].isin(train_domains)] = DROPPED_OVERLAP
    return split


def assert_domain_disjoint(df: pd.DataFrame, split: pd.Series) -> None:
    overlap = set(df.loc[split == TRAIN, "domain"]) & set(df.loc[split == TEST, "domain"])
    if overlap:
        raise LeakageError(
            f"{len(overlap)} domains in both train and test, e.g. {sorted(overlap)[:5]}"
        )
