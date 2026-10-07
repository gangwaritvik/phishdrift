import numpy as np
import pandas as pd
import pytest

from data_pipeline.split import (
    CAL,
    TEST,
    TRAIN,
    LeakageError,
    assert_disjoint,
    grouped_splits,
    random_domain_split,
)
from phishdrift.schema import to_schema


def synthetic(n_domains: int = 300, seed: int = 0) -> pd.DataFrame:
    """Several URLs per domain (subdomains + paths), including many sites on one platform."""
    rng = np.random.default_rng(seed)
    urls, labels = [], []
    for d in range(n_domains):
        label = int(rng.random() < 0.4)
        tld = "xyz" if label else "com"
        for k in range(int(rng.integers(1, 8))):
            urls.append(f"https://sub{k}.site{d}.{tld}/page/{k}?id={rng.integers(1e6)}")
            labels.append(label)
    for i in range(30):  # 30 different sites, one U1 domain
        urls.append(f"https://shop{i}.web.app/login")
        labels.append(1)
    return to_schema(pd.Series(urls), pd.Series(labels), "synthetic")


@pytest.mark.parametrize("seed", [0, 1, 2, 3])
def test_random_split_is_domain_disjoint_and_stratified(seed):
    df = synthetic(seed=seed)
    split = random_domain_split(df, 0.2, seed=seed)
    assert_disjoint(df, split)
    assert 0.15 < (split == TEST).mean() < 0.27
    p_train = df.loc[split == TRAIN, "label"].mean()
    p_test = df.loc[split == TEST, "label"].mean()
    assert abs(p_train - p_test) < 0.12


def test_platform_sites_stay_on_one_side():
    df = synthetic()
    for k in range(5):
        split = random_domain_split(df, 0.2, seed=k)
        assert split[df["domain"] == "web.app"].nunique() == 1


def test_ten_grouped_splits():
    df = synthetic()
    splits = grouped_splits(df, n_splits=10, test_fraction=0.2, cal_fraction=0.1, seed=0)
    assert list(splits.columns) == [f"split_{k}" for k in range(10)]
    for col in splits.columns:
        s = splits[col]
        assert set(s) == {TRAIN, CAL, TEST}
        assert_disjoint(df, s)
        assert 0.04 < (s == CAL).mean() < 0.13
    # different seeds give different partitions; same seed reproduces them
    assert not splits["split_0"].equals(splits["split_1"])
    again = grouped_splits(df, n_splits=10, test_fraction=0.2, cal_fraction=0.1, seed=0)
    assert splits.equals(again)


def test_assert_disjoint_catches_domain_and_url_leaks():
    df = to_schema(
        pd.Series(["https://a.com/1", "https://b.a.com/2", "https://c.com/"]),
        pd.Series([1, 1, 0]),
        "s",
    )
    with pytest.raises(LeakageError, match="domains"):
        assert_disjoint(df, pd.Series([TRAIN, TEST, TRAIN]))
    assert_disjoint(df, pd.Series([TRAIN, TRAIN, TEST]))
    dup = to_schema(pd.Series(["https://x.com/a", "http://www.x.com/a/"]), pd.Series([1, 1]), "s")
    dup["domain"] = ["x.com", "other"]  # same canonical URL under different domain labels
    with pytest.raises(LeakageError, match="URLs"):
        assert_disjoint(dup, pd.Series([TRAIN, TEST]))
