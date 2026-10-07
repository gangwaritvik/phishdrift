import json

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import pytest

from data_pipeline.datacard import write_card
from data_pipeline.loaders import write_interim
from data_pipeline.pipeline import build_dataset
from data_pipeline.split import (
    DROPPED_OVERLAP,
    DROPPED_UNDATED,
    TEST,
    TRAIN,
    LeakageError,
    assert_domain_disjoint,
    random_domain_split,
    resolve_cutoff,
    time_split,
)
from phishdrift.schema import to_schema

SPLIT_CFG = {
    "seed": 42,
    "random_split": {"test_fraction": 0.2},
    "time_split": {"cutoff": None, "cutoff_quantile": 0.8, "drop_test_domains_seen_in_train": True},
}


def synthetic(n_domains: int = 300, seed: int = 0, with_dates: bool = True) -> pd.DataFrame:
    """Several URLs per domain (subdomains + paths), dates spread over a year."""
    rng = np.random.default_rng(seed)
    urls, labels, dates = [], [], []
    for d in range(n_domains):
        label = int(rng.random() < 0.4)
        tld = "xyz" if label else "com"
        start = pd.Timestamp("2025-01-01") + pd.Timedelta(days=int(rng.integers(0, 365)))
        for k in range(int(rng.integers(1, 8))):
            urls.append(f"https://sub{k}.site{d}.{tld}/page/{k}?id={rng.integers(1e6)}")
            labels.append(label)
            dates.append(start + pd.Timedelta(days=int(rng.integers(0, 60))))
    return to_schema(
        pd.Series(urls),
        pd.Series(labels),
        "synthetic",
        dates=pd.Series(dates) if with_dates else None,
    )


@pytest.mark.parametrize("seed", [0, 1, 2, 3])
def test_random_split_no_domain_in_both(seed):
    df = synthetic(seed=seed)
    split = random_domain_split(df, 0.2, seed=seed)
    assert_domain_disjoint(df, split)
    frac = (split == TEST).mean()
    assert 0.15 < frac < 0.25
    # stratified: class balance roughly equal on both sides
    p_train = df.loc[split == TRAIN, "label"].mean()
    p_test = df.loc[split == TEST, "label"].mean()
    assert abs(p_train - p_test) < 0.1


def test_random_split_is_deterministic():
    df = synthetic()
    assert random_domain_split(df, 0.2, 7).equals(random_domain_split(df, 0.2, 7))


def test_time_split_order_and_disjoint():
    df = synthetic()
    cutoff = resolve_cutoff(df, None, 0.8)
    split = time_split(df, cutoff)
    assert_domain_disjoint(df, split)
    assert df.loc[split == TRAIN, "date"].max() < cutoff
    assert df.loc[split == TEST, "date"].min() >= cutoff
    assert (split == DROPPED_OVERLAP).sum() > 0  # domains spanning the cutoff were removed


def test_time_split_drops_undated_and_respects_fixed_cutoff():
    df = synthetic()
    df.loc[:4, "date"] = pd.NaT
    split = time_split(df, resolve_cutoff(df, "2025-07-01", 0.8))
    assert (split.loc[:4] == DROPPED_UNDATED).all()
    assert df.loc[split == TEST, "date"].min() >= pd.Timestamp("2025-07-01", tz="UTC")


def test_leakage_is_detected():
    df = to_schema(
        pd.Series(["https://a.example.com/1", "https://b.example.com/2"]), pd.Series([1, 1]), "t"
    )
    with pytest.raises(LeakageError):
        assert_domain_disjoint(df, pd.Series([TRAIN, TEST]))


def test_no_dates_raises_for_time_cutoff():
    with pytest.raises(ValueError):
        resolve_cutoff(synthetic(with_dates=False), None, 0.8)


def _build(tmp_path, df, dedup_cfg, name="synthetic"):
    interim = tmp_path / "interim" / f"{name}.parquet"
    stats = write_interim([df.iloc[:500], df.iloc[500:]], interim, dedup_cfg)
    cfg = {
        "paths": {"processed_dir": str(tmp_path / "processed")},
        "dedup": dedup_cfg,
        name: {"license": "test"},
    }
    return build_dataset(name, interim, cfg, SPLIT_CFG, stats)


def test_end_to_end_files_are_domain_disjoint(tmp_path, dedup_cfg):
    df = synthetic(n_domains=400)
    df = pd.concat([df, df.iloc[:20]], ignore_index=True)  # exact duplicates to remove
    card = _build(tmp_path, df, dedup_cfg)
    assert card["dedup"]["exact_duplicates"] == 20

    out = tmp_path / "processed" / "synthetic"
    for kind in ("random", "time"):
        train = pq.read_table(out / kind / "train.parquet").to_pandas()
        test = pq.read_table(out / kind / "test.parquet").to_pandas()
        assert set(train["domain"]).isdisjoint(test["domain"]), kind
        assert set(train["row_id"]).isdisjoint(test["row_id"])
        assert {"url", "domain", "label", "date", "source", "html"} <= set(train.columns)
    rnd = (
        pq.read_table(out / "random" / "train.parquet").num_rows
        + pq.read_table(out / "random" / "test.parquet").num_rows
    )
    assert rnd == len(df) - 20

    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["seed"] == 42 and manifest["time_cutoff"]

    md, csv = write_card([card], tmp_path / "reports")
    text = md.read_text()
    assert "## synthetic" in text and "**time split**" in text and "**random split**" in text
    table = pd.read_csv(csv)
    assert set(table["split"]) == {"random", "time"}


def test_end_to_end_undated_dataset_gets_random_only(tmp_path, dedup_cfg):
    card = _build(tmp_path, synthetic(with_dates=False), dedup_cfg, name="undated")
    assert set(card["splits"]) == {"random"}
    assert any("no per-row dates" in n for n in card["notes"])
    assert not (tmp_path / "processed" / "undated" / "time").exists()
