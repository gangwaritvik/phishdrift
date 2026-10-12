"""Tier A training and evaluation: metrics, leakage checks and a small end-to-end run."""

import math

import numpy as np
import pandas as pd
import pytest

from data_pipeline.split import LeakageError, grouped_splits
from experiments import tier_a
from experiments.metrics import at_threshold, evaluate, fpr_tag, operating_point
from features.extract import extract
from features.fit import Fitted
from features.lists import Lists


def test_operating_point_takes_largest_recall_within_fpr():
    y = np.array([0] * 100 + [1] * 10)
    s = np.r_[np.linspace(0, 0.5, 100), np.linspace(0.4, 1.0, 10)]
    op = operating_point(y, s, 0.01, min_negatives=10)
    assert op["achieved_fpr"] <= 0.01
    assert op["recall"] == pytest.approx(at_threshold(y, s, op["threshold"])["recall"])
    assert op["granularity_limited"]  # 1% of 100 negatives is 1 false positive
    assert not operating_point(y, s, 0.2, min_negatives=10)["granularity_limited"]


def test_perfect_scores_and_tags():
    y = np.array([0, 0, 1, 1])
    row = evaluate(y, np.array([0.1, 0.2, 0.8, 0.9]), [0.01, 0.001], 1, {0.01: 0.5})
    assert row["roc_auc"] == 1.0 and row["op_1pct_recall"] == 1.0
    assert row["cal_1pct_recall"] == 1.0 and row["cal_1pct_fpr"] == 0.0
    assert (fpr_tag(0.01), fpr_tag(0.001)) == ("1pct", "0p1pct")


def test_overlap_is_a_hard_failure():
    a = pd.DataFrame({"domain": ["x.com"], "_key": ["x.com/a"]})
    with pytest.raises(LeakageError):
        tier_a.assert_no_overlap(a, a, "train", "test")
    b = pd.DataFrame({"domain": ["y.com"], "_key": ["x.com/a"]})
    with pytest.raises(LeakageError):
        tier_a.assert_no_overlap(a, b, "train", "test")


def _write_part(path, name, rows, lists):
    meta = pd.DataFrame(rows)
    meta.to_parquet(path / f"meta_{name}.parquet", index=False)
    feats = pd.DataFrame([extract(u, lists=lists, fitted=Fitted()) for u in meta["url"]])
    feats.insert(0, "uid", meta["uid"])
    out = "features_a.parquet" if name == "pool" else f"features_a_{name}.parquet"
    feats.to_parquet(path / out, index=False)
    return meta


def _rows(source, n, start):
    rng = np.random.default_rng(start)
    rows = []
    for i in range(start, start + n):
        phish = i % 2 == 1
        dom = f"secure-login-{i}.xyz" if phish else f"site{i}.org"
        path = "/verify/account" if phish else f"/docs/page{rng.integers(9)}"
        rows.append(
            {
                "uid": f"{source}:{i}",
                "url": f"http://{dom}{path}",
                "domain": dom,
                "label": int(phish),
                "source": source,
                "depth": 2,
                "weight": 1.0,
            }
        )
    return rows


def test_end_to_end_small(tmp_path):
    lists = Lists.build(keywords=["login", "verify"], suspicious_tlds=["xyz"])
    pool = _write_part(tmp_path, "pool", _rows("a", 400, 0), lists)
    _write_part(tmp_path, "time_slice", _rows("a", 60, 1000), lists)
    _write_part(tmp_path, "heldout_source", _rows("b", 60, 2000), lists)
    splits = grouped_splits(pool, 2, 0.25, 0.2, seed=0).assign(uid=pool["uid"])
    splits.to_parquet(tmp_path / "splits.parquet", index=False)

    cfg = tier_a.load_config("models")
    cfg["lightgbm"] = cfg["lightgbm"] | {"n_estimators": 10, "min_child_samples": 5}
    cfg["xgboost"] = cfg["xgboost"] | {"n_estimators": 10}
    cfg["char_ngram"] = cfg["char_ngram"] | {"min_df": 1, "max_features": 2000}
    reports = tmp_path / "reports"
    md = tier_a.run(tmp_path, reports, [0], cfg=cfg, lists=lists)

    runs = pd.read_csv(reports / "tables" / "tier_a_runs.csv")
    sets = {"test", "heldout_source", "time_slice", "test_normalised"}
    assert set(runs["eval_set"]) == sets
    assert len(runs) == len(tier_a.SPECS) * len(sets)
    held = runs[(runs.eval_set == "heldout_source") & (runs.model == "lightgbm")]
    assert held["roc_auc"].iloc[0] > 0.9  # separable toy data
    controls = pd.read_csv(reports / "tables" / "tier_a_controls.csv")
    assert len(controls) == len(tier_a.CONTROL_SPECS)
    assert "Shuffled-label controls" in md.read_text(encoding="utf-8")

    tier_a.run(tmp_path, reports, [0], cfg=cfg, lists=lists)  # rerun: split 0 skipped
    assert len(pd.read_csv(reports / "tables" / "tier_a_runs.csv")) == len(runs)
    assert not math.isnan(runs["op_1pct_recall"].iloc[0])


def test_loso_small(tmp_path):
    from experiments import loso

    lists = Lists.build(keywords=["login", "verify"], suspicious_tlds=["xyz"])
    pool = _write_part(tmp_path, "pool", _rows("a", 300, 0) + _rows("b", 300, 5000), lists)
    splits = grouped_splits(pool, 1, 0.25, 0.2, seed=0).assign(uid=pool["uid"])
    splits.to_parquet(tmp_path / "splits.parquet", index=False)
    cfg = tier_a.load_config("models")
    cfg["lightgbm"] = cfg["lightgbm"] | {"n_estimators": 10, "min_child_samples": 5}
    cfg["char_ngram"] = cfg["char_ngram"] | {"min_df": 1, "max_features": 2000}
    md = loso.run(tmp_path, tmp_path / "reports", [0], cfg=cfg, lists=lists)
    rows = pd.read_csv(tmp_path / "reports" / "tables" / "loso.csv")
    left = rows[rows.condition == "leave_out"]
    assert set(left["source"]) == {"a", "b"} and len(left) == 2 * len(loso.LOSO_SPECS)
    assert (left["n_urls"] == 300).all()  # the left-out source is scored whole
    assert "leave_out" in md.read_text(encoding="utf-8")
