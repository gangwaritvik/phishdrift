"""CatBoost kind, the source-adversarial scorer and the one-split boosters experiment."""

import argparse

import numpy as np
import pandas as pd
import pytest

pytest.importorskip("torch")
pytest.importorskip("catboost")

from data_pipeline.split import grouped_splits  # noqa: E402
from experiments import boosters_a, tier_a  # noqa: E402
from features.lists import Lists  # noqa: E402
from models.adv_text import AdvText  # noqa: E402
from models.gbdt import GBDT  # noqa: E402
from tests.test_tier_a import _rows, _write_part  # noqa: E402

PARAMS = {
    "ngram_range": [3, 4],
    "n_features": 4096,
    "embed_dim": 8,
    "lr": 0.01,
    "batch_size": 16,
    "epochs": 15,
    "lam": 1.0,
    "source_weight": 1.0,
}


def test_catboost_keeps_nan_and_scores():
    rng = np.random.default_rng(0)
    x = pd.DataFrame({"a": rng.normal(size=300), "b": rng.normal(size=300)})
    y = (x["a"] > 0).astype(int).to_numpy()
    x.loc[::10, "b"] = np.nan
    s = GBDT("catboost", {"iterations": 30, "depth": 3}, ["a", "b"], 0).fit(x, y).score(x)
    assert s.shape == (300,) and s[y == 1].mean() > s[y == 0].mean() + 0.3


def test_adv_text_learns_label_and_tells_sources_apart_without_adversary():
    texts = ["http://login-verify.xyz/a"] * 40 + ["https://www.docs.org/page"] * 40
    texts += ["http://pay-secure.top/b"] * 40 + ["https://www.news.com/story"] * 40
    y = np.array([1] * 40 + [0] * 40 + [1] * 40 + [0] * 40)
    src = np.array(["a"] * 80 + ["b"] * 80)
    plain = AdvText(PARAMS, 0, lam=0.0).fit(texts, y, None, src)
    s = plain.score(texts)
    assert s[y == 1].mean() > s[y == 0].mean() + 0.4
    assert plain.score([]).shape == (0,)
    assert plain.source_accuracy(texts, src) > 0.9  # without the adversary the source is easy
    adv = AdvText(PARAMS, 0).fit(texts, y, None, src)
    assert adv.score(texts).shape == (160,)


def test_experiment_end_to_end_small(tmp_path):
    lists = Lists.build(keywords=["login", "verify"], suspicious_tlds=["xyz"])
    pool = _write_part(tmp_path, "pool", _rows("a", 400, 0), lists)
    _write_part(tmp_path, "heldout_source", _rows("b", 60, 2000), lists)
    splits = grouped_splits(pool, 1, 0.25, 0.2, seed=0).assign(uid=pool["uid"])
    splits.to_parquet(tmp_path / "splits.parquet", index=False)
    cfg = tier_a.load_config("models")
    small = {"n_estimators": 10}
    cfg["lightgbm"] = cfg["lightgbm"] | small | {"min_child_samples": 5}
    cfg["xgboost"] = cfg["xgboost"] | small
    cfg["char_ngram"] = cfg["char_ngram"] | {"min_df": 1, "max_features": 2000}
    args = argparse.Namespace(
        processed=tmp_path,
        reports=tmp_path / "out",
        split=0,
        max_hours=1.0,
        smoke=250,
        lists_dir=None,
        platforms_file=None,
    )
    assert boosters_a.run(args, cfg=cfg, lists=lists) == 0
    out = tmp_path / "out"
    alone = pd.read_csv(out / "tables" / "alone_runs.csv")
    hybrid = pd.read_csv(out / "tables" / "hybrid_runs.csv")
    assert {"char_url_lr", "adv_url", "plain_url"} == set(alone["model"])
    assert {"lightgbm", "catboost", "xgboost", "lightgbm+adv", "avg_lgbm_cat"} <= set(
        hybrid["model"]
    )
    assert {"test", "heldout_source", "test_normalised"} <= set(hybrid["eval_set"])
    assert "source_accuracy_test" in pd.read_csv(out / "tables" / "source_accuracy.csv").columns
    text = (out / "SUMMARY.md").read_text(encoding="utf-8")
    assert "Change in recall at 1% FPR against" in text
    assert boosters_a.run(args, cfg=cfg, lists=lists) == 0  # rerun: stages skipped
