"""Embedding scorer (offline ``hash`` stand-in) and the one-split experiment."""

import argparse

import numpy as np
import pandas as pd
import pytest

from data_pipeline.split import grouped_splits
from experiments import embed_a, tier_a
from features.lists import Lists
from models import char_cnn
from models.embed_scorer import Embedder, EmbedLR, words
from tests.test_tier_a import _rows, _write_part


def test_words_splits_on_everything_but_letters_and_digits():
    assert words("Login-PayPal.x.com/a_b?c=1") == "login paypal x com a b c 1"
    assert words("") == ""


def test_embedder_caches_in_shards_and_resumes(tmp_path):
    texts = ["paypal login", "docs example", "paypal login", ""]
    e = Embedder("hash", tmp_path, chunk=2)
    x = e.encode(texts)
    assert (
        x.shape == (4, 64) and np.allclose(x[0], x[2]) and len(list(e.dir.glob("shard_*.npz"))) == 2
    )
    again = Embedder("hash", tmp_path, chunk=2)  # new object reads the shards, computes nothing
    again._embed = lambda t: (_ for _ in ()).throw(AssertionError("recomputed"))
    assert np.allclose(again.encode(texts), x, atol=1e-3)  # float16 storage


def test_embedder_stops_at_deadline_and_continues(tmp_path):
    texts = [f"word{i} login" for i in range(6)]
    char_cnn.set_deadline(-1)
    try:
        with pytest.raises(char_cnn.TimeLimit):
            Embedder("hash", tmp_path, chunk=2).encode(texts)
    finally:
        char_cnn.set_deadline(None)
    assert Embedder("hash", tmp_path, chunk=2).encode(texts).shape == (6, 64)  # kept 1 shard


def test_embed_lr_separates_two_vocabularies(tmp_path):
    texts = ["login verify account"] * 40 + ["docs library archive"] * 40
    y = np.array([1] * 40 + [0] * 40)
    m = EmbedLR(Embedder("hash", tmp_path), {"C": 10.0}, 0).fit(texts, y)
    s = m.score(["login verify account", "docs library archive"])
    assert s[0] > 0.8 and s[1] < 0.2


def test_experiment_end_to_end_small(tmp_path):
    lists = Lists.build(keywords=["login", "verify"], suspicious_tlds=["xyz"])
    pool = _write_part(tmp_path, "pool", _rows("a", 400, 0), lists)
    _write_part(tmp_path, "time_slice", _rows("a", 60, 1000), lists)
    _write_part(tmp_path, "heldout_source", _rows("b", 60, 2000), lists)
    splits = grouped_splits(pool, 1, 0.25, 0.2, seed=0).assign(uid=pool["uid"])
    splits.to_parquet(tmp_path / "splits.parquet", index=False)
    cfg = tier_a.load_config("models")
    cfg["lightgbm"] = cfg["lightgbm"] | {"n_estimators": 10, "min_child_samples": 5}
    cfg["char_ngram"] = cfg["char_ngram"] | {"min_df": 1, "max_features": 2000}
    args = argparse.Namespace(
        processed=tmp_path,
        reports=tmp_path / "out",
        cache_dir=tmp_path / "cache",
        embedder="hash",
        split=0,
        max_hours=1.0,
        smoke=250,
        lists_dir=None,
        platforms_file=None,
    )
    assert embed_a.run(args, cfg=cfg, lists=lists) == 0
    out = tmp_path / "out"
    alone = pd.read_csv(out / "tables" / "alone_runs.csv")
    hybrid = pd.read_csv(out / "tables" / "hybrid_runs.csv")
    assert {"embed_host", "embed_path", "char_host_lr", "char_path_lr"} == set(alone["model"])
    assert {"hybrid2", "hybrid2+embed"} == set(hybrid["model"])
    assert {"test", "heldout_source", "time_slice"} <= set(hybrid["eval_set"])
    text = (out / "SUMMARY.md").read_text(encoding="utf-8")
    assert "Shuffled-label control" in text and "recall at 1% FPR" in text
    assert embed_a.run(args, cfg=cfg, lists=lists) == 0  # rerun: stages skipped
