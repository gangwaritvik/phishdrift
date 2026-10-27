"""CharCNN scorer and the one-split experiment (skipped when PyTorch is not installed)."""

import argparse

import numpy as np
import pandas as pd
import pytest

pytest.importorskip("torch")

from data_pipeline.split import grouped_splits  # noqa: E402
from experiments import char_cnn_a, tier_a  # noqa: E402
from features.lists import Lists  # noqa: E402
from models import char_cnn  # noqa: E402
from tests.test_tier_a import _rows, _write_part  # noqa: E402

PARAMS = {
    "max_len": 60,
    "embed_dim": 8,
    "widths": [3, 5],
    "filters": 8,
    "hidden": 8,
    "dropout": 0.0,
    "lr": 0.01,
    "batch_size": 16,
    "epochs": 20,
}


def test_encode_pads_truncates_and_maps_unknown():
    x = char_cnn.encode(["ab", "a" * 100, "é"], 10)
    assert char_cnn.encode(["é" * 50], 10).shape == (1, 10)  # multi-byte text is cut by bytes
    assert x.shape == (3, 10) and x[0, 2] == 0 and (x[1] == x[1, 0]).all()
    assert x[2, 0] == 96  # non-ASCII byte -> unknown id


def test_learns_resumes_and_stops_at_deadline(tmp_path):
    texts = ["http://login-verify.xyz/a"] * 60 + ["https://www.docs.org/page"] * 60
    y = np.array([1] * 60 + [0] * 60)
    m = char_cnn.CharCNN(PARAMS, 0, tmp_path).fit(texts, y)
    s = m.score(texts)
    assert s[:60].mean() > s[60:].mean() + 0.4
    again = char_cnn.CharCNN(PARAMS, 0, tmp_path).fit(texts, y)  # finished model is reused
    assert np.allclose(again.score(texts), s, atol=1e-6)

    char_cnn.set_deadline(-1)  # already past: stops after the first epoch, checkpoint kept
    try:
        with pytest.raises(char_cnn.TimeLimit):
            char_cnn.CharCNN(PARAMS, 1, tmp_path).fit(texts, y)
    finally:
        char_cnn.set_deadline(None)
    done = char_cnn.CharCNN(PARAMS, 1, tmp_path).fit(texts, y)  # resumes at epoch 1
    assert done.score(texts[:2]).shape == (2,)


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
        split=0,
        max_hours=1.0,
        smoke=250,
        lists_dir=None,
        platforms_file=None,
    )
    assert char_cnn_a.run(args, cfg=cfg, lists=lists) == 0
    out = tmp_path / "out"
    alone = pd.read_csv(out / "tables" / "alone_runs.csv")
    hybrid = pd.read_csv(out / "tables" / "hybrid_runs.csv")
    assert {"cnn_url", "char_url_lr"} == set(alone["model"])
    assert {"hybrid2", "hybrid2+cnn"} == set(hybrid["model"])
    assert {"test", "heldout_source", "time_slice", "test_normalised"} <= set(hybrid["eval_set"])
    text = (out / "SUMMARY.md").read_text(encoding="utf-8")
    assert "Shuffled-label control" in text and "recall at 1% FPR" in text
    assert char_cnn_a.run(args, cfg=cfg, lists=lists) == 0  # rerun: stages skipped
