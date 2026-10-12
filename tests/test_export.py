import json

import numpy as np
import pytest

from models.export import (
    BUNDLE_FILE,
    MODEL_PARITY_FILE,
    compact_trees,
    feature_matrix,
    lists_from_payload,
    probability,
)


def _small_model(missing: float):
    import lightgbm as lgb

    rng = np.random.default_rng(0)
    x = rng.normal(size=(3000, 6)).astype(np.float32)
    x[:, 3] = rng.integers(0, 3, 3000)  # many exact zeros
    y = ((x[:, 0] + (x[:, 3] == 0) + rng.normal(scale=0.5, size=3000)) > 0.5).astype(int)
    x[rng.random(x.shape) < 0.2] = missing
    params = dict(n_estimators=40, num_leaves=15, min_child_samples=5, verbose=-1)
    model = lgb.LGBMClassifier(**params, random_state=0).fit(x, y)
    return model, x


@pytest.mark.parametrize("missing", [np.nan, 0.0])
def test_tree_walker_matches_lightgbm(missing):
    model, x = _small_model(missing)
    trees = compact_trees(model.booster_)
    probe = np.vstack([x, np.full((1, 6), np.nan), np.zeros((1, 6)), np.full((1, 6), 1e-40)])
    expected = model.predict_proba(probe)[:, 1]
    assert np.max(np.abs(probability(trees, probe) - expected)) < 1e-12


def test_single_leaf_tree():
    trees = [{"f": [], "t": [], "m": [], "d": [], "l": [], "r": [], "v": [0.25]}]
    assert probability(trees, np.zeros((2, 1))) == pytest.approx(1 / (1 + np.exp(-0.25)))


@pytest.mark.skipif(not BUNDLE_FILE.exists(), reason="no exported tier A model")
def test_bundle_reproduces_lightgbm_on_parity_urls():
    bundle = json.loads(BUNDLE_FILE.read_text(encoding="utf-8"))
    parity = json.loads(MODEL_PARITY_FILE.read_text(encoding="utf-8"))
    assert parity["bundle_created"] == bundle["created"], "rerun python -m models.export"
    lists, fitted = lists_from_payload(bundle["lists"])
    urls = [c["url"] for c in parity["cases"]]
    got = probability(bundle["trees"], feature_matrix(urls, lists, fitted, bundle["names"]))
    expected = np.array([c["prob"] for c in parity["cases"]])
    assert len(urls) >= 200
    assert np.max(np.abs(got - expected)) < 1e-12
    t = bundle["thresholds"]
    assert 0 < t["suspicious"] <= t["dangerous"] <= 1
