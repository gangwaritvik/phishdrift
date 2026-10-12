import json

import numpy as np
import pytest

from features.registry import NAMES
from models.explain import contributions, expected_value, reason_rules, reasons
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
    # TreeSHAP in Python gives LightGBM's contributions (checked on a few URLs: it is slow).
    x = feature_matrix(urls[:3], lists, fitted, bundle["names"])
    for row, case in zip(x, parity["cases"][:3], strict=True):
        phi = contributions(bundle["trees"], row)
        top = reasons(phi, row, bundle["names"], bundle["reasons"], **bundle["explain"])
        assert [r["text"] for r in top] == [r["text"] for r in case["reasons"]]
        for mine, theirs in zip(top, case["reasons"], strict=True):
            assert mine["contribution"] == pytest.approx(theirs["contribution"], abs=1e-9)
    t = bundle["thresholds"]
    assert 0 < t["suspicious"] <= t["dangerous"] <= 1


def test_tree_shap_matches_lightgbm_pred_contrib():
    import lightgbm as lgb

    rng = np.random.default_rng(1)
    x = rng.normal(size=(2000, 5)).astype(np.float32)
    y = ((x[:, 0] + x[:, 1] * x[:, 2] + rng.normal(scale=0.5, size=2000)) > 0).astype(int)
    x[rng.random(x.shape) < 0.2] = np.nan
    w = rng.exponential(size=2000)
    params = dict(n_estimators=30, num_leaves=15, min_child_samples=5, verbose=-1)
    model = lgb.LGBMClassifier(**params, random_state=0).fit(x, y, sample_weight=w)
    trees = compact_trees(model.booster_)
    ref = model.booster_.predict(x[:50], pred_contrib=True)
    got = np.array([contributions(trees, row) for row in x[:50]])
    assert np.max(np.abs(got - ref[:, :-1])) < 1e-12
    assert expected_value(trees) == pytest.approx(ref[0, -1], abs=1e-12)


def test_reasons_follow_rules():
    names = list(NAMES)
    rules = reason_rules(names)
    assert set(rules) == set(names)
    phi = np.zeros(len(names))
    x = np.zeros(len(names), dtype=np.float32)
    i_ip, i_len, i_short = (
        names.index("host_is_ip"),
        names.index("url_len"),
        names.index("is_shortener"),
    )
    phi[[i_ip, i_len, i_short]] = [2.0, 0.5, 1.0]
    x[i_len] = 80
    x[i_ip] = 1  # shortener stays 0: absence is never a reason
    out = reasons(phi, x, names, rules, top=3, min_logodds=0.1)
    assert [r["feature"] for r in out] == ["host_is_ip", "url_len"]
    assert "80 characters" in out[1]["text"]
    assert reasons(phi, x, names, rules, top=1, min_logodds=0.1)[0]["feature"] == "host_is_ip"
    assert reasons(phi, x, names, rules, top=3, min_logodds=3.0) == []
