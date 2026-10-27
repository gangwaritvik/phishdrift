"""Tier C serving: the parity fixture is current, and training exports a bundle the JS side can read."""

import json
import math

import pandas as pd
import pytest

from experiments import tier_c
from features import build_c
from models import tier_c as model_c
from tests.test_tier_c import LISTS, small_cfg, write_jsonl


def test_parity_fixture_is_current():
    """tests/fixtures/tier_c_parity.json is what `python -m models.tier_c parity` writes now."""
    stored = json.loads(model_c.PARITY_FILE.read_text(encoding="utf-8"))
    fresh = json.loads(json.dumps(model_c.clean(model_c.parity_doc())))
    assert stored == fresh, "run: python -m models.tier_c parity"


@pytest.fixture
def trained(tmp_path, monkeypatch):
    monkeypatch.setattr(build_c, "load_lists", lambda: LISTS)
    write_jsonl(tmp_path / "info", n_phish=80, n_benign=80, extras=False)
    out, _ = build_c.build_c(tmp_path / "info", tmp_path / "features_c.parquet")
    cfg = small_cfg()
    df, _ = tier_c.eligible(pd.read_parquet(out), None, False)
    return cfg, *model_c.train(df, cfg, 0)


def test_bundle_has_everything_the_function_needs(trained):
    cfg, model, calib, frames = trained
    capture = {"rdap_bootstrap_url": "u", "doh_urls": ["d"], "dns_timeout_s": 5, "tls_timeout_s": 8}
    bundle = model_c.build_bundle(model, calib, frames, LISTS, cfg, capture)
    assert bundle["names"] == list(model_c.NAMES_C)
    assert bundle["serving"]["doh_urls"] == ["d"]
    assert bundle["serving"]["total_timeout_ms"] == cfg["tier_c"]["serving"]["total_timeout_ms"]
    assert bundle["brands"] == sorted(LISTS.brands)
    # with so few negatives on the cal side the 0.1% point cannot be measured, so there is none
    assert bundle["thresholds"]["dangerous"] is None
    assert 0 < bundle["thresholds"]["suspicious"] < 1
    assert set(bundle["reasons"]) == set(model_c.NAMES_C)
    assert not any(math.isnan(v) for v in bundle["isotonic"]["x"])
    json.dumps(model_c.clean(bundle))  # JSON-safe once NaN is cleaned


def test_model_parity_rows_match_exported_trees(trained):
    cfg, model, calib, frames = trained
    bundle = model_c.build_bundle(model, calib, frames, LISTS, cfg)
    doc = model_c.model_parity(bundle, model, frames, n=10)
    assert len(doc["cases"]) == 10
