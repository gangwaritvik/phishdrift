import math

import numpy as np
import pandas as pd
import pytest
from scipy.stats import norm

from data_pipeline.split import grouped_splits
from experiments import threshold_transfer as tt
from experiments.metrics import at_threshold, operating_point
from features.lists import Lists
from tests.test_tier_a import _rows, _write_part

TCFG = {
    "model": "hybrid2",
    "balanced_min_negatives": 200,
    "confidence": 0.95,
    "n_bootstrap": 60,
    "bootstrap_seed": 11,
    "loso": {"splits": [0], "model": "lightgbm", "skip_one_class": True},
}


def _cal(rng, spec, pos=3000, urls_per_domain=1, domain_sd=0.0):
    """Cal frame: legit scores N(shift, 1) per source (optionally clustered by domain)."""
    parts = []
    for src, (n_neg, shift) in spec.items():
        n_dom = math.ceil(n_neg / urls_per_domain)
        dom_effect = rng.normal(0, domain_sd, n_dom)
        dom = np.arange(n_neg) // urls_per_domain
        s = rng.normal(shift, 1, n_neg) + dom_effect[dom]
        parts.append(
            pd.DataFrame(
                {"source": src, "label": 0, "score": s, "domain": [f"{src}{d}.com" for d in dom]}
            )
        )
        s_pos = rng.normal(3.0, 1, pos // len(spec))
        doms = [f"{src}-p{i}.xyz" for i in range(len(s_pos))]
        parts.append(pd.DataFrame({"source": src, "label": 1, "score": s_pos, "domain": doms}))
    return pd.concat(parts, ignore_index=True)


def test_threshold_at_matches_operating_point_with_unit_weights():
    rng = np.random.default_rng(0)
    for seed in range(20):
        n = int(rng.integers(50, 3000))
        y = rng.integers(0, 2, n)
        s = np.round(rng.normal(y * 1.5, 1), int(rng.integers(1, 4)))  # many ties
        for t in (0.01, 0.001, 0.1):
            assert tt.threshold_at(y, s, t) == operating_point(y, s, t, 10)["threshold"], seed


def test_threshold_at_weights_and_budget():
    y = np.array([0, 0, 0, 0, 1, 1])
    s = np.array([0.1, 0.2, 0.3, 0.9, 0.5, 0.95])
    # one negative of four allowed at 25%: 0.5 keeps both positives, 1 negative (0.9) above
    assert tt.threshold_at(y, s, 0.25) == 0.5
    # the 0.9 negative weighs 10 of 13: nothing below it is feasible at 25%
    assert tt.threshold_at(y, s, 0.25, neg_weight=np.array([1, 1, 1, 10.0])) == 0.95
    assert tt.threshold_at(y, s, 0.0, max_fp=0) == 0.95
    assert tt.threshold_at(np.zeros(3), np.array([1.0, 2, 3]), 0.0) == tt.NO_ALARM
    assert tt.threshold_at(np.zeros(3), np.array([1.0, 2, 3]), 0.34) == 3.0


def test_rule_ordering_with_shifted_small_source():
    """A small source with higher legit scores: pooled under-protects it, worst-source fixes it."""
    rng = np.random.default_rng(1)
    cal = _cal(rng, {"big": (40000, 0.0), "mid": (8000, 0.3), "shifted": (3000, 1.0)})
    s = cal["score"].to_numpy()
    y = cal["label"].to_numpy()
    rows = tt.rule_thresholds(cal, s, [0.01], TCFG, 10)
    thr = {r["rule"]: r["threshold"] for r in rows}
    rec = {k: at_threshold(y, s, v)["recall"] for k, v in thr.items()}
    assert thr["worst_source"] >= thr["pooled"]
    assert thr["ucb_binom"] >= thr["worst_source"] - 0.05  # bound is above the point estimate
    assert thr["ucb_boot"] >= thr["pooled"]
    # balanced weighs the shifted source like the big one: between pooled and worst-source
    assert rec["pooled"] >= rec["balanced"] >= rec["worst_source"]
    assert thr["balanced"] > thr["pooled"]
    by = {r["rule"]: r["set_by"] for r in rows}
    assert by["worst_source"] == "shifted" and by["ucb_binom"] == "shifted"
    # every known source is at or below the target at the worst-source threshold
    for _, g in cal.groupby("source"):
        r = at_threshold(g["label"], g["score"], thr["worst_source"])
        assert r["fpr"] <= 0.01 + 1e-12


def test_balanced_equals_pooled_when_sources_are_equal_size_and_alike():
    rng = np.random.default_rng(2)
    cal = _cal(rng, {"a": (5000, 0.0), "b": (5000, 0.0)})
    s, y = cal["score"].to_numpy(), cal["label"].to_numpy()
    bal, used = tt.balanced_threshold(cal, s, 0.01, 200)
    assert bal == tt.pooled_threshold(y, s, 0.01, 10)
    assert used == "a,b"


def test_small_sources_do_not_drive_the_confidence_rules():
    rng = np.random.default_rng(3)
    cal = _cal(rng, {"big": (20000, 0.0), "tiny": (60, 2.5)})
    s = cal["score"].to_numpy()
    rows = tt.rule_thresholds(cal, s, [0.01, 0.001], TCFG, 10)
    for r in rows:
        if r["rule"] in ("worst_source", "balanced", "ucb_binom", "ucb_boot"):
            assert "tiny" not in r["set_by"], r


def test_tiny_cal_falls_back_or_refuses():
    rng = np.random.default_rng(5)
    cal = _cal(rng, {"a": (150, 0.0), "b": (100, 0.5)}, pos=200)
    s, y = cal["score"].to_numpy(), cal["label"].to_numpy()
    bal, who = tt.balanced_threshold(cal, s, 0.01, 200)
    assert bal == tt.pooled_threshold(y, s, 0.01, 10) and who.startswith("pooled")
    thr, who = tt.ucb_binom_threshold(cal, s, 0.01, 0.95)  # 250 negatives cannot certify 1%
    assert thr == tt.NO_ALARM and who.startswith("uncertifiable")
    rows = tt.rule_thresholds(cal, s, [0.01], TCFG, 10)
    assert {r["rule"]: r["threshold"] for r in rows}["ucb_binom"] == math.inf


def test_clopper_pearson_bounds():
    n = 1000
    assert tt.cp_upper(0, n, 0.95) == pytest.approx(1 - 0.05 ** (1 / n))
    ub = tt.cp_upper(np.arange(10), n, 0.95)
    assert np.all(np.diff(ub) > 0)
    assert tt.max_false_positives(100, 0.01, 0.95) == -1  # cannot certify 1% on 100 negatives
    # zero false positives certify the target from n >= ln(0.05) / ln(1 - target) negatives
    assert tt.max_false_positives(298, 0.01, 0.95) == -1
    assert tt.max_false_positives(299, 0.01, 0.95) == 0
    assert tt.max_false_positives(2994, 0.001, 0.95) == -1
    assert tt.max_false_positives(2995, 0.001, 0.95) == 0
    k = tt.max_false_positives(100000, 0.01, 0.95)
    assert 900 < k < 1000 and tt.cp_upper(k, 100000, 0.95) <= 0.01 < tt.cp_upper(
        k + 1, 100000, 0.95
    )


def _true_fpr(thr, shift=0.0):
    return 1 - norm.cdf(thr - shift)


def test_ucb_binom_holds_the_target_on_fresh_draws():
    """With independent URLs the bound holds in at least ~95% of draws; pooled in about half."""
    hits = {"pooled": 0, "ucb_binom": 0}
    reps = 200
    for seed in range(reps):
        rng = np.random.default_rng(100 + seed)
        cal = _cal(rng, {"a": (5000, 0.0)}, pos=500)
        s, y = cal["score"].to_numpy(), cal["label"].to_numpy()
        hits["pooled"] += _true_fpr(tt.pooled_threshold(y, s, 0.01, 10)) <= 0.01
        hits["ucb_binom"] += _true_fpr(tt.ucb_binom_threshold(cal, s, 0.01, 0.95)[0]) <= 0.01
    assert hits["ucb_binom"] / reps >= 0.9
    assert hits["pooled"] / reps < 0.8


def test_ucb_boot_holds_the_target_with_domain_clusters():
    """URLs cluster by domain: the domain bootstrap keeps its coverage."""
    reps, ok_boot = 30, 0
    sd, per = 0.7, 10  # domain effect; URLs per domain
    marg_sd = math.sqrt(1 + sd**2)
    for seed in range(reps):
        rng = np.random.default_rng(500 + seed)
        cal = _cal(rng, {"a": (5000, 0.0)}, pos=500, urls_per_domain=per, domain_sd=sd)
        s = cal["score"].to_numpy()
        thr, who = tt.ucb_boot_threshold(cal, s, 0.01, 0.95, 60, 10, seed)
        ok_boot += (1 - norm.cdf(thr / marg_sd)) <= 0.01
    assert ok_boot / reps >= 0.8


def test_evaluate_rules_rows_and_oracle():
    rng = np.random.default_rng(4)
    cal = _cal(rng, {"a": (3000, 0.0), "b": (3000, 0.8)})
    test = _cal(rng, {"a": (2000, 0.0), "b": (2000, 0.8)})
    sets = {"test": test} | {f"test:{s}": g for s, g in test.groupby("source")}
    sets["heldout_source"] = _cal(rng, {"c": (500, 1.5)})
    rows = pd.DataFrame(tt.evaluate_rules(cal, sets, [0.01, 0.001], TCFG, 10, oracle=True))
    main = rows[rows["rule"] != tt.ORACLE]
    assert len(main) == len(tt.RULES) * 2 * len(sets)
    orc = rows[rows["rule"] == tt.ORACLE]
    assert set(orc["eval_set"]) == {"test:a", "test:b"} and len(orc) == 4
    # granularity: 500 legit rows cannot measure 0.1% (floor(0.5) < 10)
    held = rows[(rows["eval_set"] == "heldout_source") & (rows["target_fpr"] == 0.001)]
    assert held["granularity_limited"].all()
    assert (rows["fpr"] <= rows["fpr_upper"]).all()
    # pooled under-protects the shifted source on test; worst-source protects it
    b = rows[(rows["eval_set"] == "test:b") & (rows["target_fpr"] == 0.01)].set_index("rule")
    assert b.loc["worst_source", "fpr"] < b.loc["pooled", "fpr"]
    worst = tt.worst_case(rows.assign(setting="main", split=0))
    assert set(worst["rule"]) == set(tt.RULES)
    assert set(worst["worst_set"]) <= {"test:a", "test:b"}


def test_end_to_end_small(tmp_path, monkeypatch):
    lists = Lists.build(keywords=["login", "verify"], suspicious_tlds=["xyz"])
    rows = _rows("a", 300, 0) + _rows("b", 300, 5000) + _rows("c", 300, 9000)
    pool = _write_part(tmp_path, "pool", rows, lists)
    _write_part(tmp_path, "time_slice", _rows("a", 60, 1000), lists)
    _write_part(tmp_path, "heldout_source", _rows("d", 80, 2000), lists)
    splits = grouped_splits(pool, 2, 0.25, 0.2, seed=0).assign(uid=pool["uid"])
    splits.to_parquet(tmp_path / "splits.parquet", index=False)

    cfg = tt.load_config("models")
    cfg["lightgbm"] = cfg["lightgbm"] | {"n_estimators": 10, "min_child_samples": 5}
    cfg["stack"] = cfg["stack"] | {"n_folds": 3}
    small = {"min_df": 1, "max_features": 2000}
    cfg["hybrid2"] = {
        "scorers": [
            {"name": "char_url", "piece": "url", "kind": "char", "params": small},
            {"name": "word_url", "piece": "url", "kind": "word", "params": small | {"C": 4.0}},
        ]
    }
    cfg["threshold_transfer"] = cfg["threshold_transfer"] | {"n_bootstrap": 20}
    cfg["threshold_transfer"]["loso"] = {"splits": [0], "model": "lightgbm", "skip_one_class": True}
    reports, cache = tmp_path / "reports", tmp_path / "cache"
    md = tt.run(tmp_path, reports, [0, 1], cfg=cfg, lists=lists, cache=cache)

    runs = pd.read_csv(reports / "tables" / "threshold_transfer_runs.csv")
    main = runs[runs["setting"] == "main"]
    assert set(main["split"]) == {0, 1}
    assert {"test", "test:a", "test:b", "test:c", "heldout_source", "time_slice"} == set(
        main["eval_set"]
    )
    assert set(main["rule"]) == set(tt.RULES) | {tt.ORACLE}
    loso = runs[runs["setting"] == "loso"]
    assert set(loso["left_out"]) == {"a", "b", "c"}
    assert (loso.groupby("left_out")["n_urls"].first() == 300).all()  # left-out source whole
    text = md.read_text(encoding="utf-8")
    assert "Main setting, target FPR 1.0%" in text and "Leave one source out" in text
    assert "not usable at runtime" in text
    assert (reports / "tables" / "threshold_transfer_summary.csv").exists()
    assert len(list((reports / "tables" / tt.RUNS).glob("*.csv"))) == 2 + 3

    # rerun from the score cache: no training at all, same rows
    def boom(*a, **k):
        raise AssertionError("retrained despite cache")

    monkeypatch.setattr(tt, "_fit_score", boom)
    tt.run(tmp_path, reports, [0, 1], cfg=cfg, lists=lists, cache=cache)
    again = pd.read_csv(reports / "tables" / "threshold_transfer_runs.csv")
    assert len(again) == len(runs)
