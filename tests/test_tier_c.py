"""Tier C experiment: eligibility filters, grouped splits, skip path and an end-to-end run."""

import json

import numpy as np
import pandas as pd
import pytest

from data_pipeline.split import LeakageError, grouped_splits
from experiments import tier_c
from features import build_c
from features.lists import Lists

LISTS = Lists.build(platforms=["web.app"], brands=["paypal"], keywords=["login", "verify"])
DAYS = ("2026-10-10", "2026-10-11", "2026-10-12")


def _host(name, dom, label, day, i, rng):
    phish = label == 1
    age_days = rng.integers(1, 60) if phish else rng.integers(2000, 9000)
    captured = f"{day}T12:00:00+00:00"
    registered = (pd.Timestamp(captured) - pd.Timedelta(days=int(age_days))).isoformat()
    domain_rec = {
        "kind": "domain",
        "domain": dom,
        "captured_at": captured,
        "rdap": {
            "registered": registered,
            "expires": (pd.Timestamp(registered) + pd.Timedelta(days=365)).isoformat(),
            "last_changed": registered,
            "registrar": "r",
            "status": ["client transfer prohibited"],
            "nameservers": [],
            "redacted": bool(phish),
        },
        "rdap_error": None,
    }
    host_rec = {
        "kind": "host",
        "host": name,
        "domain": dom,
        "label": label,
        "first_seen": f"{day} 10:00:00+00:00",
        "captured_at": captured,
        "dns": {
            "errors": [],
            "a": [f"192.0.2.{i % 250 + 1}"],
            "aaaa": [],
            "cname": [],
            "ns": [f"ns{j}.dns{i % 7}.net" for j in (1, 2)],
            "mx_count": 0 if phish else 2,
            "spf": not phish,
            "dmarc": not phish,
            "min_ttl": 300,
            "resolves": True,
        },
        "tls": {
            "ok": True,
            "verified": True,
            "issuer_o": "Let's Encrypt" if phish else "DigiCert",
            "issuer_cn": "R11",
            "subject_cn": name,
            "not_before": registered,
            "not_after": "2027-01-01T00:00:00+00:00",
            "san_count": 1,
            "sans": [name],
        },
    }
    return [domain_rec, host_rec]


def write_jsonl(path, n_phish=60, n_benign=60, extras=True):
    rng = np.random.default_rng(0)
    recs = []
    for i in range(n_phish):
        dom = f"phish{i}.top"
        recs += _host(f"login.{dom}", dom, 1, DAYS[i % 3], i, rng)
    for i in range(n_benign):  # benign hosts come as <domain> and www.<domain>
        dom = f"site{i}.org"
        for name in (dom, f"www.{dom}"):
            recs += _host(name, dom, 0, DAYS[i % 3], i, rng)
    if extras:  # one row for each filter
        recs += _host("x.web.app", "web.app", 1, DAYS[0], 1, rng)
        recs += _host("192.0.2.9", "192.0.2.9", 1, DAYS[0], 2, rng)
        blocked = _host("blocked.bad.top", "bad.top", 1, DAYS[0], 3, rng)
        blocked[1]["dns"] |= {"a": ["0.0.0.0"]}
        dead = _host("dead.gone.top", "gone.top", 1, DAYS[0], 4, rng)
        dead[1]["dns"] |= {"a": [], "resolves": False}
        recs += blocked + dead
    path.mkdir(parents=True, exist_ok=True)
    by_day: dict[str, list[str]] = {}
    for r in recs:
        by_day.setdefault(r["captured_at"][:10], []).append(json.dumps(r))
    for day, lines in by_day.items():
        (path / f"{day}.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def small_cfg(n_splits=3):
    cfg = tier_c.load_config("models")
    cfg["tier_c"] = cfg["tier_c"] | {"n_splits": n_splits, "min_rows_per_class": 10}
    cfg["tier_c"]["lightgbm"] = cfg["tier_c"]["lightgbm"] | {"n_estimators": 20}
    return cfg


@pytest.fixture
def features_c(tmp_path, monkeypatch):
    monkeypatch.setattr(build_c, "load_lists", lambda: LISTS)
    write_jsonl(tmp_path / "info")
    out, _ = build_c.build_c(tmp_path / "info", tmp_path / "features_c.parquet")
    return out


def test_eligibility_filters(features_c):
    df, filters = tier_c.eligible(pd.read_parquet(features_c))
    f = filters.set_index("filter")
    assert f.loc["hosting platform", "phishing"] == 1
    assert f.loc["IP host", "phishing"] == 1
    assert f.loc["filtered by the PC's resolver", "phishing"] == 1
    assert f.loc["not resolving", "phishing"] == 1
    assert f["benign"].sum() == 0
    assert (df["label"] == 1).sum() == 60 and (df["label"] == 0).sum() == 120
    assert df["resolves"].all() and not df["filtered"].any()


def test_split_overlap_is_a_hard_failure(features_c):
    df, _ = tier_c.eligible(pd.read_parquet(features_c))
    side = grouped_splits(df, 1, 0.2, 0.25, seed=0)["split_0"]
    tier_c.check_split(df, side)  # a real split passes
    www = df.index[df["host"].str.startswith("www.")][0]
    bare = df.index[df["host"] == df.loc[www, "host"][4:]][0]
    broken = side.copy()
    broken.loc[www], broken.loc[bare] = "train", "test"  # one domain on both sides
    with pytest.raises(LeakageError):
        tier_c.check_split(df, broken)


def test_end_to_end(features_c, tmp_path):
    reports = tmp_path / "reports"
    md = tier_c.run(features_c, reports, cfg=small_cfg()).read_text(encoding="utf-8")
    runs = pd.read_csv(reports / "tables" / "tier_c_runs.csv")
    assert set(runs["split"]) == {0, 1, 2}
    models = set(zip(runs["model"], runs["features"], strict=True))
    assert models == {
        ("lightgbm", "c_all"),
        ("lightgbm", "c_no_age"),
        ("baseline", "domain_age_days"),
        ("lightgbm", "c_all_shuffled"),
    }
    main = runs[runs["features"] == "c_all"]
    assert (main["roc_auc"] > 0.9).all()  # separable toy data
    assert (main["n_urls"] > main["n_domains"]).all()  # www pairs: hosts > domains
    assert {"cal_1pct_recall", "op_0p1pct_granularity_limited"} <= set(runs)
    imp = pd.read_csv(reports / "tables" / "tier_c_importance.csv")
    assert {"feature", "group", "gain_share_mean"} <= set(imp)
    assert "Leakage tripwire" in md  # perfect toy separation trips it
    assert "Shuffled-label control" in md and "`has_cname`" in md
    assert "Time check: train/cal on" in md
    assert (reports / "tables" / "tier_c_time.csv").exists()
    assert "Tranco" in md  # caveats


def test_skip_without_benign(tmp_path, monkeypatch):
    monkeypatch.setattr(build_c, "load_lists", lambda: LISTS)
    write_jsonl(tmp_path / "info", n_benign=0)
    out, _ = build_c.build_c(tmp_path / "info", tmp_path / "f.parquet")
    assert tier_c.main(["--features", str(out), "--reports", str(tmp_path / "r")]) == 0
    md = (tmp_path / "r" / "tier_c.md").read_text(encoding="utf-8")
    assert "Not trained" in md and "no eligible benign hosts" in md
    assert not (tmp_path / "r" / "tables" / "tier_c_runs.csv").exists()


def test_with_a_on_a_tiny_pool(features_c, tmp_path):
    from tests.test_tier_a import _rows, _write_part

    pool_dir = tmp_path / "processed"
    pool_dir.mkdir()
    pool = _write_part(pool_dir, "pool", _rows("a", 200, 0), LISTS)
    rows = _rows("b", 2, 900)
    rows[0] |= {"url": "http://phish0.top/x", "domain": "phish0.top"}  # also a tier C host
    _write_part(pool_dir, "heldout_source", rows, LISTS)
    splits = grouped_splits(pool, 1, 0.25, 0.2, seed=0).assign(uid=pool["uid"])
    splits.to_parquet(pool_dir / "splits.parquet", index=False)
    cfg = small_cfg(n_splits=2)
    cfg["lightgbm"] = cfg["lightgbm"] | {"n_estimators": 10, "min_child_samples": 5}
    cfg["stack"] = cfg["stack"] | {"n_folds": 3}
    small = {"min_df": 1, "max_features": 2000}
    cfg["hybrid2"] = {
        "scorers": [{"name": "char_url", "piece": "url", "kind": "char", "params": small}]
    }
    reports = tmp_path / "reports"
    tier_c.run(features_c, reports, cfg=cfg, with_a=True, processed=pool_dir, lists=LISTS)
    runs = pd.read_csv(reports / "tables" / "tier_c_runs.csv")
    assert {"a_host", "c+a_host"} <= set(runs["model"]) | set(runs["features"])
    filters = pd.read_csv(reports / "tables" / "tier_c_filters.csv").set_index("filter")
    assert filters.loc["domain in the tier A pool (--with-a)", "phishing"] == 1


def test_hosts_captured_long_after_first_seen_are_dropped():
    df = pd.DataFrame(
        {
            "host": ["a.xyz", "b.xyz", "c.com"],
            "domain": ["a.xyz", "b.xyz", "c.com"],
            "label": [1, 1, 0],
            "is_hosting_platform": [False] * 3,
            "is_ip": [False] * 3,
            "filtered": [False] * 3,
            "resolves": [True] * 3,
            "first_seen": ["2026-10-12T00:00:00+00:00", "2026-10-12T00:00:00+00:00", None],
            "captured_at": [
                "2026-10-12T00:30:00+00:00",  # 0.5 h: kept
                "2026-10-12T10:00:00+00:00",  # 10 h: dropped
                "2026-10-12T05:00:00+00:00",  # first seen unknown: kept
            ],
        }
    )
    out, filters = tier_c.eligible(df, max_lag_h=2)
    assert sorted(out["host"]) == ["a.xyz", "c.com"]
    assert filters.iloc[-1]["phishing"] == 1
    out, _ = tier_c.eligible(df)  # no limit: all kept
    assert len(out) == 3
