import numpy as np
import pandas as pd
import pytest

from data_pipeline.corpus import (
    DROPPED_OVERLAP,
    EVAL_ONLY,
    HELDOUT,
    POOL,
    TIME_SLICE,
    DepthImbalanceError,
    assign_domain_owner,
    balance_depth,
    build_corpus,
    cap_per_domain,
    carve_holdouts,
    check_depth,
    depth_bucket,
    enforce_depth,
    shared_phishing_domains,
    source_weights,
)
from phishdrift.schema import to_schema

DEPTH_CFG = {
    "top_bucket": 4,
    "balance": True,
    "target_share": 0.8,
    "min_minority": 5,
    "fail_share": 0.9,
}


def meta(rows: list[tuple]) -> pd.DataFrame:
    """rows: (url, label, source[, date[, origin]])"""
    rows = [r + (None,) * (5 - len(r)) for r in rows]
    urls, labels, srcs, dates, origins = zip(*rows, strict=True)
    df = to_schema(
        pd.Series(urls),
        pd.Series(labels),
        pd.Series(srcs),
        dates=pd.Series(dates),
        origin=pd.Series([o or "" for o in origins]),
    ).drop(columns="html")
    return df.assign(
        row_id=range(len(df)),
        uid=[f"{s}:{i}" for i, s in enumerate(srcs)],
        html_simhash=pd.array([None] * len(df), dtype="Int64"),
        has_html=False,
    )


def test_shared_phishing_domains_only_counts_phishing_rows():
    df = meta(
        [
            ("https://a.web.app/x", 1, "phreshphish"),
            ("https://b.web.app/y", 1, "phishpedia"),  # same U1 domain, other phishing source
            ("https://bit.ly/abc", 1, "phreshphish"),
            ("https://bit.ly/abc2", 0, "phiusiil"),  # benign in another source: not "shared"
            ("https://evil.xyz/", 1, "phreshphish"),
            ("https://evil.xyz/2", 1, "phreshphish"),
        ]
    )
    assert shared_phishing_domains(df) == {"web.app"}


def test_domain_owner_is_earliest_then_priority():
    df = meta(
        [
            ("https://site.com/a", 0, "phiusiil"),  # undated: counts as latest
            ("https://site.com/b", 0, "live", "2026-10-01"),
            ("https://other.com/a", 0, "urlphish"),
            ("https://other.com/b", 0, "phiusiil"),
        ]
    )
    out = assign_domain_owner(df, ["live", "urlphish", "phiusiil"])
    assert sorted(zip(out["domain"], out["source"], strict=True)) == [
        ("other.com", "urlphish"),
        ("site.com", "live"),
    ]


def test_cap_per_domain_is_seeded():
    df = meta([(f"https://big.com/p{i}", 0, "s") for i in range(30)] + [("https://x.com/", 0, "s")])
    a = cap_per_domain(df, 20, seed=1)
    assert (a["domain"] == "big.com").sum() == 20 and (a["domain"] == "x.com").sum() == 1
    assert a.index.equals(cap_per_domain(df, 20, seed=1).index)
    assert not a.index.equals(cap_per_domain(df, 20, seed=2).index)


HOLDOUT_CFG = {
    "heldout_source": "phish360",
    "eval_only_sources": ["natural_legit"],
    "time_slice": {"origins": ["hf_test"], "sources": {"live": {"newest_fraction": 0.5}}},
}


def test_carve_holdouts_and_overlap_drop():
    df = meta(
        [
            ("https://p.com/a", 1, "phreshphish", "2025-01-01", "hf_train"),
            ("https://q.com/a", 1, "phreshphish", "2025-06-01", "hf_test"),
            ("https://h.com/a", 1, "phish360"),
            ("https://h.com/b", 0, "phiusiil"),  # shares a domain with the held-out source
            ("https://n.org/x/y", 0, "natural_legit"),
            ("https://l1.xyz/", 1, "live", "2026-10-01"),
            ("https://l2.xyz/", 1, "live", "2026-10-02"),
            ("https://l3.xyz/", 1, "live", "2026-10-03"),
            ("https://l4.xyz/", 1, "live", "2026-10-04"),
        ]
    )
    part = carve_holdouts(df, HOLDOUT_CFG).tolist()
    assert part == [
        POOL,
        TIME_SLICE,
        HELDOUT,
        DROPPED_OVERLAP,
        EVAL_ONLY,
        POOL,
        POOL,
        TIME_SLICE,
        TIME_SLICE,
    ]


def test_depth_bucket_tops_out():
    assert depth_bucket(pd.Series([0, 1, 3, 4, 9]), 4).tolist() == ["0", "1", "3", "4+", "4+"]


def _homepage_heavy() -> pd.DataFrame:
    """Benign is mostly bare homepages, phishing mostly deep: the PhiUSIIL shortcut."""
    rows = [(f"https://www.legit{i}.com", 0, "phiusiil") for i in range(100)]
    rows += [(f"https://ph{i}.xyz", 1, "phreshphish") for i in range(10)]
    rows += [(f"https://ph{i}.xyz/a/b", 1, "phreshphish") for i in range(100, 200)]
    rows += [(f"https://deep{i}.com/a/b", 0, "phreshphish") for i in range(30)]
    return meta(rows)


def test_check_depth_fails_on_homepage_shortcut_and_balance_fixes_it():
    df = _homepage_heavy()
    check = check_depth(df, DEPTH_CFG)
    assert not check["passed"]
    assert set(check["bad_buckets"]) == {"0"}  # 100 benign vs 10 phishing = 90.9%
    balanced = balance_depth(df, DEPTH_CFG, seed=0)
    t = check_depth(balanced, DEPTH_CFG)
    assert t["passed"]
    b0 = balanced.loc[balanced["depth"] == 0, "label"].value_counts()
    assert b0[0] == 40 and b0[1] == 10  # benign homepages cut to 80% of the bucket
    with pytest.raises(DepthImbalanceError, match="0"):
        enforce_depth(check)


def test_balance_leaves_buckets_with_tiny_minority_for_the_check():
    rows = [(f"https://www.l{i}.com", 0, "s") for i in range(100)]
    rows += [(f"https://p{i}.xyz", 1, "s") for i in range(2)]  # minority below min_minority
    df = meta(rows)
    assert len(balance_depth(df, DEPTH_CFG, seed=0)) == len(df)
    assert not check_depth(df, DEPTH_CFG)["passed"]


def test_source_weights_cap_share_and_balance_classes():
    rows = [(f"https://a{i}.com/x", i % 2, "big") for i in range(800)]
    rows += [(f"https://b{i}.com/x", int(i < 20), "small") for i in range(200)]
    df = meta(rows)
    w = source_weights(df, max_source_share=0.6)
    assert w.mean() == pytest.approx(1.0)
    share = w.groupby(df["source"]).sum() / w.sum()
    assert share["big"] == pytest.approx(0.6)
    small = df["source"] == "small"
    by_class = w[small].groupby(df.loc[small, "label"]).sum()
    assert by_class[0] == pytest.approx(by_class[1])  # 20 phish carry as much as 180 benign


def _corpus_cfg(**depth) -> dict:
    return {
        "corpus": {
            "seed": 0,
            "source_priority": ["live", "phreshphish", "phish360", "phiusiil", "natural_legit"],
            "max_urls_per_domain": 3,
            "max_source_share": 0.6,
            "depth": {**DEPTH_CFG, **depth},
        },
        "holdouts": HOLDOUT_CFG,
        "dedup": {
            "html_min_tokens": 20,
            "html_max_chars": 200_000,
            "shingle_size": 5,
            "simhash_max_hamming": 3,
            "near_dup_within_label_only": True,
        },
    }


def synthetic_meta(seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for d in range(120):
        lab = int(d % 2)
        tld = "xyz" if lab else "com"
        for k in range(int(rng.integers(1, 6))):
            rows.append(
                (f"https://s{k}.site{d}.{tld}/p/{k}", lab, "phreshphish", "2025-01-01", "hf_train")
            )
    rows += [(f"https://www.homepage{i}.edu", 0, "phiusiil") for i in range(40)]
    rows += [(f"https://ph{i}.top", 1, "phreshphish", "2025-02-01", "hf_train") for i in range(15)]
    rows += [
        (f"https://new{i}.xyz/a", 1, "phreshphish", "2025-09-01", "hf_test") for i in range(20)
    ]
    rows += [(f"https://h{i}.net/x", i % 2, "phish360") for i in range(20)]
    rows += [("https://a.web.app/x", 1, "phreshphish", "2025-01-01", "hf_train")]
    rows += [("https://b.web.app/y", 1, "phish360")]
    rows += [("https://site0.com/p/0", 1, "phish360")]  # conflicting label with phreshphish
    return meta(rows)


def test_build_corpus_end_to_end():
    m = synthetic_meta()
    corpus, stats = build_corpus(m, _corpus_cfg())
    assert set(corpus["part"]) == {POOL, HELDOUT, TIME_SLICE}
    assert "web.app" not in set(corpus["domain"])  # in two phishing sources
    assert stats.shared_phishing_domains == 1
    assert corpus.groupby("domain").size().max() <= 3
    assert "url_dedup" in stats.removed and "domain_cap" in stats.removed
    assert stats.depth_check["passed"]
    pool = corpus[corpus["part"] == POOL]
    assert pool["weight"].mean() == pytest.approx(1.0)
    assert (corpus.loc[corpus["part"] != POOL, "weight"] == 1.0).all()
    for a in corpus["part"].unique():  # no domain in two parts
        for b in corpus["part"].unique():
            if a < b:
                da = set(corpus.loc[corpus["part"] == a, "domain"])
                assert not da & set(corpus.loc[corpus["part"] == b, "domain"])


def test_build_corpus_reports_failed_depth_check():
    m = synthetic_meta()
    m = m[~((m["source"] == "phreshphish") & (m["label"] == 0))]  # only homepage benign left
    _, stats = build_corpus(m, _corpus_cfg())
    assert not stats.depth_check["passed"]
