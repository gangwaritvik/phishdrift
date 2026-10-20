import numpy as np

from phishguard.analyze import holds, verdict
from phishguard.data import assign_split, family, represent
from phishguard.run import depth_weights

CFG = {
    "holds": {"min_splits_same_sign": 9, "ci": 0.95},
    "verdict": {"replicated": 0.8, "partly": 0.5, "min_settings": 3},
}


def test_represent_ladder():
    url, dom = "http://www.shop.example.co.uk/a/b?x=1", "example.co.uk"
    assert represent(url, dom, "R1", frozenset()) == url
    assert represent(url, dom, "R2", frozenset()) == "https://shop.example.co.uk"  # no www
    assert represent(url, dom, "R3", frozenset()) == "https://shop.example.co.uk"
    assert represent(url, dom, "R4", frozenset()) == "https://www.example.co.uk"


def test_split_is_grouped_and_stable():
    doms = np.array(["a.com", "b.com", "a.com", "c.com"] * 50)
    s1 = assign_split(doms, 42, 3, {"train": 0.7, "cal": 0.1})
    s2 = assign_split(doms, 42, 3, {"train": 0.7, "cal": 0.1})
    assert (s1 == s2).all()
    for d in set(doms):
        assert len(set(s1[doms == d])) == 1


def test_holds_and_verdict():
    eff = np.full(10, 0.2)
    assert holds(eff, np.random.default_rng(0).normal(0.2, 0.01, 500), CFG, 1)[0]
    assert not holds(np.r_[np.full(8, 0.2), -0.1, -0.1], np.full(100, 0.2), CFG, 1)[0]
    assert not holds(eff, np.random.default_rng(0).normal(0.0, 0.1, 500), CFG, 1)[0]
    assert verdict([True] * 8 + [False] * 2, CFG) == "replicated"
    assert verdict([True] * 6 + [False] * 4, CFG) == "partly replicated"
    assert verdict([True, False], CFG) == "not testable"


def test_depth_weights_balance_strata():
    depth = np.array([0, 0, 0, 1, 1, 5, 0, 1, 1, 1])
    y = np.array([1, 1, 1, 1, 1, 1, 0, 0, 0, 0])
    w = depth_weights(depth, y)
    assert w[5] == 0  # depth 3+ has no benign row
    for c in (0, 1):
        m = (y == c) & (w > 0)
        assert np.isclose(w[m & (depth == 0)].sum() / w[m].sum(), 4 / 9)


def test_crawl_family_covers_seed_sources():
    assert {"phiusiil", "urlphish"} <= family("benign:crawl")
    assert family("phish:phreshphish") == {"phreshphish"}
