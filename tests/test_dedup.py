import random

import pandas as pd
import pytest

from data_pipeline.corpus import dedup_urls
from data_pipeline.dedup import (
    hamming,
    html_simhash,
    near_dup_clusters,
    near_dup_html,
    simhash,
    visible_tokens,
)
from phishdrift.schema import to_schema

WORDS = [f"word{i}" for i in range(400)]


def _page(seed: int, n: int = 200, edits: int = 0, base_seed: int | None = None) -> str:
    rng = random.Random(base_seed if base_seed is not None else seed)
    tokens = [rng.choice(WORDS) for _ in range(n)]
    erng = random.Random(seed)
    for _ in range(edits):
        tokens[erng.randrange(n)] = erng.choice(WORDS)
    return (
        "<html><head><script>var x=1;</script></head><body><p>"
        + " ".join(tokens)
        + "</p></body></html>"
    )


def _df(rows) -> pd.DataFrame:
    urls, labels, dates, html = zip(*rows, strict=True)
    df = to_schema(
        pd.Series(urls), pd.Series(labels), "t", dates=pd.Series(dates), html=pd.Series(html)
    )
    return df.assign(
        row_id=range(len(df)),
        uid=[f"t:{i}" for i in range(len(df))],
        html_simhash=pd.array([html_simhash(h, CFG) for h in df["html"]], dtype="Int64"),
    )


CFG = {
    "html_min_tokens": 20,
    "html_max_chars": 200_000,
    "shingle_size": 5,
    "simhash_max_hamming": 3,
    "near_dup_within_label_only": True,
}


def test_visible_tokens_skip_scripts_and_tags():
    html = "<script>secret()</script><style>.a{}</style><p>Hello &amp; World</p><!-- hidden -->"
    assert visible_tokens(html, 10_000) == ["hello", "world"]


def test_simhash_identical_and_different():
    a = simhash(visible_tokens(_page(1), 10**6), 5)
    assert a == simhash(visible_tokens(_page(1), 10**6), 5)
    b = simhash(visible_tokens(_page(2), 10**6), 5)
    assert hamming(a, b) > 10


def test_simhash_is_close_for_small_edit():
    a = simhash(visible_tokens(_page(1, n=2000), 10**6), 5)
    b = simhash(visible_tokens(_page(99, n=2000, edits=1, base_seed=1), 10**6), 5)
    assert hamming(a, b) <= 3


def test_short_or_missing_html_not_hashed():
    assert html_simhash(None, CFG) is None
    assert html_simhash("<p>too short</p>", CFG) is None


def test_url_dedup_keeps_earliest_across_sources():
    df = _df(
        [
            ("https://evil.xyz/login", 1, "2025-03-01", None),
            ("HTTPS://www.EVIL.xyz:443/login/#x", 1, "2025-01-01", None),
            ("https://evil.xyz/other", 1, "2025-02-01", None),
        ]
    )
    df.loc[1, "source"] = "other"
    out = dedup_urls(df, ["t", "other"])
    assert len(out) == 2
    kept = out.loc[out["url"].str.contains("login", case=False)]
    assert kept["date"].iloc[0] == pd.Timestamp("2025-01-01", tz="UTC")
    assert kept["source"].iloc[0] == "other"


def test_url_dedup_ties_go_to_source_priority():
    df = _df([("https://a.com/x", 1, None, None), ("http://a.com/x", 1, None, None)])
    df["source"] = ["low", "high"]
    out = dedup_urls(df, ["high", "low"])
    assert out["source"].tolist() == ["high"]


def test_conflicting_labels_dropped():
    df = _df(
        [
            ("https://a.com/x", 1, "2025-01-01", None),
            ("http://www.a.com/x", 0, "2025-01-02", None),
            ("https://b.com/", 0, "2025-01-01", None),
        ]
    )
    out = dedup_urls(df, ["t"])
    assert out["url"].tolist() == ["https://b.com/"]


def test_near_duplicate_html_removed_within_label():
    big = _page(1, n=2000)
    near = _page(7, n=2000, edits=1, base_seed=1)
    df = _df(
        [
            ("https://kit2.xyz/b", 1, "2025-01-01", big),
            ("https://other.xyz/c", 1, "2025-01-03", _page(3, n=2000)),
            ("https://kit1.xyz/a", 1, "2025-01-05", near),
        ]
    )
    out, n = near_dup_html(df, CFG)
    assert n == 1
    assert set(out["url"]) == {"https://kit2.xyz/b", "https://other.xyz/c"}  # first kept


def test_phish_cloning_benign_page_is_kept():
    page = _page(5, n=500)
    df = _df(
        [
            ("https://realbank.com/login", 0, "2025-01-01", page),
            ("https://realbank-login.xyz/", 1, "2025-01-02", page),
        ]
    )
    out, n = near_dup_html(df, CFG)
    assert n == 0 and len(out) == 2


def test_cross_label_dedup_when_configured():
    page = _page(5, n=500)
    df = _df(
        [
            ("https://realbank.com/login", 0, "2025-01-01", page),
            ("https://realbank-login.xyz/", 1, "2025-01-02", page),
        ]
    )
    _, n = near_dup_html(df, {**CFG, "near_dup_within_label_only": False})
    assert n == 1


def test_pages_without_html_are_untouched():
    df = _df([("https://a.com/", 0, None, None), ("https://b.com/", 0, None, None)])
    out, n = near_dup_html(df, CFG)
    assert n == 0 and len(out) == 2


def test_clusters_are_transitive_and_band_limit_enforced():
    a = 0
    b = a ^ 0b111  # distance 3 from a
    c = b ^ (0b111 << 20)  # distance 3 from b, 6 from a
    roots = near_dup_clusters([a, b, c, 1 << 63 | 0xFFFF_0000], 3)
    assert roots[a] == roots[b] == roots[c]
    with pytest.raises(ValueError):
        near_dup_clusters([a], 4)
