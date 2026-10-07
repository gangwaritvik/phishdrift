import io
import zipfile
from datetime import date

import pandas as pd

from collector import benign, feeds, store
from phishdrift.http import HttpClient


def test_parse_openphish(fixtures):
    df = feeds.parse_openphish((fixtures / "openphish_feed.txt").read_text())
    assert len(df) == 3
    assert list(df.columns) == feeds.FEED_COLUMNS
    assert (df["label"] == 1).all() and (df["threat"] == "phishing").all()


def test_parse_phishtank_keeps_verified_only(fixtures):
    df = feeds.parse_phishtank((fixtures / "phishtank_online_valid.csv").read_bytes())
    assert df["url"].tolist() == ["https://hdfc-netbanking-alert.xyz/login"]
    assert df["target"].tolist() == ["HDFC Bank"]
    assert df["feed_time"].iloc[0] == pd.Timestamp("2026-10-06T10:00:00", tz="UTC")


def test_parse_urlhaus_skips_comments_and_tags_malware(fixtures):
    df = feeds.parse_urlhaus((fixtures / "urlhaus_recent.csv").read_text())
    assert len(df) == 2
    assert (df["threat"] == "malware").all()
    assert df["feed_time"].notna().all()


def test_phishtank_skipped_without_key(monkeypatch):
    monkeypatch.delenv("PHISHTANK_APP_KEY", raising=False)
    assert feeds.fetch_phishtank(None, {"key_env": "PHISHTANK_APP_KEY"}) is None


def test_tranco_zip_and_seeded_sample():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("top-1m.csv", "\n".join(f"{i},site{i}.com" for i in range(1, 101)))
    ranked = benign.parse_tranco_zip(buf.getvalue())
    assert ranked[:2] == ["site1.com", "site2.com"] and len(ranked) == 100
    a = benign.sample_domains(ranked, top_n=50, k=10, day=date(2026, 10, 7))
    assert a == benign.sample_domains(ranked, top_n=50, k=10, day=date(2026, 10, 7))
    assert a != benign.sample_domains(ranked, top_n=50, k=10, day=date(2026, 10, 8))
    assert all(rank <= 50 for rank, _ in a)


def test_robots_and_sitemap_parsing(fixtures):
    sitemaps = benign.parse_robots_sitemaps((fixtures / "robots.txt").read_text())
    assert sitemaps == [
        "https://example.org/sitemap_index.xml",
        "https://example.org/news-sitemap.xml",
    ]
    locs, is_index = benign.parse_sitemap_locs((fixtures / "sitemap.xml").read_text())
    assert not is_index and len(locs) == 6
    _, is_index = benign.parse_sitemap_locs("<sitemapindex><sitemap><loc>x</loc></sitemap>")
    assert is_index


def test_select_inner_pages_filters(fixtures):
    locs, _ = benign.parse_sitemap_locs((fixtures / "sitemap.xml").read_text())
    pages = benign.select_inner_pages(locs, "https://example.org/", k=10, seed=1)
    assert sorted(pages) == [
        "https://example.org/about",
        "https://example.org/blog/post-1?ref=home",
        "https://www.example.org/contact",
    ]
    assert len(benign.select_inner_pages(locs, "https://example.org/", k=1, seed=1)) == 1


def test_extract_same_site_links():
    html = (
        '<a href="/docs">d</a><a href="https://blog.example.org/p">b</a>'
        '<a href="https://other.com/x">o</a><a href="#top">t</a><a href="mailto:a@b.c">m</a>'
    )
    links = benign.extract_same_site_links(html, "https://example.org/")
    assert links == ["https://example.org/docs", "https://blog.example.org/p"]


def _batch(urls, labels, sources, threat="phishing"):
    n = len(urls)
    return pd.DataFrame(
        {
            "url": urls,
            "source": sources,
            "threat": [threat] * n,
            "label": pd.Series(labels, dtype="int8"),
            "feed_time": pd.Series(pd.NaT, index=range(n), dtype="datetime64[ns, UTC]"),
            "target": [None] * n,
        }
    )


def test_index_keeps_first_seen_and_merges_sources():
    t1 = pd.Timestamp("2026-10-06T00:00:00", tz="UTC")
    t2 = pd.Timestamp("2026-10-07T00:00:00", tz="UTC")
    idx, n_new = store.update_index(
        store.empty_index(),
        _batch(
            ["https://a.xyz/x", "HTTPS://A.xyz/x#f", "https://b.xyz/"],
            [1, 1, 1],
            ["openphish", "phishtank", "openphish"],
        ),
        t1,
    )
    assert n_new == 2 and len(idx) == 2
    assert idx.set_index("url_norm").loc["https://a.xyz/x", "sources"] == "openphish,phishtank"

    idx, n_new = store.update_index(
        idx, _batch(["https://a.xyz/x", "https://c.xyz/"], [1, 1], ["urlhaus", "openphish"]), t2
    )
    assert n_new == 1 and len(idx) == 3
    row = idx.set_index("url_norm").loc["https://a.xyz/x"]
    assert row["first_seen"] == t1 and row["last_seen"] == t2
    assert row["sources"] == "openphish,phishtank,urlhaus"


def test_index_flags_label_conflicts():
    t = pd.Timestamp("2026-10-07", tz="UTC")
    idx, _ = store.update_index(store.empty_index(), _batch(["https://x.com/"], [0], ["tranco"]), t)
    idx, _ = store.update_index(idx, _batch(["https://x.com/"], [1], ["openphish"]), t)
    row = idx.iloc[0]
    assert bool(row["label_conflict"]) and row["label"] == 1


def test_index_roundtrip(tmp_path):
    t = pd.Timestamp("2026-10-07", tz="UTC")
    idx, _ = store.update_index(
        store.empty_index(), _batch(["https://a.xyz/"], [1], ["openphish"]), t
    )
    path = tmp_path / "index.parquet"
    store.save_index(idx, path)
    back = store.load_index(path)
    assert back["first_seen"].iloc[0] == t
    assert store.write_daily(idx, tmp_path / "raw", date(2026, 10, 7), "openphish").exists()


class _FakeResp:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def raise_for_status(self):
        pass

    def iter_content(self, n):
        yield self.body


def test_http_client_caches_and_hides_url(tmp_path, monkeypatch):
    client = HttpClient(cache_dir=tmp_path, default_min_interval_s=0)
    calls = []
    monkeypatch.setattr(
        client._session, "get", lambda url, **kw: calls.append(url) or _FakeResp(b"hello")
    )
    url = "http://feed.example/data/SECRETKEY/x.csv"
    assert client.get(url, cache_ttl_s=60) == b"hello"
    assert client.get(url, cache_ttl_s=60) == b"hello"
    assert len(calls) == 1
    assert client.last_fetch_time(url) is not None
    assert all("SECRETKEY" not in p.read_text(errors="ignore") for p in tmp_path.glob("*.json"))
    client.get(url)  # ttl 0 bypasses the cache
    assert len(calls) == 2
