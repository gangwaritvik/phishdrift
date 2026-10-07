import json
from datetime import UTC, date, datetime

import pandas as pd
import requests

from collector import __main__ as collector_main
from collector import benign, domain_capture, feeds, store
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


def test_parse_phishing_database_list(fixtures):
    df = feeds.parse_url_list(
        (fixtures / "phishing_database_new_today.txt").read_text(), "phishing_database"
    )
    assert df["url"].tolist() == [
        "https://secure-login-hdfc.xyz/verify",
        "http://paypa1-account.top/signin",
        "https://wallet-connect-sync.web.app/",
    ]
    assert (df["source"] == "phishing_database").all() and (df["label"] == 1).all()


# --- crawler ---------------------------------------------------------------------------

UA = "PhishDrift-research-collector/0.2 (test)"
PAGE = "<html><body>" + " ".join(f"<p>text {i}</p>" for i in range(30)) + "</body></html>"


class FakeClient:
    """Serves bytes from a dict; missing URLs are 404s. Records requests."""

    def __init__(self, pages: dict[str, bytes | int]):
        self.pages = pages
        self.user_agent = UA
        self.calls: list[tuple[str, float | None]] = []

    def get(self, url, *, cache_ttl_s=0, headers=None, max_bytes=None, min_interval_s=None):
        self.calls.append((url, min_interval_s))
        body = self.pages.get(url, 404)
        if isinstance(body, int):
            resp = requests.Response()
            resp.status_code = body
            raise requests.HTTPError(f"{body}", response=resp)
        return body


CRAWL_CFG = {
    "inner_pages_min": 3,
    "inner_pages_max": 5,
    "max_sitemaps_per_domain": 2,
    "max_page_bytes": 1_000_000,
    "store_html": True,
    "max_crawl_delay_s": 10,
}


def test_robots_rules_delay_and_sitemaps(fixtures):
    robots = benign.parse_robots((fixtures / "robots.txt").read_text(), UA)
    assert robots.allowed("https://example.org/about")
    assert not robots.allowed("https://example.org/private/admin")
    assert robots.crawl_delay == 2.0
    assert robots.sitemaps == [
        "https://example.org/sitemap_index.xml",
        "https://example.org/news-sitemap.xml",
    ]
    assert not benign.parse_robots((fixtures / "robots.txt").read_text(), "BadBot/1.0").allowed(
        "https://example.org/about"
    )


def test_missing_robots_conventions():
    assert benign.parse_robots(None, UA, status=404).allowed("https://x.com/a")
    assert not benign.parse_robots(None, UA, status=403).allowed("https://x.com/a")
    assert (
        benign.fetch_robots(FakeClient({"https://x.com/robots.txt": 503}), "https://x.com/", 10)
        is None
    )


def test_sitemap_parsing(fixtures):
    locs, is_index = benign.parse_sitemap_locs((fixtures / "sitemap.xml").read_text())
    assert not is_index and len(locs) == 7
    _, is_index = benign.parse_sitemap_locs("<sitemapindex><sitemap><loc>x</loc></sitemap>")
    assert is_index


def test_select_inner_pages_obeys_robots(fixtures):
    robots = benign.parse_robots((fixtures / "robots.txt").read_text(), UA)
    locs, _ = benign.parse_sitemap_locs((fixtures / "sitemap.xml").read_text())
    pages = benign.select_inner_pages(locs, "https://example.org/", k=10, seed=1, robots=robots)
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


def _site(fixtures) -> dict:
    sitemap = (fixtures / "sitemap.xml").read_bytes()
    return {
        "https://example.org/robots.txt": (fixtures / "robots.txt").read_bytes(),
        "https://example.org/sitemap_index.xml": sitemap,
        "https://example.org/": PAGE.encode(),
        "https://example.org/about": PAGE.encode(),
        "https://example.org/blog/post-1?ref=home": PAGE.encode(),
        "https://www.example.org/contact": 404,  # dead sitemap entry: dropped
        "https://example.org/private/admin": PAGE.encode(),
    }


def test_crawl_domain_respects_robots_and_delay(fixtures):
    client = FakeClient(_site(fixtures))
    res = benign.crawl_domain(client, "example.org", CRAWL_CFG, seed=0, include_homepage=False)
    urls = [p["url"] for p in res.pages]
    assert sorted(urls) == ["https://example.org/about", "https://example.org/blog/post-1?ref=home"]
    assert res.status == benign.FEW_PAGES  # 2 < inner_pages_min
    assert all(p["html"] == PAGE for p in res.pages)
    fetched = [u for u, _ in client.calls]
    assert "https://example.org/private/admin" not in fetched
    assert all(delay == 2.0 for u, delay in client.calls if not u.endswith("robots.txt"))


def test_crawl_domain_skips_long_crawl_delay_and_blocked_sites():
    slow = FakeClient({"https://slow.com/robots.txt": b"User-agent: *\nCrawl-delay: 60\n"})
    res = benign.crawl_domain(slow, "slow.com", CRAWL_CFG, 0, include_homepage=True)
    assert res.status == benign.CRAWL_DELAY_TOO_LONG and len(slow.calls) == 1
    blocked = FakeClient({"https://no.com/robots.txt": b"User-agent: *\nDisallow: /\n"})
    res = benign.crawl_domain(blocked, "no.com", CRAWL_CFG, 0, include_homepage=True)
    assert res.status == benign.ROBOTS_DISALLOW_ALL and res.pages == []
    assert [u for u, _ in blocked.calls] == ["https://no.com/robots.txt"]


def test_crawl_domain_falls_back_to_homepage_links():
    html = "".join(f'<a href="/section/{i}">s</a>' for i in range(8))
    pages = {"https://site.com/robots.txt": 404, "https://site.com/": html.encode()}
    pages.update({f"https://site.com/section/{i}": PAGE.encode() for i in range(8)})
    res = benign.crawl_domain(FakeClient(pages), "site.com", CRAWL_CFG, 0, include_homepage=True)
    assert res.status == benign.OK
    assert res.pages[0]["url"] == "https://site.com/" and len(res.pages) == 1 + 5


def test_crawl_run_uses_seed_file_and_moves_on(tmp_path, fixtures):
    seed_dir, crawl_dir = tmp_path / "seeds", tmp_path / "crawl"
    seed_dir.mkdir()
    (seed_dir / "phiusiil.txt").write_text("example.org\nother.edu\n")
    cfg = {
        **CRAWL_CFG,
        "seeds": {
            "phiusiil": {"from": "seed_file", "domains_per_run": 1, "include_homepage": False}
        },
    }
    client = FakeClient({**_site(fixtures), "https://other.edu/robots.txt": 503})
    now = datetime(2026, 10, 7, 6, 15, tzinfo=UTC)
    first = benign.crawl(client, cfg, crawl_dir, seed_dir, now)
    second = benign.crawl(client, cfg, crawl_dir, seed_dir, now)
    tried = store.load_attempts(crawl_dir)
    assert sorted(tried["seed_domain"]) == ["example.org", "other.edu"]  # no domain twice
    assert first["phiusiil"]["domains"] == second["phiusiil"]["domains"] == 1
    pages = store.load_crawl(crawl_dir)
    assert set(pages["seed_source"]) == {"phiusiil"} and len(pages) == 2
    assert set(pages["seed_domain"]) == {"example.org"}
    assert benign.crawl(client, cfg, crawl_dir, seed_dir, now)["phiusiil"]["domains"] == 0


def test_missing_seed_file_is_reported_not_fatal(tmp_path):
    cfg = {
        **CRAWL_CFG,
        "seeds": {
            "urlphish": {"from": "seed_file", "domains_per_run": 5, "include_homepage": False}
        },
    }
    now = datetime(2026, 10, 7, tzinfo=UTC)
    assert benign.crawl(FakeClient({}), cfg, tmp_path / "c", tmp_path / "s", now) == {}


def test_sample_domains_is_seeded_and_excludes():
    domains = [f"d{i}.com" for i in range(50)]
    a = benign.sample_domains(domains, 10, seed=1, exclude={"d0.com"})
    assert a == benign.sample_domains(domains, 10, seed=1, exclude={"d0.com"})
    assert "d0.com" not in a and len(a) == 10
    assert benign.run_seed(date(2026, 10, 7), "live") != benign.run_seed(date(2026, 10, 8), "live")


# --- feeds -> stores -------------------------------------------------------------------


def test_blocklist_feeds_never_reach_training(tmp_path, monkeypatch):
    cfg = {
        "paths": {"raw_dir": str(tmp_path / "raw"), "blocklist_dir": str(tmp_path / "block")},
        "feeds": {
            "openphish": {"role": "training"},
            "urlhaus": {"role": "blocklist"},
            "phishtank": {"role": "training"},
        },
    }
    monkeypatch.setitem(
        feeds.FETCHERS, "openphish", lambda c, f: _batch(["https://p.xyz/"], [1], ["openphish"])
    )
    monkeypatch.setitem(
        feeds.FETCHERS,
        "urlhaus",
        lambda c, f: _batch(["http://m.xyz/a.sh"], [1], ["urlhaus"], "malware"),
    )
    monkeypatch.setitem(feeds.FETCHERS, "phishtank", lambda c, f: None)  # no key
    batch, failures = collector_main.collect_feeds(None, cfg, datetime(2026, 10, 7, tzinfo=UTC))
    assert failures == 0 and batch["url"].tolist() == ["https://p.xyz/"]
    assert (tmp_path / "block" / "2026-10-07" / "urlhaus.parquet").exists()
    assert not (tmp_path / "raw" / "2026-10-07" / "urlhaus.parquet").exists()


def test_capture_targets_put_phishing_first():
    t = pd.Timestamp("2026-10-07", tz="UTC")
    new = pd.DataFrame(
        {"url": ["https://ok.com/", "https://p.xyz/a"], "label": [0, 1], "first_seen": [t, t]}
    )
    targets = collector_main.capture_targets(new, {"live": {"domains_with_pages": ["news.com"]}})
    assert [x["url"] for x in targets] == [
        "https://p.xyz/a",
        "https://ok.com/",
        "https://news.com/",
    ]


# --- domain capture --------------------------------------------------------------------


def test_parse_rdap(fixtures):
    rdap = domain_capture.parse_rdap(json.loads((fixtures / "rdap_domain.json").read_text()))
    assert rdap["registered"] == "2026-10-05T11:20:00Z"
    assert rdap["expires"] == "2027-10-05T23:59:59Z"
    assert rdap["registrar"] == "NameSilo, LLC"
    assert rdap["nameservers"] == ["ns1.dnsowl.com", "ns2.dnsowl.com"]
    assert rdap["redacted"] is True


def test_parse_cert():
    cert = {
        "subject": ((("commonName", "secure-login.xyz"),),),
        "issuer": (
            (("countryName", "US"),),
            (("organizationName", "Let's Encrypt"),),
            (("commonName", "R11"),),
        ),
        "notBefore": "Oct  5 11:00:00 2026 GMT",
        "notAfter": "Jan  3 11:00:00 2027 GMT",
        "subjectAltName": (("DNS", "secure-login.xyz"), ("DNS", "www.secure-login.xyz")),
    }
    out = domain_capture.parse_cert(cert)
    assert out["issuer_o"] == "Let's Encrypt" and out["issuer_cn"] == "R11"
    assert out["subject_cn"] == "secure-login.xyz" and out["san_count"] == 2
    assert out["not_before"].startswith("2026-10-05T11:00:00")


def _fake_dns(records: dict):
    def query(name, rdtype):
        value = records.get((name, rdtype), [])
        if isinstance(value, Exception):
            raise value
        return value

    return query


def test_dns_facts():
    q = _fake_dns(
        {
            ("login.evil.xyz", "A"): [("192.0.2.1", 300)],
            ("evil.xyz", "NS"): [("ns1.host.net.", 3600)],
            ("evil.xyz", "TXT"): [('"v=spf1 -all"', 600)],
            ("evil.xyz", "MX"): TimeoutError("slow"),
        }
    )
    out = domain_capture.dns_facts("login.evil.xyz", "evil.xyz", q)
    assert out["resolves"] and out["a"] == ["192.0.2.1"] and out["ns"] == ["ns1.host.net"]
    assert out["spf"] and not out["dmarc"] and out["mx_count"] == 0
    assert out["min_ttl"] == 300 and out["errors"] == ["MX:TimeoutError"]


def test_capture_once_per_host_and_domain(tmp_path, fixtures):
    rdap_body = (fixtures / "rdap_domain.json").read_bytes()
    client = FakeClient({"https://rdap.example/domain/evil.xyz": rdap_body})
    cfg = {
        "max_domains_per_run": 10,
        "rdap_url": "https://rdap.example/domain/{domain}",
        "dns_timeout_s": 1,
        "tls": True,
        "tls_timeout_s": 1,
    }
    t = pd.Timestamp("2026-10-07", tz="UTC")
    targets = [
        {"url": "https://a.evil.xyz/login", "label": 1, "first_seen": t},
        {"url": "https://b.evil.xyz/x", "label": 1, "first_seen": t},
        {"url": "http://192.0.2.7/bank", "label": 1, "first_seen": t},
    ]
    now = datetime(2026, 10, 7, tzinfo=UTC)
    fake_tls = lambda host, timeout: {"ok": False, "error": "test"}  # noqa: E731
    out = domain_capture.capture(targets, client, cfg, tmp_path, now, _fake_dns({}), fake_tls)
    assert out == {"hosts": 3, "domains": 2}
    rdap_calls = [u for u, _ in client.calls if "rdap" in u]
    assert rdap_calls == ["https://rdap.example/domain/evil.xyz"]  # once per domain, none for IP
    recs = [json.loads(x) for x in (tmp_path / "2026-10-07.jsonl").read_text().splitlines()]
    dom = next(r for r in recs if r["kind"] == "domain" and r["domain"] == "evil.xyz")
    assert dom["rdap"]["registrar"] == "NameSilo, LLC"
    ip = next(r for r in recs if r.get("host") == "192.0.2.7")
    assert ip["dns"] is None
    again = domain_capture.capture(targets, client, cfg, tmp_path, now, _fake_dns({}), fake_tls)
    assert again == {"hosts": 0, "domains": 0}


def test_capture_respects_per_run_cap(tmp_path):
    cfg = {
        "max_domains_per_run": 2,
        "rdap_url": "https://rdap.example/domain/{domain}",
        "dns_timeout_s": 1,
        "tls": False,
        "tls_timeout_s": 1,
    }
    targets = [{"url": f"https://s{i}.xyz/", "label": 1, "first_seen": None} for i in range(5)]
    now = datetime(2026, 10, 7, tzinfo=UTC)
    out = domain_capture.capture(targets, FakeClient({}), cfg, tmp_path, now, _fake_dns({}))
    assert out["hosts"] == 2
    recs = [json.loads(x) for x in (tmp_path / "2026-10-07.jsonl").read_text().splitlines()]
    assert {r["rdap_error"] for r in recs if r["kind"] == "domain"} == {"not_found"}


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
        idx,
        _batch(["https://a.xyz/x", "https://c.xyz/"], [1, 1], ["phishing_database", "openphish"]),
        t2,
    )
    assert n_new == 1 and len(idx) == 3
    row = idx.set_index("url_norm").loc["https://a.xyz/x"]
    assert row["first_seen"] == t1 and row["last_seen"] == t2
    assert row["sources"] == "openphish,phishing_database,phishtank"


def test_index_flags_label_conflicts():
    t = pd.Timestamp("2026-10-07", tz="UTC")
    idx, _ = store.update_index(store.empty_index(), _batch(["https://x.com/"], [0], ["other"]), t)
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
