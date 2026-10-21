"""Popular-sites seed sets: CrUX hosts, Common Crawl index URLs, run by name."""

import gzip
import json
from datetime import UTC, datetime

import requests

from collector import benign, popular, store
from data_pipeline.sources import crawl_frame, crawl_seed_names
from tests.test_collector import CRAWL_CFG, PAGE, _site

NOW = datetime(2026, 10, 20, 9, 0, tzinfo=UTC)

CRUX = "\n".join(
    [
        "origin,rank",
        "https://www.top.com,1000",  # head: skipped
        "https://shop.example.org,5000",
        "https://example.org,10000",  # same domain, worse rank
        "https://blog.newsy.net,10000",
        "https://stitch.withgoogle.com,50000",
        "https://withgoogle.com,5000",  # the platform itself
        "https://other.withgoogle.com,5000",
        "https://t.co,5000",  # shortener
        "https://seen.com,5000",  # domain already in the corpus
        "https://a.github.io,5000",  # feed phishing on github.io must not hide its tenants
        "http://plain.org,5000",  # not https
        "https://1.2.3.4,5000",
        "https://host.com:8443,5000",
        "https://far.com,500000",  # beyond max_rank
    ]
)


def test_parse_crux_keeps_best_rank_and_drops_odd_hosts():
    rows = dict(popular.parse_crux(CRUX, skip_rank=1000, max_rank=100000))
    assert rows["shop.example.org"] == 5000 and rows["example.org"] == 10000
    assert "www.top.com" not in rows and "far.com" not in rows
    assert not {"plain.org", "1.2.3.4", "host.com:8443", "host.com"} & set(rows)


def test_select_hosts_is_seeded_one_per_domain_and_keeps_tenants():
    rows = popular.parse_crux(CRUX, 1000, 100000)
    kw = {
        "exclude_domains": {"seen.com", "github.io"},
        "exclude_hosts": set(),
        "platforms": frozenset({"withgoogle.com", "github.io"}),
        "shorteners": frozenset({"t.co"}),
        "k": 50,
        "seed": 3,
    }
    got = popular.select_hosts(rows, **kw)
    assert got == popular.select_hosts(rows, **kw)
    assert sum(h.endswith("example.org") for h in got) == 1  # one host per ordinary domain
    assert {"stitch.withgoogle.com", "other.withgoogle.com", "a.github.io"} <= set(got)
    assert not {"withgoogle.com", "t.co", "seen.com"} & set(got)
    assert len(popular.select_hosts(rows, **{**kw, "k": 2})) == 2
    hidden = popular.select_hosts(rows, **{**kw, "exclude_hosts": {"a.github.io"}})
    assert "a.github.io" not in hidden


def test_parse_cdx_and_pick_urls_keep_deep_html_pages_of_the_host():
    lines = [
        {"url": "https://s.com/", "status": "200", "mime": "text/html"},
        {"url": "https://s.com/a/b", "status": "200", "mime": "text/html"},
        {"url": "https://s.com/a/b#x", "status": "200", "mime": "text/html"},
        {"url": "https://s.com/img.png", "status": "200", "mime": "image/png"},
        {"url": "https://s.com/gone", "status": "404", "mime": "text/html"},
        {"url": "https://s.com/file.pdf", "status": "200", "mime": "text/html"},
        {"url": "https://other.com/x", "status": "200", "mime": "text/html"},
        {"url": "http://s.com/p?id=7", "status": "200", "mime": "text/html"},
        {"url": "https://s.com:8080/y", "status": "200", "mime": "text/html"},
    ]
    text = "\n".join(json.dumps(x) for x in lines) + "\nnot json"
    urls = popular.parse_cdx(text)
    assert "https://s.com/gone" not in urls and "https://s.com/img.png" not in urls
    picked = popular.pick_urls(urls, "s.com", per_host=10, seed=1)
    assert sorted(picked) == ["https://s.com/a/b", "https://s.com/p?id=7"]
    assert len(popular.pick_urls(urls, "s.com", per_host=1, seed=1)) == 1


class CCClient:
    """Serves the index; records requests; accepts the keywords HttpClient.get takes."""

    def __init__(self, pages: dict[str, bytes | int]):
        self.pages = pages
        self.user_agent = "test"
        self.calls: list[str] = []

    def get(
        self,
        url,
        *,
        cache_ttl_s=0,
        headers=None,
        max_bytes=None,
        min_interval_s=None,
        timeout_s=None,
    ):
        self.calls.append(url)
        for prefix, body in self.pages.items():
            if url.startswith(prefix) or url == prefix:
                if isinstance(body, int):
                    resp = requests.Response()
                    resp.status_code = body
                    raise requests.HTTPError(str(body), response=resp)
                return body
        resp = requests.Response()
        resp.status_code = 404
        raise requests.HTTPError("404", response=resp)


def _cdx(host: str, n: int) -> bytes:
    return "\n".join(
        json.dumps({"url": f"https://{host}/news/{i}", "status": "200", "mime": "text/html"})
        for i in range(n)
    ).encode()


PCFG = {
    "commoncrawl": {
        "collections_url": "https://index.test/collinfo.json",
        "timeout_s": 5,
        "min_interval_s": 0,
        "fetch_limit": 300,
        "per_host": 4,
        "min_pages": 3,
    }
}
ENDPOINT = "https://index.test/CC-MAIN-2026-40-index"


def test_commoncrawl_pages_reads_a_random_index_page_and_caps_urls():
    client = CCClient(
        {
            f"{ENDPOINT}?url=big.com/*&output=json&fl=url,status,mime&showNumPages": json.dumps(
                {"pages": 7}
            ).encode(),
            f"{ENDPOINT}?url=big.com/*": _cdx("big.com", 20),
        }
    )
    res = popular.commoncrawl_pages(client, ENDPOINT, "big.com", PCFG, seed=5)
    assert res.status == benign.OK and len(res.pages) == 4
    assert all(
        p["html"] is None and p["url"].startswith("https://big.com/news/") for p in res.pages
    )
    page = int(client.calls[-1].split("&page=")[1].split("&")[0])
    assert 0 <= page < 7
    assert popular.commoncrawl_pages(client, ENDPOINT, "big.com", PCFG, seed=5).pages == res.pages


def test_commoncrawl_pages_reports_missing_and_failing_hosts():
    client = CCClient(
        {f"{ENDPOINT}?url=few.com": _cdx("few.com", 2), f"{ENDPOINT}?url=bad.com": 503}
    )
    few = popular.commoncrawl_pages(client, ENDPOINT, "few.com", PCFG, seed=1)
    assert few.status == benign.FEW_PAGES and len(few.pages) == 2
    assert (
        popular.commoncrawl_pages(client, ENDPOINT, "bad.com", PCFG, seed=1).status == benign.ERROR
    )
    assert (
        popular.commoncrawl_pages(client, ENDPOINT, "none.com", PCFG, seed=1).status
        == benign.NO_PAGES
    )


def test_latest_collection_takes_the_newest_endpoint():
    info = json.dumps([{"id": "CC-MAIN-2026-40", "cdx-api": ENDPOINT}, {"id": "old"}]).encode()
    client = CCClient({"https://index.test/collinfo.json": info})
    assert popular.latest_collection(client, PCFG) == ENDPOINT


def test_fetch_crux_falls_back_to_an_older_month():
    gz = gzip.compress(b"origin,rank\nhttps://shop.example.org,5000\n")
    client = CCClient({"https://crux.test/202608.csv.gz": gz})
    pcfg = {
        "origins_url": "https://crux.test/{month}.csv.gz",
        "months_back": 3,
        "cache_ttl_s": 1,
        "timeout_s": 5,
        "skip_rank": 1000,
        "max_rank": 100000,
    }
    assert popular.fetch_crux(client, pcfg, NOW) == [("shop.example.org", 5000)]
    assert client.calls[0].endswith("202609.csv.gz") and client.calls[1].endswith("202608.csv.gz")


def _crawl_cfg(tmp_path):
    return {
        **CRAWL_CFG,
        "workers": 2,
        "checkpoint_every": 1,
        "popular": {
            "origins_url": "https://crux.test/{month}.csv.gz",
            "months_back": 1,
            "cache_ttl_s": 1,
            "timeout_s": 5,
            "skip_rank": 1000,
            "max_rank": 100000,
            "seed": 1,
            **PCFG,
        },
        "popular_exclusions": (set(), set()),
        "popular_shorteners": frozenset(),
        "seeds": {
            "popular": {
                "from": "crux",
                "scheduled": False,
                "domains_per_run": 5,
                "include_homepage": False,
            },
            "commoncrawl": {
                "from": "commoncrawl",
                "source": "popular",
                "scheduled": False,
                "domains_per_run": 5,
                "include_homepage": False,
            },
            "live": {"from": "seed_file", "domains_per_run": 1, "include_homepage": False},
        },
    }


def test_popular_seed_sets_run_only_by_name_and_feed_one_source(tmp_path, fixtures):
    crux = gzip.compress(b"origin,rank\nhttps://example.org,5000\nhttps://cc.example.com,5000\n")
    pages = {
        **_site(fixtures),
        "https://crux.test/202609.csv.gz": crux,
        "https://index.test/collinfo.json": json.dumps([{"cdx-api": ENDPOINT}]).encode(),
        f"{ENDPOINT}?url=cc.example.com": _cdx("cc.example.com", 6),
    }
    pages["https://example.org/sitemap.xml"] = pages["https://example.org/sitemap_index.xml"]

    client = CCClient(pages)
    cfg = _crawl_cfg(tmp_path)
    crawl_dir, seed_dir = tmp_path / "crawl", tmp_path / "seeds"
    seed_dir.mkdir()
    (seed_dir / "live.txt").write_text("")
    assert set(benign.crawl(client, cfg, crawl_dir, seed_dir, NOW)) <= {"live"}  # not scheduled
    assert not any(c.startswith("https://crux.test") for c in client.calls)

    out = benign.crawl(client, cfg, crawl_dir, seed_dir, NOW, only=["popular", "commoncrawl"])
    assert set(out) == {"popular", "commoncrawl"}
    attempts = store.load_attempts(crawl_dir)
    assert set(attempts["seed_source"]) == {"popular", "commoncrawl"}
    assert (
        benign.crawl(client, cfg, crawl_dir, seed_dir, NOW, only=["popular"])["popular"]["domains"]
        == 0
    )

    crawl = store.load_crawl(crawl_dir)
    cc = crawl[crawl["seed_source"] == "commoncrawl"]
    assert len(cc) == 4 and cc["html"].isna().all()
    crawled = crawl[crawl["seed_source"] == "popular"]
    assert len(crawled) > 0 and (crawled["html"] == PAGE).all()
    names = crawl_seed_names("popular", cfg["seeds"])
    assert sorted(names) == ["commoncrawl", "popular"]
    frame = crawl_frame(crawl, "popular", names)
    assert set(frame["source"]) == {"popular"} and (frame["label"] == 0).all()
    assert set(frame["origin"]) == {"crawl", "commoncrawl"}
    assert frame["depth"].min() >= 1
    assert frame["html"].notna().sum() == len(crawled)  # crawled pages carry HTML, index pages none


def test_crawl_command_takes_its_own_lock_for_popular_seeds(tmp_path, monkeypatch):
    from collector import __main__ as cm

    cfg = {"crawler": _crawl_cfg(tmp_path)}
    cfg["paths"] = {"crawl_dir": str(tmp_path / "crawl"), "http_cache_dir": str(tmp_path / "http")}
    cfg["run"] = {"lock_path": str(tmp_path / "run.lock"), "lock_stale_s": 100}
    cfg["ood"] = {"lock_stale_s": 50}
    cfg["http"] = {}
    seen = {}

    def fake_run_crawl(client, cfg_, now, only, heartbeat=None):
        seen["only"], seen["heartbeat"] = only, heartbeat
        seen["locks"] = sorted(p.name for p in tmp_path.rglob("*.lock"))

    monkeypatch.setattr(cm, "load_config", lambda name: cfg)
    monkeypatch.setattr(cm.HttpClient, "from_config", classmethod(lambda cls, *a, **k: object()))
    monkeypatch.setattr(cm, "run_crawl", fake_run_crawl)
    assert cm.main(["crawl", "--seeds", "popular", "commoncrawl", "--domains-per-run", "7"]) == 0
    assert seen["locks"] == ["popular_crawl.lock"] and seen["heartbeat"] is not None
    assert cfg["crawler"]["seeds"]["popular"]["domains_per_run"] == 7
    assert cm.main(["crawl", "--seeds", "live"]) == 0
    assert seen["locks"] == ["run.lock"] and seen["heartbeat"] is None


def test_failed_index_sites_are_retried_and_use_the_index_client(tmp_path):
    class Calls(CCClient):
        def __init__(self, pages, name):
            super().__init__(pages)
            self.name = name

    index = json.dumps([{"cdx-api": ENDPOINT}]).encode()
    crux = gzip.compress(b"origin,rank\nhttps://cc.example.com,5000\n")
    cfg = _crawl_cfg(tmp_path)
    cfg["seeds"]["commoncrawl"]["retry_errors"] = True
    cfg["popular"]["commoncrawl"]["workers"] = 1
    crawl_dir, seed_dir = tmp_path / "crawl", tmp_path / "seeds"
    seed_dir.mkdir()
    shared = Calls({"https://crux.test/202609.csv.gz": crux}, "shared")
    down = Calls(
        {"https://index.test/collinfo.json": index, f"{ENDPOINT}?url=cc.example.com": 503}, "cc"
    )
    cfg["popular_client"] = down
    first = benign.crawl(shared, cfg, crawl_dir, seed_dir, NOW, only=["commoncrawl"])
    assert first["commoncrawl"]["status"] == {"error": 1}
    assert down.calls and not any("index.test" in c for c in shared.calls)

    up = Calls(
        {
            "https://index.test/collinfo.json": index,
            f"{ENDPOINT}?url=cc.example.com": _cdx("cc.example.com", 5),
        },
        "cc",
    )
    cfg["popular_client"] = up
    again = benign.crawl(shared, cfg, crawl_dir, seed_dir, NOW, only=["commoncrawl"])
    assert again["commoncrawl"]["domains"] == 1 and again["commoncrawl"]["pages"] == 4


def test_commoncrawl_client_and_summary_text(tmp_path):
    cfg = {
        "http": {
            "timeout_s": 20,
            "retries": 3,
            "backoff_factor": 2.0,
            "user_agent": "t",
            "default_min_interval_s": 1.0,
        },
        "paths": {"http_cache_dir": str(tmp_path / "cache")},
        "popular": {
            "commoncrawl": {
                "timeout_s": 60,
                "retries": 4,
                "backoff_factor": 3.0,
                "connect_timeout_s": 30,
                "min_interval_s": 1.0,
            }
        },
    }
    c = popular.commoncrawl_client(cfg)
    assert (c.retries, c.connect_timeout_s, c.timeout_s, c.backoff_factor) == (4, 30, 60, 3.0)
    assert popular.summary_text(tmp_path / "empty") == "No popular-site attempts recorded yet."


def test_popular_urls_seed_set_keeps_sitemap_urls_without_downloading_pages(tmp_path, fixtures):
    crux = gzip.compress(b"origin,rank\nhttps://example.org,5000\n")
    pages = {**_site(fixtures), "https://crux.test/202609.csv.gz": crux}
    pages["https://example.org/sitemap.xml"] = pages["https://example.org/sitemap_index.xml"]
    client = CCClient(pages)
    cfg = _crawl_cfg(tmp_path)
    cfg["seeds"]["popular_urls"] = {
        "from": "crux",
        "source": "popular",
        "scheduled": False,
        "domains_per_run": 5,
        "include_homepage": False,
        "crawl": {"store_html": False, "inner_pages_max": 20},
    }
    crawl_dir, seed_dir = tmp_path / "crawl", tmp_path / "seeds"
    seed_dir.mkdir()
    benign.crawl(client, cfg, crawl_dir, seed_dir, NOW, only=["popular_urls"])
    got = store.load_crawl(crawl_dir)
    assert len(got) > 0 and got["html"].isna().all()
    assert set(got["seed_source"]) == {"popular_urls"}
    assert "popular_urls" in crawl_seed_names("popular", cfg["seeds"])


def test_index_run_stops_after_consecutive_failures_and_leaves_the_rest_untried(tmp_path):
    hosts = "".join(f"https://h{i}.com,5000\n" for i in range(12))
    crux = gzip.compress(("origin,rank\n" + hosts).encode())
    index = json.dumps([{"cdx-api": ENDPOINT}]).encode()
    pages = {"https://index.test/collinfo.json": index, f"{ENDPOINT}?url=h": 503}
    cfg = _crawl_cfg(tmp_path)
    cfg["seeds"]["commoncrawl"]["domains_per_run"] = 12
    cfg["popular"]["commoncrawl"].update(workers=1, max_consecutive_errors=3)
    cfg["popular_client"] = CCClient(pages)
    crawl_dir, seed_dir = tmp_path / "crawl", tmp_path / "seeds"
    seed_dir.mkdir()
    out = benign.crawl(
        CCClient({"https://crux.test/202609.csv.gz": crux}),
        cfg,
        crawl_dir,
        seed_dir,
        NOW,
        ["commoncrawl"],
    )
    assert out["commoncrawl"]["status"] == {"error": 3}
    assert len(store.load_attempts(crawl_dir)) == 3


def test_popular_summary_command_runs_without_the_verbose_flag(tmp_path, monkeypatch, capsys):
    from collector import __main__ as cm

    cfg = {"paths": {"crawl_dir": str(tmp_path / "crawl")}}
    monkeypatch.setattr(cm, "load_config", lambda name: cfg)
    assert cm.main(["popular-summary"]) == 0
    assert "No popular-site attempts" in capsys.readouterr().out
