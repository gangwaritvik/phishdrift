"""Backend tests. No test touches the network: the domain checker is a stub."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from backend import lists
from backend.app import create_app
from backend.checks import FACT_KEYS, LiveChecker, empty_facts, evaluate, facts_from_raw
from backend.limits import RateLimiter, TTLCache
from backend.settings import Settings

FIXTURE = Path(__file__).parent / "fixtures" / "list_key_parity.json"
NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)


class StubChecker:
    def __init__(self, facts: dict | None = None):
        self.calls: list[str] = []
        self.facts = facts or {}

    def __call__(self, domain: str) -> dict:
        self.calls.append(domain)
        return {**empty_facts(), **self.facts}


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings.load(
        {
            "feedback": {"dir": str(tmp_path / "feedback")},
            "lists": {"out_dir": str(tmp_path / "lists")},
            "rate_limit": {"capacity": 1000},
        }
    )


def make_client(settings, checker=None, **kwargs) -> tuple[TestClient, StubChecker]:
    checker = checker or StubChecker()
    return TestClient(create_app(settings, checker, **kwargs)), checker


# --- endpoints --------------------------------------------------------------------------


def test_health(settings):
    client, _ = make_client(settings)
    assert client.get("/health").json() == {"ok": True}


def test_domain_info_shape_and_cache(settings):
    facts = {"age_days": 3, "registered": True, "resolves": True, "tls_ok": True}
    client, checker = make_client(settings, StubChecker(facts))
    first = client.post("/domain-info", json={"domain": "Example.COM"}).json()
    assert first["domain"] == "example.com"
    assert first["cached"] is False
    assert first["error"] is None
    assert set(first["facts"]) == set(FACT_KEYS)
    assert first["facts"]["age_days"] == 3
    assert first["risk"] == "high"
    assert {s["id"] for s in first["signals"]} == {"domain_very_young"}
    assert all(set(s) == {"id", "text", "severity"} for s in first["signals"])
    second = client.post("/domain-info", json={"domain": "example.com"}).json()
    assert second["cached"] is True
    assert second["facts"] == first["facts"]
    assert checker.calls == ["example.com"]


def test_cache_expires_and_is_shared_with_score(settings):
    now = [0.0]
    client, checker = make_client(settings, monotonic=lambda: now[0])
    client.post("/domain-info", json={"domain": "a.example"})
    assert client.post("/score", json={"domain": "a.example", "local_verdict": 1}).json()["cached"]
    now[0] += settings.cfg["cache"]["ttl_s"] + 1
    assert not client.post("/domain-info", json={"domain": "a.example"}).json()["cached"]
    assert checker.calls == ["a.example", "a.example"]


def test_score_shape(settings):
    facts = {"age_days": 400, "registered": True, "resolves": True, "tls_ok": True}
    client, _ = make_client(settings, StubChecker(facts))
    body = client.post("/score", json={"domain": "old.example", "local_verdict": 2}).json()
    assert body == {
        "domain": "old.example",
        "risk": "low",
        "signals": [],
        "tier_c_model": False,
        "cached": False,
    }


def test_score_rules_fire_from_config(settings):
    facts = {"age_days": 2, "cert_free_issuer": True, "tls_ok": True, "tls_verified": True}
    client, _ = make_client(settings, StubChecker(facts))
    body = client.post("/score", json={"domain": "new.example", "local_verdict": 0}).json()
    ids = {s["id"] for s in body["signals"]}
    assert {"domain_very_young", "free_cert_very_young_domain"} <= ids
    assert body["risk"] == "high"


@pytest.mark.parametrize(
    "domain",
    [
        "https://example.com",
        "example.com/path",
        "example.com:8080",
        "exa mple.com",
        " example.com",
        "user@example.com",
        "example.com?x=1",
        "localhost",
        "",
        "a" * 64 + ".com",
        "[::1]",
        "bücher.example",
        "example..com",
        "-bad.example.com",
    ],
)
def test_domain_validation_rejects(settings, domain):
    client, checker = make_client(settings)
    assert client.post("/domain-info", json={"domain": domain}).status_code == 422
    assert client.post("/score", json={"domain": domain, "local_verdict": 0}).status_code == 422
    assert checker.calls == []


def test_validation_rejects_bad_enums_and_extra_fields(settings):
    client, _ = make_client(settings)
    ok = {"domain": "example.com"}
    assert client.post("/score", json={**ok, "local_verdict": 3}).status_code == 422
    assert client.post("/score", json=ok).status_code == 422
    assert (
        client.post("/domain-info", json={**ok, "url": "https://example.com/x"}).status_code == 422
    )
    fb = {**ok, "kind": "other", "verdict": 1}
    assert client.post("/feedback", json=fb).status_code == 422
    assert client.post("/feedback", json={**ok, "kind": "false_positive"}).status_code == 422


def test_trailing_dot_is_normalised(settings):
    client, _ = make_client(settings)
    assert client.post("/domain-info", json={"domain": "Example.com."}).json()["domain"] == (
        "example.com"
    )


def test_rate_limit(settings):
    settings.cfg["rate_limit"].update(capacity=3, refill_per_s=0.001)
    client, _ = make_client(settings)
    codes = [
        client.post("/domain-info", json={"domain": "a.example"}).status_code for _ in range(5)
    ]
    assert codes == [200, 200, 200, 429, 429]
    limited = client.post("/domain-info", json={"domain": "a.example"})
    assert int(limited.headers["Retry-After"]) >= 1
    assert client.get("/health").status_code == 200  # health is not limited


def test_token_bucket_refills():
    now = [0.0]
    rl = RateLimiter(capacity=2, refill_per_s=1.0, max_clients=2, clock=lambda: now[0])
    assert [rl.allow("a")[0] for _ in range(3)] == [True, True, False]
    now[0] += 1.0
    assert rl.allow("a")[0] is True
    rl.allow("b")
    rl.allow("c")  # evicts the oldest client "a"
    assert len(rl._buckets) == 2


def test_ttl_cache_evicts_oldest():
    cache: TTLCache[int] = TTLCache(ttl_s=10, max_entries=2, clock=lambda: 0.0)
    for i, key in enumerate("abc"):
        cache.put(key, i)
    assert cache.get("a") is None
    assert (cache.get("b"), cache.get("c")) == (1, 2)


def test_feedback_file_has_only_the_documented_fields(settings):
    fixed = datetime(2026, 10, 12, 23, 59, 30, tzinfo=UTC)
    client, _ = make_client(settings, utcnow=lambda: fixed)
    headers = {"X-PhishDrift-Token": client.post("/register").json()["token"]}
    for kind, verdict in (("false_positive", 2), ("missed_phish", 0)):
        body = {"domain": "Shop.Example.com", "kind": kind, "verdict": verdict}
        assert client.post("/feedback", json=body, headers=headers).json() == {"ok": True}
    path = settings.feedback_dir / "2026-10-12.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert len(rows) == 2
    for row in rows:
        assert set(row) == {"domain", "kind", "verdict", "timestamp", "reporter"}
        assert row["domain"] == "shop.example.com"
        assert row["timestamp"] == "2026-10-12T23:59:30+00:00"
    assert [r["kind"] for r in rows] == ["false_positive", "missed_phish"]


# --- fail soft --------------------------------------------------------------------------


def test_failed_lookup_is_low_with_error_and_not_cached(settings):
    class Boom:
        calls = 0

        def __call__(self, domain):
            self.calls += 1
            raise RuntimeError("secret detail")

    boom = Boom()
    client, _ = make_client(settings, boom)
    body = client.post("/domain-info", json={"domain": "x.example"})
    assert body.status_code == 200
    data = body.json()
    assert data["risk"] == "low"
    assert data["signals"] == []
    assert data["error"] == "lookup_failed"
    assert "secret" not in json.dumps(data)
    assert set(data["facts"]) == set(FACT_KEYS)
    assert all(v is None for v in data["facts"].values())
    client.post("/domain-info", json={"domain": "x.example"})
    assert boom.calls == 2
    score = client.post("/score", json={"domain": "x.example", "local_verdict": 1})
    assert score.status_code == 200
    assert score.json()["risk"] == "low"


def test_timeout_is_low_with_error(settings):
    import time

    settings.cfg["lookup"]["overall_timeout_s"] = 0.05

    def slow(domain):
        time.sleep(0.5)
        return {}

    client, _ = make_client(settings, slow)
    data = client.post("/domain-info", json={"domain": "slow.example"}).json()
    assert (data["risk"], data["error"], data["signals"]) == ("low", "timeout", [])


# --- rules and facts --------------------------------------------------------------------


def test_facts_from_raw_and_rules():
    rdap = {"registered": "2026-10-09T00:00:00Z"}
    dns = {"resolves": True, "mx_count": 0, "spf": False, "dmarc": False, "errors": []}
    tls = {
        "ok": True,
        "verified": True,
        "issuer_o": "Let's Encrypt",
        "issuer_cn": "R3",
        "not_before": "2026-10-10T00:00:00+00:00",
        "san_count": 2,
    }
    facts = facts_from_raw(rdap, None, dns, tls, NOW, ["let's encrypt"])
    assert facts["age_days"] == 3
    assert facts["cert_age_days"] == 2
    assert facts["cert_free_issuer"] is True
    assert facts["san_count"] == 2
    assert facts["has_mx"] is False
    signals, risk = evaluate(facts, Settings.load().cfg["rules"])
    assert risk == "high"
    assert {s["id"] for s in signals} == {"domain_very_young", "free_cert_very_young_domain"}


def test_failed_lookups_are_unknown_not_false():
    dns = {"resolves": False, "mx_count": 0, "spf": False, "dmarc": False, "errors": ["MX:Timeout"]}
    facts = facts_from_raw(None, "http_503", dns, None, NOW, [])
    assert facts["registered"] is None
    assert facts["resolves"] is False
    assert facts["has_mx"] is None
    assert facts["tls_ok"] is None
    assert facts_from_raw(None, "not_found", None, None, NOW, [])["registered"] is False


def test_live_checker_maps_collector_records(tmp_path):
    settings = Settings.load({"lookup": {"rdap_cache_ttl_s": 0}})
    settings.collector["paths"]["http_cache_dir"] = str(tmp_path)

    class FakeClient:
        def get(self, url, **kwargs):
            assert "example.com" in url
            return json.dumps(
                {"events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}]}
            ).encode()

    def query(name, rdtype):
        return [("93.184.216.34", 60)] if rdtype == "A" and name == "www.example.com" else []

    seen = []

    def tls(host, timeout):
        seen.append(host)
        return {"ok": True, "verified": True, "issuer_o": "DigiCert", "san_count": 1}

    checker = LiveChecker(settings, client=FakeClient(), query=query, tls=tls, now=lambda: NOW)
    facts = checker("www.example.com")
    assert facts["registered"] is True
    assert facts["age_days"] > 2000
    assert facts["resolves"] is True
    assert facts["cert_free_issuer"] is False
    assert seen == ["www.example.com"]


def test_live_checker_skips_tls_for_private_addresses(tmp_path):
    settings = Settings.load()

    class NoRdap:
        def get(self, url, **kwargs):
            raise OSError

    def query(name, rdtype):
        return [("10.0.0.5", 60)] if rdtype == "A" else []

    def tls(host, timeout):
        raise AssertionError("must not connect to a private address")

    checker = LiveChecker(settings, client=NoRdap(), query=query, tls=tls, now=lambda: NOW)
    facts = checker("internal.example.com")
    assert facts["tls_ok"] is None


# --- lists ------------------------------------------------------------------------------


def test_list_key_examples():
    key = lists.list_url_key("https://User@WWW.Example.com:8443/a/b/?q=1#top")
    assert key == "example.com:8443/a/b?q=1"
    assert lists.list_url_key("example.com/") == "example.com"
    assert lists.list_domain_key("http://login.secure.paypal.co.uk/x") == "paypal.co.uk"
    assert lists.list_domain_key("http://foo.github.io/x") == "github.io"
    assert lists.list_domain_key("http://192.168.0.1:80/x") == "192.168.0.1"
    assert lists.list_domain_key("http://[2001:db8::1]/") == "2001:db8::1"
    assert len(lists.list_hash("example.com", 6)) == 12


def test_key_parity_fixture_matches_python_now():
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert len(data["cases"]) >= 60
    cfg = Settings.load().cfg["lists"]
    assert data["prefix_bytes"] == cfg["prefix_bytes"]
    for case in data["cases"]:
        url_key, domain_key = lists.list_url_key(case["url"]), lists.list_domain_key(case["url"])
        hint = "run `python -m backend.make_fixture` and update the JS port"
        assert case["url_key"] == url_key, f"{case['url']!r}: {hint}"
        assert case["domain_key"] == domain_key, f"{case['url']!r}: {hint}"
        assert case["url_hash"] == lists.list_hash(url_key, data["prefix_bytes"])
        assert case["domain_hash"] == lists.list_hash(domain_key, data["prefix_bytes"])


def _write_feed(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_parquet(path, index=False)


def test_build_lists_end_to_end(tmp_path):
    raw, block = tmp_path / "feeds", tmp_path / "blocklists"
    _write_feed(
        raw / "2026-10-12" / "openphish.parquet",
        [
            {"url": "http://evil.example.com/login", "label": 1, "threat": "phishing"},
            {"url": "http://www.evil.example.com/other", "label": 1, "threat": "phishing"},
            {"url": "https://badsite.github.io/paypal/login", "label": 1, "threat": "phishing"},
            {"url": "https://benign.example.org/", "label": 0, "threat": ""},
        ],
    )
    _write_feed(
        block / "2026-10-12" / "urlhaus.parquet",
        [{"url": "http://malware.test.co.uk/x.exe", "label": 1, "threat": "malware"}],
    )
    urls = lists.collect_blocklist_urls(raw, block)
    assert "https://benign.example.org/" not in urls
    assert len(urls) == 4

    tranco = tmp_path / "tranco.csv"
    tranco.write_text(
        "1,google.com\n2,github.io\n3,www.evil.example.com\n4,wikipedia.org\n5,x.org\n"
    )
    cands = lists.read_tranco_file(tranco, top_n=4)
    assert cands == ["google.com", "github.io", "www.evil.example.com", "wikipedia.org"]

    docs = lists.build_lists(urls, cands, frozenset({"github.io"}), 6, built_at=NOW)
    h = lambda k: lists.list_hash(k, 6)  # noqa: E731
    block_doc = docs["blocklist"]
    # example.com is an allowlist candidate with phishing on evil.example.com, so that zone is
    # open hosting: its URLs are blocked by full URL and example.com itself stays allowlisted.
    assert docs["allowlist"]["open_hosting"] == ["evil.example.com"]
    assert block_doc["domains"] == [h("test.co.uk")]
    assert block_doc["urls"] == sorted(
        [
            h("badsite.github.io/paypal/login"),
            h("evil.example.com/login"),
            h("evil.example.com/other"),
        ]
    )
    assert h("github.io") not in block_doc["domains"]
    assert docs["allowlist"]["domains"] == sorted(
        [h("google.com"), h("example.com"), h("wikipedia.org")]
    )
    manifest = docs["manifest"]
    assert manifest["counts"] == {
        "blocklist_domains": 1,
        "blocklist_urls": 3,
        "allowlist_domains": 3,
        "open_hosting_domains": 1,
        "allowlist_top": 3,
    }
    assert manifest["prefix_bytes"] == 6
    assert manifest["built_at"] == "2026-10-12T12:00:00+00:00"
    assert len(manifest["version"]) == 12
    again = lists.build_lists(reversed(urls), cands, frozenset({"github.io"}), 6)
    assert again["manifest"]["version"] == manifest["version"]
    # rank order matters only for the top-site sentinels
    swapped = lists.build_lists(urls, reversed(cands), frozenset({"github.io"}), 6)
    assert swapped["allowlist"]["domains"] == docs["allowlist"]["domains"]
    assert swapped["allowlist"]["top"] == [
        h(d) for d in ["wikipedia.org", "example.com", "google.com"]
    ]


def test_open_hosting_zones_are_learned_from_phishing_hosts():
    h = lambda k: lists.list_hash(k, 6)  # noqa: E731
    cands = ["azure.com", "google.com", "weebly.com", "evil-brand.com"]
    feed = [
        "https://tenant1.swedencentral.cloudapp.azure.com/ch/login",
        "https://drive.google.com/file/d/abc",
        "https://drive.google.com/file/d/def",
        "https://drive.google.com/file/d/ghi",
        "https://drive.google.com/file/d/jkl",
        "https://drive.google.com/file/d/mno",
        "https://docs.google.com/forms/d/x",
        "https://usercontent.google.com/y",
        "https://shop-a.weebly.com/",
        "https://bank-b.weebly.com/login",
        "https://mail-c.weebly.com/",
        "https://evil-brand.com/login",  # phishing on the registrable domain itself
        "https://www.evil-brand.com/verify",  # www. is not a host below the domain
        "http://bad-host.example.net/x",  # not an allowlist candidate: blocked as a domain
    ]
    docs = lists.build_lists(feed, cands, frozenset(), 6)
    zones = docs["allowlist"]["open_hosting"]
    # google.com has three children but 7 URLs (path tenancy), so only the children are zones
    assert zones == sorted(
        [
            "cloudapp.azure.com",
            "docs.google.com",
            "drive.google.com",
            "usercontent.google.com",
            "weebly.com",
        ]
    )
    # allowlist candidates are never blocked as a domain: their bad URLs are listed one by one
    # (the extension lets an exact URL hit override the allowlist)
    assert docs["allowlist"]["domains"] == sorted(
        [h("azure.com"), h("google.com"), h("evil-brand.com")]
    )
    assert docs["blocklist"]["domains"] == [h("example.net")]
    assert h("evil-brand.com/login") in docs["blocklist"]["urls"]
    assert h("evil-brand.com/verify") in docs["blocklist"]["urls"]
    assert h("tenant1.swedencentral.cloudapp.azure.com/ch/login") in docs["blocklist"]["urls"]
    assert lists.in_zone("other.westeurope.cloudapp.azure.com", set(zones))
    assert not lists.in_zone("portal.azure.com", set(zones))
    assert not lists.in_zone("www.google.com", set(zones))
    assert not lists.in_zone("xcloudapp.azure.com", set(zones))
    # extra URLs only help find zones; they are never blocklisted
    more = ["https://x.files.1drv.com/a"]
    extra = lists.build_lists(
        ["https://evil-brand.com/"], ["1drv.com"], frozenset(), 6, extra_phishing_urls=more
    )
    assert extra["allowlist"]["open_hosting"] == ["files.1drv.com"]
    assert extra["blocklist"]["urls"] == []


def test_read_phishing_file_keeps_phishing_rows(tmp_path):
    csv = tmp_path / "p.csv"
    csv.write_text("url,label\nhttps://a.x.com/,1\nhttps://b.y.com/,0\n")
    assert lists.read_phishing_file(csv) == ["https://a.x.com/"]
    pq_path = tmp_path / "p.parquet"
    pd.DataFrame({"url": ["https://a.x.com/", "https://b.y.com/"], "label": [1, 0]}).to_parquet(
        pq_path
    )
    assert lists.read_phishing_file(pq_path) == ["https://a.x.com/"]
    txt = tmp_path / "p.txt"
    txt.write_text("# comment\nhttps://a.x.com/\n\nhttp://b.y.com/z\n")
    assert lists.read_phishing_file(txt) == ["https://a.x.com/", "http://b.y.com/z"]


def test_zone_evidence_opens_hosting_domain(monkeypatch):
    from backend import __main__ as cli

    history = "\n".join(f"http://tenant{i}.freehost.com/login" for i in range(5))
    monkeypatch.setattr(cli.HttpClient, "get", lambda self, url, **kw: history.encode())
    evidence = cli.fetch_zone_evidence(Settings.load())
    assert len(evidence) == 5
    docs = lists.build_lists(
        [], ["freehost.com", "google.com"], frozenset(), 6, extra_phishing_urls=evidence
    )
    assert "freehost.com" in docs["allowlist"]["open_hosting"]
    assert lists.list_hash("freehost.com", 6) not in docs["allowlist"]["domains"]
    assert lists.list_hash("google.com", 6) in docs["allowlist"]["domains"]
    assert docs["blocklist"]["domains"] == [] and docs["blocklist"]["urls"] == []


def test_zone_evidence_download_failure_is_skipped(monkeypatch):
    from backend import __main__ as cli

    def boom(self, url, **kw):
        raise OSError("offline")

    monkeypatch.setattr(cli.HttpClient, "get", boom)
    assert cli.fetch_zone_evidence(Settings.load()) == []


def test_list_endpoints(settings):
    client, _ = make_client(settings)
    for path in ("/lists/manifest", "/lists/blocklist.json", "/lists/allowlist.json"):
        resp = client.get(path)
        assert resp.status_code == 404
        assert "build-lists" in resp.json()["detail"]
    docs = lists.build_lists(["http://evil.example.com/x"], ["google.com"], frozenset(), 6)
    lists.write_lists(docs, settings.lists_dir)
    assert client.get("/lists/manifest").json() == docs["manifest"]
    assert client.get("/lists/blocklist.json").json() == docs["blocklist"]
    assert client.get("/lists/allowlist.json").json() == docs["allowlist"]
    assert set(docs["blocklist"]) == {"version", "prefix_bytes", "domains", "urls"}
    assert set(docs["allowlist"]) == {
        "version",
        "prefix_bytes",
        "domains",
        "open_hosting",
        "top",
    }
    assert client.get("/lists/blocklist.json").content == lists._canonical(docs["blocklist"])


def test_cli_build_lists_without_tranco_continues(tmp_path, monkeypatch, caplog):
    from backend import __main__ as cli

    def no_tranco(*args, **kwargs):
        raise OSError("offline")

    monkeypatch.setattr(lists, "tranco_from_package", no_tranco)
    out = tmp_path / "out"
    assert cli.main(["build-lists", "--out", str(out)]) == 0
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["counts"]["allowlist_domains"] == 0
    cli_file = tmp_path / "t.txt"
    cli_file.write_text("google.com\n")
    assert cli.main(["build-lists", "--tranco-file", str(cli_file), "--out", str(out)]) == 0
    assert json.loads((out / "manifest.json").read_text())["counts"]["allowlist_domains"] == 1


def test_live_checker_treats_a_broken_resolver_as_unknown():
    settings = Settings.load()

    class NoRdap:
        def get(self, url, **kwargs):
            raise OSError

    def dead_resolver(name, rdtype):
        return []

    checker = LiveChecker(settings, client=NoRdap(), query=dead_resolver, now=lambda: NOW)
    facts = checker("example.com")
    assert facts["resolves"] is None
    assert facts["tls_ok"] is None

    def working_resolver(name, rdtype):
        return [("198.51.100.1", 60)] if name == "a.root-servers.net" else []

    checker = LiveChecker(settings, client=NoRdap(), query=working_resolver, now=lambda: NOW)
    assert checker("nonexistent.example.com")["resolves"] is False


def test_path_tenants_open_the_whole_domain():
    urls = [f"https://telegra.ph/page-{i}" for i in range(4)] + ["https://www.google.com/x/y"]
    zones = lists.open_hosting_zones(urls, {"telegra.ph", "google.com"}, 3, 0.5)
    assert zones == {"telegra.ph"}


def test_many_busy_tenants_open_the_whole_domain():
    urls = [f"https://t{i}.host.me/{j}" for i in range(25) for j in range(5)]
    assert lists.open_hosting_zones(urls, {"host.me"}, 3, 0.5) == {
        f"t{i}.host.me" for i in range(25)
    }
    assert lists.open_hosting_zones(urls, {"host.me"}, 3, 0.5, min_children_whole=20) == {"host.me"}


def test_shorteners_are_never_allowlisted():
    docs = lists.build_lists(
        [], ["t.co", "example.com"], frozenset(), 6, shorteners=frozenset({"t.co"})
    )
    assert docs["allowlist"]["domains"] == [lists.list_hash("example.com", 6)]
