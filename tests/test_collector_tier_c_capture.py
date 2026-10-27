"""Tier C capture: both classes, a resolver that does not filter, failed lookups retried,
parallel capture, and a Tranco list that survives a cache race."""

import json
from datetime import UTC, datetime

import pandas as pd

from collector import __main__ as collector_main
from collector import benign, domain_capture
from tests.test_collector import FakeClient, _fake_dns

NOW = datetime(2026, 10, 13, 5, 0, tzinfo=UTC)
CFG = {
    "max_domains_per_run": 50,
    "rdap_url": "https://rdap.example/domain/{domain}",
    "dns_timeout_s": 1,
    "tls": False,
    "tls_timeout_s": 1,
}


def _records(path):
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


class _DohResp:
    def __init__(self, body: dict):
        self.body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self.body


class _DohSession:
    def __init__(self, answers: dict):
        self.answers = answers
        self.calls = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append((url, params["name"], params["type"]))
        value = self.answers.get((url, params["name"], params["type"]))
        if isinstance(value, Exception):
            raise value
        return _DohResp(value or {"Status": 3})


def test_doh_query_keeps_only_the_asked_type_and_falls_back_to_the_next_resolver():
    import requests

    g, cf = "https://dns.google/resolve", "https://cloudflare-dns.com/dns-query"
    answers = {
        (g, "www.shop.com", "A"): requests.ConnectionError("blocked"),
        (cf, "www.shop.com", "A"): {
            "Status": 0,
            "Answer": [
                {"type": 5, "TTL": 300, "data": "shop.cdn.net."},
                {"type": 1, "TTL": 60, "data": "198.51.100.4"},
            ],
        },
        (g, "shop.com", "TXT"): {
            "Status": 0,
            "Answer": [{"type": 16, "TTL": 600, "data": '"v=spf1 -all"'}],
        },
    }
    session = _DohSession(answers)
    query = domain_capture.doh_query([g, cf], 1, session)
    assert query("www.shop.com", "A") == [("198.51.100.4", 60)]
    assert query("shop.com", "TXT") == [("v=spf1 -all", 600)]
    assert query("nothing.shop.com", "A") == []  # NXDOMAIN is an answer, not an error


def test_sinkhole_answers_do_not_count_as_resolving_and_are_captured_again(tmp_path):
    blocked = _fake_dns({("evil.xyz", "A"): [("0.0.0.0", 10)]})
    t = [{"url": "https://evil.xyz/login", "label": 1, "first_seen": None}]
    domain_capture.capture(t, FakeClient({}), CFG, tmp_path, NOW, blocked)
    rec = [r for r in _records(tmp_path / "2026-10-13.jsonl") if r["kind"] == "host"][0]
    assert rec["dns"]["sinkhole"] is True and rec["dns"]["resolves"] is False
    # a filtered answer is not a capture: the next run (within the backlog) tries again
    real = _fake_dns({("evil.xyz", "A"): [("203.0.113.9", 60)]})
    out = domain_capture.capture(t, FakeClient({}), CFG, tmp_path, NOW, real)
    assert out["hosts"] == 1
    hosts = [r for r in _records(tmp_path / "2026-10-13.jsonl") if r["kind"] == "host"]
    assert hosts[-1]["dns"]["resolves"] is True
    assert domain_capture.load_captured(tmp_path)[0] == {"evil.xyz"}


def test_old_records_without_the_sinkhole_key_are_checked_from_their_addresses():
    assert domain_capture.filtered_dns({"dns": {"a": ["0.0.0.0"], "aaaa": []}})
    assert not domain_capture.filtered_dns({"dns": {"a": ["0.0.0.0", "198.51.100.1"]}})
    assert not domain_capture.filtered_dns({"dns": {"a": [], "aaaa": []}})  # no answer at all
    assert not domain_capture.filtered_dns({"dns": None})


def test_tls_connects_to_our_own_address_with_the_host_as_server_name(tmp_path):
    seen = []

    def tls(host, timeout_s, address=None):
        seen.append((host, address))
        return {"ok": True}

    dns = _fake_dns({("a.evil.xyz", "A"): [("0.0.0.0", 5), ("203.0.113.5", 60)]})
    t = [{"url": "https://a.evil.xyz/", "label": 1, "first_seen": None}]
    domain_capture.capture(t, FakeClient({}), {**CFG, "tls": True}, tmp_path, NOW, dns, tls)
    assert seen == [("a.evil.xyz", "203.0.113.5")]


def test_failed_rdap_lookups_are_retried_on_later_runs_up_to_the_limit(tmp_path):
    t = [{"url": "https://a.evil.xyz/", "label": 1, "first_seen": None}]
    client = FakeClient({"https://rdap.example/domain/evil.xyz": 429})
    cfg = {**CFG, "rdap_retries": 2}
    for _ in range(4):
        domain_capture.capture(t, client, cfg, tmp_path, NOW, _fake_dns({}))
    rdap_calls = [u for u, _ in client.calls if "rdap" in u]
    assert len(rdap_calls) == 2  # first try + one retry: 2 failed records reach the limit
    recs = _records(tmp_path / "2026-10-13.jsonl")
    assert sum(r["kind"] == "host" for r in recs) == 1  # the host itself is captured once


def test_parallel_capture_writes_every_host_once(tmp_path):
    targets = [{"url": f"https://s{i}.xyz/", "label": 1, "first_seen": None} for i in range(30)]
    cfg = {**CFG, "workers": 6, "checkpoint_every": 7}
    out = domain_capture.capture(targets, FakeClient({}), cfg, tmp_path, NOW, _fake_dns({}))
    assert out == {"hosts": 30, "domains": 30}
    recs = _records(tmp_path / "2026-10-13.jsonl")
    hosts = [r["host"] for r in recs if r["kind"] == "host"]
    assert sorted(hosts) == sorted(f"s{i}.xyz" for i in range(30))


def test_benign_targets_skip_corpus_ood_feed_and_captured_domains(tmp_path, monkeypatch):
    processed, crawl, info, ood_dir = (tmp_path / n for n in ("processed", "crawl", "info", "ood"))
    for d in (processed, crawl, info, ood_dir):
        d.mkdir()
    pd.DataFrame({"domain": ["inpool.com"]}).to_parquet(processed / "meta_pool.parquet")
    (ood_dir / "ood_sample.txt").write_text("# sample\nood-site.com\n")
    domain_capture.append_records(
        [{"kind": "host", "host": "done.com", "domain": "done.com"}], info, "2026-10-12"
    )
    ranked = [f"top{i}.com" for i in range(5)] + [
        "inpool.com", "ood-site.com", "done.com", "web.app", "fresh1.com", "fresh2.org",
    ]  # fmt: skip
    cfg = {
        "paths": {
            "crawl_dir": str(crawl),
            "index_path": str(tmp_path / "none.parquet"),
            "ood_dir": str(ood_dir),
            "domain_info_dir": str(info),
        },
        "crawler": {"tranco_cache_dir": str(tmp_path / "tranco")},
        "ood": {"exclude_files": ["meta_pool.parquet"], "exclude_crawl_attempts": True},
        "domain_capture": {
            "benign": {
                "enabled": True,
                "per_run": 10,
                "seed": 1,
                "skip_top_n": 5,
                "bands": [{"from_rank": 1, "to_rank": 100, "share": 1.0}],
            }
        },
    }
    monkeypatch.setattr(collector_main, "resolve", lambda p: __import__("pathlib").Path(p))
    monkeypatch.setattr(
        collector_main, "load_config", lambda name: {"paths": {"processed_dir": str(processed)}}
    )
    monkeypatch.setattr(benign, "tranco_domains", lambda n, cache: ranked)
    monkeypatch.setattr(collector_main.ood, "load_platforms", lambda: frozenset({"web.app"}))
    targets = collector_main.benign_targets(cfg, NOW)
    urls = sorted(t["url"] for t in targets)
    assert urls == [
        "https://fresh1.com/",
        "https://fresh2.org/",
        "https://www.fresh1.com/",
        "https://www.fresh2.org/",
    ]
    assert {t["label"] for t in targets} == {0}


def test_tranco_falls_back_to_the_newest_complete_cached_list(tmp_path, monkeypatch):
    import sys
    import types

    class Broken:
        def __init__(self, cache_dir):
            pass

        def list(self):
            raise ValueError("substring not found")

    monkeypatch.setitem(sys.modules, "tranco", types.SimpleNamespace(Tranco=Broken))
    (tmp_path / "AAAAA.csv").write_text("".join(f"{i},d{i}.com\r\n" for i in range(1, 6)))
    (tmp_path / "BBBBB.csv").write_text("1,x.com\n2")  # cut off mid-write
    got = benign.tranco_domains(3, tmp_path, attempts=2, wait_s=0)
    assert got == ["d1.com", "d2.com", "d3.com"]


def test_a_host_whose_address_lookups_both_failed_is_captured_again(tmp_path):
    down = _fake_dns({("a.xyz", "A"): TimeoutError("x"), ("a.xyz", "AAAA"): TimeoutError("x")})
    t = [{"url": "https://a.xyz/", "label": 1, "first_seen": None}]
    domain_capture.capture(t, FakeClient({}), CFG, tmp_path, NOW, down)
    assert domain_capture.load_captured(tmp_path)[0] == set()
    domain_capture.capture(t, FakeClient({}), CFG, tmp_path, NOW, _fake_dns({}))
    assert domain_capture.load_captured(tmp_path)[0] == {"a.xyz"}


def test_a_stuck_lookup_is_abandoned_and_the_run_finishes(tmp_path):
    import threading

    release = threading.Event()

    def dns(name, rdtype):
        if name == "stuck.xyz":
            release.wait(30)  # hangs until the test ends
        return []

    targets = [
        {"url": f"https://{h}/", "label": 1, "first_seen": None} for h in ("stuck.xyz", "ok.xyz")
    ]
    cfg = {**CFG, "workers": 2, "job_deadline_s": 0.5}
    try:
        out = domain_capture.capture(targets, FakeClient({}), cfg, tmp_path, NOW, dns)
    finally:
        release.set()
    assert out["hosts"] == 1
    assert domain_capture.load_captured(tmp_path)[0] == {"ok.xyz"}  # stuck.xyz waits for next run


def test_domain_unit_captures_the_apex_once_and_falls_back_to_www(tmp_path):
    cfg = {**CFG, "unit": "domain", "tls": True}
    dns = _fake_dns(
        {
            ("shop.com", "A"): [("203.0.113.1", 60)],
            ("blog.net", "A"): [],
            ("www.blog.net", "A"): [("203.0.113.2", 60)],
        }
    )
    seen = []

    def tls(host, timeout_s, address=None):
        seen.append((host, address))
        return {"ok": True, "verified": False, "error": "x"}

    t = [
        {"url": "https://login.shop.com/a", "label": 1, "first_seen": None},
        {"url": "https://pay.shop.com/b", "label": 1, "first_seen": None},  # same domain
        {"url": "https://blog.net/", "label": 0, "first_seen": None},
        {"url": "https://evil.pages.dev/", "label": 1, "first_seen": None},  # platform
        {"url": "http://203.0.113.9/x", "label": 1, "first_seen": None},  # IP host
    ]
    out = domain_capture.capture(t, FakeClient({}), cfg, tmp_path, NOW, dns, tls)
    assert out == {"hosts": 2, "domains": 2}
    hosts = {r["host"]: r for r in _records(tmp_path / "2026-10-13.jsonl") if r["kind"] == "host"}
    assert set(hosts) == {"shop.com", "blog.net"}
    assert hosts["shop.com"]["probe_host"] == "shop.com"
    assert hosts["blog.net"]["probe_host"] == "www.blog.net"
    assert sorted(seen) == [("shop.com", "203.0.113.1"), ("www.blog.net", "203.0.113.2")]
