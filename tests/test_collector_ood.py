"""Out-of-distribution legitimate-page crawl (collector/ood.py, `python -m collector crawl-ood`)."""

import logging
from datetime import UTC, datetime

import pandas as pd
import pytest

from collector import __main__ as collector_main
from collector import benign, ood, store
from phishdrift.config import load_config, resolve
from tests.test_collector import CRAWL_CFG, PAGE, FakeClient, _site

NOW = datetime(2026, 10, 12, 8, 0, tzinfo=UTC)

OOD_CFG = {
    "seed": 7,
    "sample_size": 40,
    "skip_top_n": 100,
    "bands": [
        {"from_rank": 101, "to_rank": 500, "share": 0.5},
        {"from_rank": 501, "to_rank": 2000, "share": 0.5},
    ],
    "store_html": False,
    "inner_pages_min": 3,
    "inner_pages_max": 5,
    "checkpoint_every": 2,
    "lock_stale_s": 3600,
    "exclude_files": ["meta_pool.parquet", "pool.parquet"],
}


def ranked(n: int = 2000) -> list[str]:
    return [f"site{i}.com" for i in range(1, n + 1)]  # rank = position + 1


def rank_of(domain: str) -> int:
    return int(domain.removeprefix("site").removesuffix(".com"))


# --- sampling --------------------------------------------------------------------------


def test_band_quotas_sum_to_sample_size():
    bands = [{"share": 0.25}] * 3 + [{"share": 0.25}]
    assert sum(ood.band_quotas(bands, 1500)) == 1500
    assert sum(ood.band_quotas([{"share": 1}, {"share": 1}, {"share": 1}], 10)) == 10


def test_sample_is_seeded_banded_and_skips_head_exclusions_platforms():
    exclude = {f"site{i}.com" for i in range(101, 160)}
    platforms = frozenset({"site200.com"})
    lst = [*ranked(), "www.noregistrable.com"]  # not a registrable domain: dropped
    lst[300] = "www.noregistrable.com"
    a = ood.sample_ood_domains(lst, OOD_CFG, exclude, platforms)
    assert a == ood.sample_ood_domains(lst, OOD_CFG, exclude, platforms)  # same seed, same sample
    assert a != ood.sample_ood_domains(lst, {**OOD_CFG, "seed": 8}, exclude, platforms)
    assert len(a) == len(set(a)) == 40
    assert all(rank_of(d) > 100 for d in a)  # head skipped
    assert not exclude & set(a) and "site200.com" not in a and "www.noregistrable.com" not in a
    low = [d for d in a if rank_of(d) <= 500]
    assert len(low) == 20 and len(a) - len(low) == 20  # both bands represented


def test_sample_never_returns_rank_information():
    out = ood.sample_ood_domains(ranked(), OOD_CFG, set())
    assert all(isinstance(d, str) for d in out)


def test_head_cut_applies_even_when_a_band_starts_inside_it():
    cfg = {**OOD_CFG, "skip_top_n": 1000, "bands": [{"from_rank": 1, "to_rank": 1500, "share": 1}]}
    out = ood.sample_ood_domains(ranked(), cfg, set(), n=20)
    assert len(out) == 20 and all(rank_of(d) > 1000 for d in out)


def test_excluded_domains_union_of_pool_parts_crawl_log_and_feed_index(tmp_path):
    processed, crawl_dir = tmp_path / "processed", tmp_path / "crawl"
    processed.mkdir()
    pd.DataFrame({"domain": ["a.com", "B.com"], "label": [1, 0]}).to_parquet(
        processed / "meta_pool.parquet"
    )
    pd.DataFrame({"domain": ["c.com"]}).to_parquet(processed / "pool.parquet")
    store.append_attempts(
        pd.DataFrame(
            [{"seed_source": "live", "seed_domain": "d.com", "status": "ok", "pages": 3,
              "attempted_at": NOW}],
            columns=store.ATTEMPT_COLUMNS,
        ),
        crawl_dir,
    )  # fmt: skip
    index_path = tmp_path / "index.parquet"
    batch = pd.DataFrame(
        {
            "url": ["https://login.e.com/x"],
            "source": ["openphish"],
            "threat": ["phishing"],
            "label": pd.Series([1], dtype="int8"),
            "feed_time": pd.Series([pd.NaT], dtype="datetime64[ns, UTC]"),
            "target": [None],
        }
    )
    index, _ = store.update_index(store.empty_index(), batch, NOW)
    store.save_index(index, index_path)
    domains, found = ood.excluded_domains(OOD_CFG, processed, crawl_dir, index_path)
    assert domains == {"a.com", "b.com", "c.com", "d.com", "e.com"}
    assert found["meta_pool.parquet"] == 2 and found["pool.parquet"] == 1
    assert found["crawl attempts"] == 1 and found["feed index"] == 1


def test_missing_exclusion_files_are_skipped(tmp_path):
    domains, found = ood.excluded_domains(OOD_CFG, tmp_path, tmp_path / "c", tmp_path / "i.parquet")
    assert domains == set() and not any(k.endswith(".parquet") for k in found)


def test_sample_file_is_written_once_and_reused(tmp_path):
    calls = []

    def draw():
        calls.append(1)
        return ["a.com", "b.org", "c.net"]

    first = ood.plan_sample(tmp_path, OOD_CFG, draw, NOW)
    second = ood.plan_sample(tmp_path, OOD_CFG, draw, NOW)
    assert first == second == ["a.com", "b.org", "c.net"] and len(calls) == 1
    ood.plan_sample(tmp_path, OOD_CFG, draw, NOW, resample=True)
    assert len(calls) == 2


def test_ood_dir_must_not_overlap_the_training_crawl_dir(tmp_path):
    ood.check_separate_dirs(tmp_path / "raw" / "ood", tmp_path / "raw" / "crawl")
    for bad in (tmp_path / "raw" / "crawl", tmp_path / "raw" / "crawl" / "ood", tmp_path / "raw"):
        with pytest.raises(ValueError):
            ood.check_separate_dirs(bad, tmp_path / "raw" / "crawl")


def test_shipped_config_is_consistent():
    cfg = load_config("collector")
    o = cfg["ood"]
    ood.check_separate_dirs(resolve(cfg["paths"]["ood_dir"]), resolve(cfg["paths"]["crawl_dir"]))
    assert o["sample_size"] == 1500 and o["store_html"] is False
    assert sum(ood.band_quotas(o["bands"], o["sample_size"])) == 1500
    assert o["skip_top_n"] > 0 and max(b["to_rank"] for b in o["bands"]) <= 1_000_000
    assert "meta_pool.parquet" in o["exclude_files"]
    assert o["checkpoint_every"] == 25


# --- crawl -----------------------------------------------------------------------------


def _pages() -> dict:
    home = "".join(f'<a href="/section/{i}">s</a>' for i in range(8))
    pages = {
        **_site_pages(),
        "https://site.com/robots.txt": 404,
        "https://site.com/": home.encode(),
        "https://other.edu/robots.txt": 503,
    }
    pages.update({f"https://site.com/section/{i}": PAGE.encode() for i in range(8)})
    return pages


def _site_pages() -> dict:
    from tests.conftest import FIXTURES

    return _site(FIXTURES)


def _crawl(tmp_path, domains, client=None, **kw):
    cfg = {**CRAWL_CFG, "workers": 4}
    return ood.crawl_ood(
        client or FakeClient(_pages()), cfg, {**OOD_CFG, **kw.pop("cfg", {})}, tmp_path / "ood",
        domains, NOW, **kw
    )  # fmt: skip


def test_crawl_writes_urls_csv_status_and_no_html(tmp_path):
    domains = ["example.org", "other.edu", "site.com"]
    out = _crawl(tmp_path, domains)
    assert out["crawled_now"] == 3
    ood_dir = tmp_path / "ood"
    csv = pd.read_csv(ood_dir / "ood_urls.csv")
    assert list(csv.columns) == ["url", "domain", "label", "crawled_at", "ok"]
    assert (csv["label"] == 0).all()
    good, bad = csv[csv["ok"]], csv[~csv["ok"]]
    assert set(good["domain"]) == {"example.org", "site.com"}
    assert 3 <= len(good[good["domain"] == "site.com"]) <= 5  # 3-5 inner pages
    assert bad["url"].tolist() == ["https://other.edu/"]  # robots.txt unreadable: listed as not ok
    assert not good["url"].str.rstrip("/").eq("https://site.com").any()  # no homepage
    pages = ood.load_pages(ood_dir)
    assert pages["html"].isna().all() and (pages["origin"] == "ood").all()  # store_html false
    attempts = store.load_attempts(ood_dir)
    assert set(attempts["seed_source"]) == {"ood"} and len(attempts) == 3
    assert set(attempts["status"]) >= {benign.ROBOTS_UNREADABLE}
    # the training crawl folder is untouched / empty
    assert store.load_crawl(tmp_path / "crawl").empty


def test_store_html_true_keeps_page_html(tmp_path):
    _crawl(tmp_path, ["site.com"], cfg={"store_html": True})
    pages = ood.load_pages(tmp_path / "ood")
    assert len(pages) >= 3 and (pages["html"] == PAGE).all()


def test_rerun_skips_finished_sites_and_limit_caps_the_run(tmp_path):
    domains = ["example.org", "other.edu", "site.com"]
    first = _crawl(tmp_path, domains, limit=2)
    assert first["crawled_now"] == 2
    second = _crawl(tmp_path, domains)
    assert second["done_before"] == 2 and second["crawled_now"] == 1
    third = _crawl(tmp_path, domains)
    assert third["crawled_now"] == 0
    assert len(store.load_attempts(tmp_path / "ood")) == 3  # no site twice


def test_timed_out_site_is_recorded_and_not_retried(tmp_path):
    def stuck(items, work, workers, hard_limit_s):
        yield items[0], None  # run_parallel's signal for an abandoned site

    out = _crawl(tmp_path, ["example.org"], parallel=stuck)
    assert out["status_now"] == {benign.TIMED_OUT: 1}
    csv = pd.read_csv(tmp_path / "ood" / "ood_urls.csv")
    assert csv["ok"].tolist() == [False]
    assert _crawl(tmp_path, ["example.org"])["crawled_now"] == 0


def test_ctrl_c_keeps_finished_sites_and_a_rerun_continues(tmp_path):
    def interrupted(items, work, workers, hard_limit_s):
        for item in items[:2]:
            yield item, work(item)
        raise KeyboardInterrupt

    domains = ["example.org", "other.edu", "site.com"]
    with pytest.raises(KeyboardInterrupt):
        _crawl(tmp_path, domains, parallel=interrupted, cfg={"checkpoint_every": 100})
    assert len(store.load_attempts(tmp_path / "ood")) == 2  # saved by the final flush
    assert (tmp_path / "ood" / "ood_urls.csv").exists()
    assert _crawl(tmp_path, domains)["crawled_now"] == 1


def test_progress_line_per_checkpoint(tmp_path, caplog):
    with caplog.at_level(logging.INFO, logger="collector.ood"):
        _crawl(tmp_path, ["example.org", "other.edu", "site.com", "third.com"])
    lines = [r.getMessage() for r in caplog.records if "sites (" in r.getMessage()]
    assert len(lines) == 2 and "4/4" in lines[-1] and "pages" in lines[-1]  # checkpoint_every 2


def test_duplicate_pages_after_a_half_saved_checkpoint_are_dropped():
    pages = pd.DataFrame(
        {
            "url": ["https://a.com/x", "https://a.com/x"],
            "domain": ["a.com", "a.com"],
            "crawled_at": [NOW, NOW],
        }
    )
    attempts = pd.DataFrame(
        [["ood", "a.com", "ok", 1, NOW]],
        columns=store.ATTEMPT_COLUMNS,
    )
    assert len(ood.build_urls_table(pages, attempts)) == 1


# --- the command -----------------------------------------------------------------------


def _patch_command(monkeypatch, tmp_path, ranked_list, pages, processed_files=None):
    cfg = load_config("collector")
    real_exclude_files = cfg["ood"]["exclude_files"]  # the shipped list, not the test one
    cfg["paths"] = {
        **cfg["paths"],
        "ood_dir": str(tmp_path / "raw" / "ood"),
        "crawl_dir": str(tmp_path / "raw" / "crawl"),
        "index_path": str(tmp_path / "interim" / "idx.parquet"),
        "http_cache_dir": str(tmp_path / "cache"),
    }
    cfg["ood"] = {
        **OOD_CFG,
        "skip_top_n": 0,
        "sample_size": 3,
        "bands": [{"from_rank": 1, "to_rank": 100, "share": 1}],
        "exclude_files": real_exclude_files,
    }
    cfg["crawler"] = {
        **cfg["crawler"],
        **CRAWL_CFG,
        "workers": 2,
        "tranco_cache_dir": str(tmp_path),
    }
    processed = tmp_path / "processed"
    processed.mkdir()
    for name, domains in (processed_files or {}).items():
        pd.DataFrame({"domain": domains}).to_parquet(processed / name)
    datasets = {"paths": {"processed_dir": str(processed)}}
    monkeypatch.setattr(
        collector_main, "load_config", lambda name: cfg if name == "collector" else datasets
    )
    monkeypatch.setattr(benign, "tranco_domains", lambda top_n, cache_dir: ranked_list)
    client = FakeClient(pages)
    monkeypatch.setattr(
        collector_main.HttpClient, "from_config", classmethod(lambda cls, c, d: client)
    )
    monkeypatch.setattr(collector_main, "crawler_client", lambda c, cfg_: c)
    return cfg


def test_command_excludes_pool_domains_and_writes_the_small_csv(tmp_path, monkeypatch):
    pages = _pages()
    pages.update(
        {
            "https://third.com/robots.txt": 404,
            "https://third.com/": "".join(f'<a href="/p/{i}">x</a>' for i in range(6)).encode(),
        }
    )
    _patch_command(
        monkeypatch,
        tmp_path,
        ["site.com", "example.org", "third.com", "github.io", "trained.com"],
        pages,
        {"meta_pool.parquet": ["trained.com"], "meta_time_slice.parquet": ["third.com"]},
    )
    assert collector_main.run_crawl_ood() == 0
    ood_dir = tmp_path / "raw" / "ood"
    sampled = (ood_dir / "ood_sample.txt").read_text()
    assert "trained.com" not in sampled and "third.com" not in sampled  # in a processed part
    assert "github.io" not in sampled  # hosting platform
    csv = pd.read_csv(ood_dir / "ood_urls.csv")
    assert set(csv["domain"]) == {"site.com", "example.org"}
    assert not (tmp_path / "raw" / "crawl").exists()  # nothing written where the corpus build reads
    assert collector_main.run_crawl_ood() == 0  # rerun: nothing left to do, still fine


def test_command_refuses_without_any_processed_part(tmp_path, monkeypatch):
    _patch_command(monkeypatch, tmp_path, ["site.com"], _pages())
    assert collector_main.run_crawl_ood() == 1
    assert not (tmp_path / "raw" / "ood" / "ood_sample.txt").exists()
    assert collector_main.run_crawl_ood(allow_no_exclusions=True) == 0


def test_html_pass_recrawls_only_the_working_sites_into_a_separate_folder_with_html(
    tmp_path, monkeypatch
):
    pages = _pages()
    _patch_command(
        monkeypatch,
        tmp_path,
        ["site.com", "example.org"],
        pages,
        {"meta_pool.parquet": ["trained.com"]},
    )
    assert collector_main.run_crawl_ood(html_pass=True) == 1  # needs the first pass first
    assert collector_main.run_crawl_ood() == 0
    first = pd.read_csv(tmp_path / "raw" / "ood" / "ood_urls.csv")
    good = set(first.loc[first["ok"], "domain"])
    assert good
    assert collector_main.run_crawl_ood(html_pass=True) == 0
    second_dir = tmp_path / "raw" / "ood_html"
    second = pd.read_csv(second_dir / "ood_urls.csv")
    assert set(second["domain"]) <= good
    stored = ood.load_pages(second_dir)
    assert len(stored) and stored["html"].notna().all()
    assert (
        not ood.load_pages(tmp_path / "raw" / "ood")["html"].notna().any()
    )  # first pass: URLs only
