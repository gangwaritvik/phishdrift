"""A collector run can be stopped at any point (Ctrl+C, closed window, the task scheduler's
time limit) without corrupting what it already saved, and the next run continues."""

import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd
import pytest

from collector import __main__ as collector_main
from collector import domain_capture, store
from collector.lock import AlreadyRunning, run_lock
from phishdrift.config import load_config
from phishdrift.http import HttpClient
from tests.test_collector import FakeClient, _fake_dns, _FakeResp

NOW = datetime(2026, 10, 12, 6, 15, tzinfo=UTC)
CAPTURE_CFG = {
    "max_domains_per_run": 50,
    "rdap_url": "https://rdap.example/domain/{domain}",
    "dns_timeout_s": 1,
    "tls": False,
    "tls_timeout_s": 1,
}


def _targets(n: int) -> list[dict]:
    return [{"url": f"https://s{i}.xyz/", "label": 1, "first_seen": None} for i in range(n)]


def _hosts(path) -> list[str]:
    recs = [json.loads(x) for x in path.read_text().splitlines()]
    return [r["host"] for r in recs if r["kind"] == "host"]


# --- http cache and parquet writes -----------------------------------------------------


def test_corrupt_cache_metadata_is_a_miss_not_a_crash(tmp_path, monkeypatch):
    client = HttpClient(cache_dir=tmp_path, default_min_interval_s=0)
    monkeypatch.setattr(client._session, "get", lambda url, **kw: _FakeResp(b"fresh"))
    url = "https://feed.example/list.txt"
    body_path, meta_path = client._cache_paths(url)
    body_path.write_bytes(b"half")
    meta_path.write_text('{"fetched_at": 17')  # cut off mid-write
    assert client.last_fetch_time(url) is None
    assert client.get(url, cache_ttl_s=60) == b"fresh"
    assert client.get(url, cache_ttl_s=60) == b"fresh"  # now a clean hit
    assert not list(tmp_path.glob("*.tmp"))  # no temporary files left behind


def test_failed_parquet_write_keeps_the_previous_file(tmp_path, monkeypatch):
    df = pd.DataFrame({"url": ["https://a.com/"]})
    out = store.write_daily(df, tmp_path, NOW.date(), "openphish")
    original = out.read_bytes()

    def boom(self, path, **kw):
        Path(path).write_bytes(b"partial")
        raise OSError("disk full")

    monkeypatch.setattr(pd.DataFrame, "to_parquet", boom)
    with pytest.raises(OSError):
        store.write_daily(df, tmp_path, NOW.date(), "openphish")
    assert out.read_bytes() == original
    assert [p.name for p in out.parent.glob("*.parquet")] == [
        "openphish.parquet"
    ]  # tmp is not *.parquet


# --- domain capture --------------------------------------------------------------------


def test_cut_off_jsonl_line_is_skipped_and_the_next_append_stays_valid(tmp_path):
    day = tmp_path / "2026-10-12.jsonl"
    day.write_text(
        json.dumps({"kind": "host", "host": "a.xyz", "domain": "a.xyz"}) + '\n{"kind": "ho'
    )
    hosts, _ = domain_capture.load_captured(tmp_path)
    assert hosts == {"a.xyz"}
    domain_capture.append_records(
        [{"kind": "host", "host": "b.xyz", "domain": "b.xyz"}], tmp_path, "2026-10-12"
    )
    lines = day.read_text().splitlines()
    assert json.loads(lines[-1])["host"] == "b.xyz"
    assert domain_capture.load_captured(tmp_path)[0] == {"a.xyz", "b.xyz"}


def test_capture_saves_every_checkpoint_and_on_ctrl_c_then_resumes(tmp_path):
    def dns(name, rdtype):
        if name.startswith("s3."):
            raise KeyboardInterrupt
        return []

    cfg = {**CAPTURE_CFG, "checkpoint_every": 2}
    with pytest.raises(KeyboardInterrupt):
        domain_capture.capture(_targets(6), FakeClient({}), cfg, tmp_path, NOW, dns)
    day = tmp_path / "2026-10-12.jsonl"
    assert _hosts(day) == ["s0.xyz", "s1.xyz", "s2.xyz"]  # s2 was saved by the final flush
    out = domain_capture.capture(_targets(6), FakeClient({}), cfg, tmp_path, NOW, _fake_dns({}))
    assert out["hosts"] == 3  # s3, s4, s5: nothing captured twice
    assert sorted(_hosts(day)) == [f"s{i}.xyz" for i in range(6)]


def test_capture_stops_starting_hosts_after_its_time_budget(tmp_path):
    cfg = {**CAPTURE_CFG, "time_budget_s": -1}
    out = domain_capture.capture(_targets(3), FakeClient({}), cfg, tmp_path, NOW, _fake_dns({}))
    assert out == {"hosts": 0, "domains": 0}


def test_hosts_left_over_from_a_stopped_run_are_retried_within_the_backlog_window():
    old, recent, stale = (NOW - timedelta(hours=h) for h in (0, 20, 100))
    index = pd.DataFrame(
        {
            "url": ["https://new.xyz/", "https://left-over.xyz/", "https://ancient.xyz/", "https://ok.com/"],
            "label": [1, 1, 1, 0],
            "first_seen": [pd.Timestamp(t) for t in (old, recent, stale, recent)],
        }
    )  # fmt: skip
    rows = collector_main.recent_rows(index, NOW, 48)
    assert set(rows["url"]) == {"https://new.xyz/", "https://left-over.xyz/", "https://ok.com/"}
    urls = [t["url"] for t in collector_main.capture_targets(rows, {})]
    assert urls == [
        "https://new.xyz/",
        "https://left-over.xyz/",
        "https://ok.com/",
    ]  # phishing, newest first


# --- lock ------------------------------------------------------------------------------


def test_second_run_is_refused_while_the_first_holds_the_lock(tmp_path):
    path = tmp_path / "collector.lock"
    with run_lock(path, 3600):
        with pytest.raises(AlreadyRunning), run_lock(path, 3600):
            pass
        assert path.exists()
    assert not path.exists()  # released
    with run_lock(path, 3600):  # and can be taken again
        pass


def test_stale_lock_from_a_killed_run_is_replaced_and_touch_keeps_it_fresh(tmp_path):
    path = tmp_path / "collector.lock"
    path.write_text("pid 1")
    old = time.time() - 7200
    os.utime(path, (old, old))
    with run_lock(path, 3600) as lock:
        assert path.exists()
        os.utime(path, (old, old))
        lock.touch()
        assert time.time() - path.stat().st_mtime < 60
    assert not path.exists()


def test_lock_is_released_when_the_run_is_interrupted(tmp_path):
    path = tmp_path / "collector.lock"
    with pytest.raises(KeyboardInterrupt), run_lock(path, 3600):
        raise KeyboardInterrupt
    assert not path.exists()


def test_run_is_skipped_not_failed_while_another_run_is_active(tmp_path, monkeypatch):
    cfg = load_config("collector")
    cfg["run"] = {**cfg["run"], "lock_path": str(tmp_path / "collector.lock")}
    monkeypatch.setattr(collector_main, "load_config", lambda name: cfg)
    monkeypatch.setattr(collector_main, "_run", lambda *a: pytest.fail("must not run"))
    with run_lock(tmp_path / "collector.lock", 3600):
        assert collector_main.run() == 0


# --- configuration the 12-hourly schedule depends on ------------------------------------


def test_feed_cache_expires_before_the_next_12_hourly_run():
    cfg = load_config("collector")
    for name, feed in cfg["feeds"].items():
        assert feed["cache_ttl_s"] < 12 * 3600, name  # a run a few seconds early must refetch
    cap = cfg["domain_capture"]
    assert cap["checkpoint_every"] > 0 and 0 < cap["time_budget_s"] < 3 * 3600
    assert cfg["run"]["lock_stale_s"] > 3 * 3600  # longer than the task's 3 hour limit
    hard = cfg["crawler"]["domain_deadline_s"] + 180
    assert hard < 3600  # one stuck site cannot hold the run for long
