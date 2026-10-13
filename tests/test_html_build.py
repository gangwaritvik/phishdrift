"""Tier B: NaN on unusable HTML, bounded work, extract() integration, and the sharded build."""

import math
import time

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from features import build_b, html_features
from features.extract import extract
from features.fit import Fitted
from features.html_features import analyze, extract_html, nan_features
from features.registry import NAMES, NAMES_B, REGISTRY_B
from tests.html_helpers import FILLER, LISTS, URL, isnan, page


def all_nan(values: dict) -> bool:
    return list(values) == list(NAMES_B) and all(math.isnan(v) for v in values.values())


# ---- registry ---------------------------------------------------------------------------------


def test_registry_b_is_complete_and_separate_from_tier_a():
    assert len(NAMES_B) == len(set(NAMES_B)) >= 70
    assert not set(NAMES_B) & set(NAMES)
    assert all(f.tier == "B" and f.availability == "samples with HTML" for f in REGISTRY_B)
    assert {f.group for f in REGISTRY_B} == {
        "forms",
        "links",
        "resources",
        "text",
        "structure",
        "scripts",
    }


def test_a_good_page_returns_every_registered_feature_as_float_and_none_missing():
    values, status = analyze(
        URL, page('<form action="/x"><input type="password"></form>'), lists=LISTS
    )
    assert status == "ok" and values is not None
    assert list(values) == list(NAMES_B)
    assert all(isinstance(v, float) for v in values.values())
    # a real page has real numbers for the counts, not a silent all-NaN failure
    assert not isnan(values["n_forms"]) and not isnan(values["page_size"])
    assert sum(math.isnan(v) for v in values.values()) < len(values) / 2


# ---- unusable HTML = NaN for every value ------------------------------------------------------


@pytest.mark.parametrize(
    "html",
    [
        None,
        "",
        "   \n\t ",
        b"",
        123,
        "<html><body>tiny</body></html>",
        "<html><body><script>" + "x" * 5000 + "</script></body></html>",  # no visible text
        "<html><body>" + "<p>word</p>" * 5 + "</body></html>",  # under 200 characters
    ],
)
def test_missing_or_tiny_html_is_all_nan(html):
    assert all_nan(extract_html(URL, html, lists=LISTS))
    values, status = analyze(URL, html, lists=LISTS)
    assert values is None and status in ("empty", "short")


JUNK = {
    "404 title": page(
        title="404 Not Found",
        filler=False,
        body="<p>" + "The page you asked for is gone. " * 10 + "</p>",
    ),
    "nginx": page(
        title="Welcome to nginx!",
        filler=False,
        body="<p>" + "If you see this page, the web server is installed. " * 6 + "</p>",
    ),
    "parked": page(
        title="example.com",
        filler=False,
        body="<p>" + "This domain is for sale. Buy this domain today. " * 8 + "</p>",
    ),
    "suspended": page(
        title="Account Suspended",
        filler=False,
        body="<p>" + "This account has been suspended. Contact your provider. " * 6 + "</p>",
    ),
    "takedown": page(
        title="Site",
        filler=False,
        body="<p>"
        + "This website has been removed due to a violation. This site has been taken down. " * 3
        + "</p>",
    ),
    "cloudflare": page(
        title="Just a moment...",
        filler=False,
        body="<p>"
        + "Checking your browser first. Enable JavaScript and cookies to continue. " * 4
        + "</p>",
    ),
    "forbidden": page(
        title="403 Forbidden",
        filler=False,
        body="<p>" + "You don't have permission to access this resource. " * 8 + "</p>",
    ),
}


@pytest.mark.parametrize("name", list(JUNK))
def test_parked_takedown_and_error_pages_are_all_nan(name):
    values, status = analyze(URL, JUNK[name], lists=LISTS)
    assert (values, status) == (None, "junk"), name
    assert all_nan(extract_html(URL, JUNK[name], lists=LISTS))


def test_a_phishing_page_that_talks_about_suspension_is_not_junk():
    body = (
        "<p>Your account has been suspended. Verify your identity now to restore access. "
        + "Please sign in below to continue. " * 4
        + '</p><form action="/p"><input type="password" name="pw"></form>'
    )
    values, status = analyze(URL, page(body, title="Account Suspended"), lists=LISTS)
    assert status == "ok" and values["n_password_fields"] == 1


def test_a_long_real_page_is_not_junk_even_if_it_mentions_error_pages():
    text = "<p>How to fix a 404 not found error and a 403 forbidden page. " + FILLER * 20 + "</p>"
    assert analyze(URL, page(text, title="Blog: fixing a 404 error"), lists=LISTS)[1] == "ok"


# ---- never raises, bounded work ---------------------------------------------------------------


def test_malformed_html_does_not_raise():
    garbage = [
        "<<<<>>>>" * 500 + FILLER,
        "<div " + 'a="' * 300 + FILLER,
        FILLER + "<!--" * 500,
        FILLER + "<![CDATA[" * 100 + "<?php " * 100,
        "<a href=" * 400 + FILLER,
        FILLER + "&#xZZ;&#99999999999;&amp" * 200,
        "\x00\x01\x02" * 200 + FILLER,
    ]
    for html in garbage:
        values, status = analyze(URL, html, lists=LISTS)
        assert status in ("ok", "short", "junk"), status
        assert values is None or list(values) == list(NAMES_B)


def test_very_deep_nesting_does_not_recurse():
    html = "<div>" * 40_000 + FILLER + "</div>" * 40_000
    values, status = analyze(URL, html, lists=LISTS)
    assert status == "ok"
    assert values["max_dom_depth"] <= html_features.MAX_STACK


def test_a_failure_inside_the_parser_gives_all_nan(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("parser exploded")

    monkeypatch.setattr(html_features, "_parse", boom)
    assert analyze(URL, page(), lists=LISTS) == (None, "failed")
    assert all_nan(extract_html(URL, page(), lists=LISTS))


def test_the_wall_clock_guard_stops_a_slow_page(monkeypatch):
    monkeypatch.setattr(html_features, "MAX_PAGE_SECONDS", 0.0)
    start = time.monotonic()
    assert analyze(URL, page("<p>x</p>" * 20_000), lists=LISTS) == (None, "timeout")
    assert time.monotonic() - start < 5


def test_the_event_cap_keeps_the_part_already_parsed(monkeypatch):
    monkeypatch.setattr(html_features, "MAX_EVENTS", 500)
    values, status = analyze(URL, page("<b>x</b>" * 5_000), lists=LISTS)
    assert status == "ok" and values["n_tags"] <= 600


def test_pages_with_huge_text_stay_fast():
    html = page("<p>" + "word " * 100_000 + "</p>")
    start = time.monotonic()
    values, status = analyze(URL, html, lists=LISTS)
    assert status == "ok" and time.monotonic() - start < 5
    assert values["visible_text_len"] <= html_features.MAX_TEXT_CHARS


def test_bytes_are_decoded():
    values, status = analyze(URL, page(title="Café").encode("utf-8"), lists=LISTS)
    assert status == "ok" and values["has_title"] == 1


def test_a_url_without_a_host_gives_nan():
    assert analyze("", page(), lists=LISTS) == (None, "no_url")


# ---- extract() keeps tier A byte-identical ----------------------------------------------------


def test_extract_without_html_is_exactly_tier_a():
    a = extract("https://www.example.com/login?x=1", lists=LISTS, fitted=Fitted())
    assert list(a) == list(NAMES)
    for html in (None, "", "<html></html>", JUNK["parked"]):
        b = extract("https://www.example.com/login?x=1", html, lists=LISTS, fitted=Fitted())
        assert list(b) == list(NAMES)


def test_extract_with_usable_html_adds_tier_b_after_unchanged_tier_a():
    url = "https://www.example.com/login?x=1"
    a = extract(url, lists=LISTS, fitted=Fitted())
    b = extract(url, page(), lists=LISTS, fitted=Fitted())
    assert list(b) == [*NAMES, *NAMES_B]
    for name in NAMES:
        same = (isnan(a[name]) and isnan(b[name])) or a[name] == b[name]
        assert same, name


def test_nan_features_has_every_name():
    assert all_nan(nan_features())


# ---- the sharded build ------------------------------------------------------------------------


def write_part(path, n_good=7, row_group_size=2):
    rows = []
    for i in range(n_good):
        rows.append(
            (f"s:{i}", f"https://site{i}.example.org/a/{i}", page(f"<p>{i}</p>", title=f"Site {i}"))
        )
    rows.insert(2, ("s:none", "https://nohtml.example.net/", None))
    rows.insert(4, ("s:empty", "https://empty.example.net/", ""))
    rows.insert(5, ("s:junk", "https://junk.example.net/", JUNK["parked"]))
    rows.insert(6, ("s:short", "https://short.example.net/", "<p>hi</p>"))
    table = pa.table(
        {
            "uid": [r[0] for r in rows],
            "url": [r[1] for r in rows],
            "label": [i % 2 for i in range(len(rows))],
            "html": pa.array([r[2] for r in rows], pa.string()),
        }
    )
    pq.write_table(table, path, row_group_size=row_group_size)
    return [r[0] for r in rows if r[0].startswith("s:") and r[0][2:].isdigit()]


def run_build(tmp_path, split="pool", workers=1, shard_rows=4, **kw):
    log = []
    out = build_b.build_b(
        split,
        processed_dir=tmp_path / "processed",
        interim_dir=tmp_path / "interim",
        workers=workers,
        shard_rows=shard_rows,
        batch_rows=3,
        progress=log.append,
        **kw,
    )
    return out, log


@pytest.fixture
def processed(tmp_path):
    (tmp_path / "processed").mkdir()
    good = write_part(tmp_path / "processed" / "pool.parquet")
    return tmp_path, good


def test_build_keeps_only_usable_rows_as_float32(processed):
    tmp_path, good = processed
    out, log = run_build(tmp_path)
    assert out == tmp_path / "processed" / "features_b.parquet"
    table = pq.read_table(out)
    assert table.column_names == ["uid", *NAMES_B]
    assert table.column("uid").to_pylist() == good  # junk, short, empty and missing rows dropped
    assert all(pa.types.is_float32(table.schema.field(n).type) for n in NAMES_B)
    assert not any("has_html" in c for c in table.column_names)
    assert any("usable 7" in line or "7 of 11" in line for line in log)
    # the shards are on disk under interim/features_b/<part>/
    shards = sorted((tmp_path / "interim" / "features_b" / "pool").glob("shard_*.parquet"))
    assert len(shards) == 3  # 11 rows in 6 row groups of 2, shards of whole groups of >= 4 rows


def test_other_parts_get_their_own_file(tmp_path):
    (tmp_path / "processed").mkdir()
    write_part(tmp_path / "processed" / "time_slice.parquet")
    out, _ = run_build(tmp_path, "time_slice")
    assert out.name == "features_b_time_slice.parquet"
    assert (tmp_path / "interim" / "features_b" / "time_slice").is_dir()


def test_rerun_skips_finished_shards_and_resumes_after_ctrl_c(processed, monkeypatch):
    tmp_path, good = processed
    calls = []
    real = build_b.process_rows

    def counting(rows):
        calls.append(len(rows))
        if len(calls) == 4:  # the second shard's batches: stop in the middle of it
            raise KeyboardInterrupt
        return real(rows)

    monkeypatch.setattr(build_b, "process_rows", counting)
    with pytest.raises(KeyboardInterrupt):
        run_build(tmp_path)
    folder = tmp_path / "interim" / "features_b" / "pool"
    assert [p.name for p in folder.glob("shard_*.parquet")] == ["shard_00000.parquet"]
    assert not list(folder.glob("*.tmp"))
    assert not (tmp_path / "processed" / "features_b.parquet").exists()

    # same command again: the finished shard is not recomputed
    calls.clear()
    monkeypatch.setattr(
        build_b, "process_rows", lambda rows: (calls.append(len(rows)), real(rows))[1]
    )
    out, log = run_build(tmp_path)
    assert sum(calls) == 11 - 4  # shard 0 held 4 of the 11 rows
    assert any("shard 1/3 already done" in line for line in log)
    assert pq.read_table(out).column("uid").to_pylist() == good

    # and a third run does no work at all
    calls.clear()
    out2, log2 = run_build(tmp_path)
    assert calls == [] and out2 == out
    shard_lines = [line for line in log2 if "] shard " in line]
    assert len(shard_lines) == 3 and all("already done" in line for line in shard_lines)


def test_leftover_tmp_files_are_removed(processed):
    tmp_path, _ = processed
    folder = tmp_path / "interim" / "features_b" / "pool"
    folder.mkdir(parents=True)
    (folder / "shard_00001.parquet.tmp").write_bytes(b"half written")
    run_build(tmp_path)
    assert not list(folder.glob("*.tmp"))


def test_a_changed_input_file_stops_the_resume(processed):
    tmp_path, _ = processed
    run_build(tmp_path)
    write_part(tmp_path / "processed" / "pool.parquet", n_good=9)
    with pytest.raises(RuntimeError, match="delete that folder"):
        run_build(tmp_path)


def test_two_workers_give_the_same_table_as_one(processed):
    tmp_path, _ = processed
    one, _ = run_build(tmp_path)
    expected = pq.read_table(one)
    one.unlink()
    for shard in (tmp_path / "interim" / "features_b" / "pool").iterdir():
        shard.unlink()
    two, _ = run_build(tmp_path, workers=2)
    got = pq.read_table(two)
    assert got.column("uid").to_pylist() == expected.column("uid").to_pylist()
    for name in NAMES_B:
        a, b = got.column(name).to_pylist(), expected.column(name).to_pylist()
        assert all((isnan(x) and isnan(y)) or x == y for x, y in zip(a, b, strict=True)), name


def test_a_part_without_html_is_skipped(tmp_path):
    (tmp_path / "processed").mkdir()
    table = pa.table(
        {
            "uid": ["h:0", "h:1", "h:2"],
            "url": ["http://a.test/", "http://b.test/", "http://c.test/"],
            "html": pa.array([None, None, None], pa.string()),
        }
    )
    pq.write_table(table, tmp_path / "processed" / "heldout_source.parquet")
    out, log = run_build(tmp_path, "heldout_source")
    assert out is None and "no HTML" in log[0]
    assert not list((tmp_path / "processed").glob("features_b*"))
    assert not (tmp_path / "interim" / "features_b").exists()


def test_html_check_falls_back_to_scanning_when_statistics_are_missing(tmp_path):
    table = pa.table({"uid": ["a", "b"], "html": pa.array([None, "<p>x</p>"], pa.string())})
    pq.write_table(table, tmp_path / "with.parquet", write_statistics=False)
    empty = pa.table({"uid": ["a", "b"], "html": pa.array([None, None], pa.string())})
    pq.write_table(empty, tmp_path / "without.parquet", write_statistics=False)
    assert build_b.part_has_html(pq.ParquetFile(tmp_path / "with.parquet"))
    assert not build_b.part_has_html(pq.ParquetFile(tmp_path / "without.parquet"))


def test_a_missing_input_file_is_a_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="milestone 1"):
        run_build(tmp_path)


def test_command_line_routes_tier_b(monkeypatch, capsys):
    from features import __main__ as cli

    seen = {}

    def fake(split, workers=None):
        seen.update(split=split, workers=workers)

    monkeypatch.setattr(build_b, "build_b", fake)
    assert cli.main(["build", "--tier", "B", "--split", "time_slice", "--workers", "2"]) == 0
    assert seen == {"split": "time_slice", "workers": 2}
    assert "tier B not built" in capsys.readouterr().out


def test_source_check_reads_tier_b_features_only_for_rows_with_html(tmp_path):
    import pandas as pd

    from experiments.feature_source_check import run

    n = 1200
    uid = [f"s:{i}" for i in range(n)]
    source = ["a", "b"] * (n // 2)
    label = [0, 0, 1, 1] * (n // 4)
    pd.DataFrame({"uid": uid, "label": label, "source": source}).to_parquet(
        tmp_path / "pool.parquet"
    )
    # tier B has only the first 800 rows (the others had no usable HTML) and its own columns
    pd.DataFrame(
        {
            "uid": uid[:800],
            "n_forms": [float(s == "a") * 5 + i % 3 for i, s in enumerate(source[:800])],
        }
    ).to_parquet(tmp_path / "features_b.parquet")
    res = run(tmp_path, tmp_path / "out.csv", "features_b.parquet").set_index("feature")
    assert list(res.index) == ["n_forms"] and bool(res.loc["n_forms", "flag"])
