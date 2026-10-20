"""collector.render (sampling, checkpoints, index) and experiments.render_gap (summary tables)."""

from __future__ import annotations

import json
import threading

import pandas as pd
import pytest

from collector import render
from experiments import render_gap


def _pages(n_sites: int = 5, per_site: int = 4) -> pd.DataFrame:
    rows = [
        {"url": f"https://www.s{s}.com/p{p}", "domain": f"s{s}.com", "html": f"<p>{s}-{p}</p>"}
        for s in range(n_sites)
        for p in range(per_site)
    ]
    return pd.DataFrame(rows)


CFG = {"sample": {"seed": 7, "size": 6, "max_per_site": 2}}


# --- sampling --------------------------------------------------------------------------------


def test_page_id_is_stable_and_file_safe():
    a = render.page_id("https://a.com/x?y=1|2")
    assert a == render.page_id("https://a.com/x?y=1|2") and len(a) == 16 and a.isalnum()
    assert a != render.page_id("https://a.com/x?y=1|3")


def test_sample_caps_pages_per_site_and_spreads_over_sites():
    s = render.sample_pages(_pages(), size=6, max_per_site=2, seed=1)
    assert len(s) == 6 and s["domain"].value_counts().max() <= 2
    assert s["domain"].nunique() == 5  # every site's first page before any second page
    assert list(s["id"]) == [render.page_id(u) for u in s["url"]]


def test_sample_is_deterministic_and_seed_dependent():
    a = render.sample_pages(_pages(), 6, 2, seed=1)
    b = render.sample_pages(_pages(), 6, 2, seed=1)
    c = render.sample_pages(_pages(), 6, 2, seed=2)
    assert list(a["url"]) == list(b["url"])
    assert list(a["url"]) != list(c["url"])


def test_sample_smaller_than_requested_and_empty():
    assert len(render.sample_pages(_pages(2, 5), 100, 3, 0)) == 6
    assert len(render.sample_pages(_pages(0, 0), 10, 2, 0)) == 0


def test_plan_writes_raw_files_once_and_reuses_the_sample(tmp_path):
    calls = []

    def load():
        calls.append(1)
        return _pages()

    first = render.plan(tmp_path, CFG, load)
    assert len(calls) == 1 and len(first) == 6
    for r in first.itertuples():
        assert (tmp_path / "raw" / f"{r.id}.html").read_text().startswith("<p>")
    again = render.plan(tmp_path, CFG, lambda: pytest.fail("load must not run"))
    assert list(again["id"]) == list(first["id"])
    # a raw file lost after the sample was saved is restored from the input
    (tmp_path / "raw" / f"{first['id'][0]}.html").unlink()
    render.plan(tmp_path, CFG, load)
    assert (tmp_path / "raw" / f"{first['id'][0]}.html").exists() and len(calls) == 2


# --- browser output --------------------------------------------------------------------------


def test_classify():
    ok = render.classify(b"<html><body><p>hi</p></body></html>", 0, 1.0)
    assert ok.status == render.OK and ok.html.startswith(b"<html>")
    err = render.classify(b'<div id="main-frame-error">ERR_NAME_NOT_RESOLVED</div>', 0, 1.0)
    assert (err.status, err.error) == (render.NET_ERROR, "ERR_NAME_NOT_RESOLVED")
    blank = render.classify(b"<html><head></head><body></body></html>\n", 0, 1.0)
    assert blank.status == render.EMPTY
    assert render.classify(b"", 0, 1.0).status == render.EMPTY
    assert render.classify(b"", 3, 1.0).status == render.ERROR
    assert len(render.classify(b"<p>" + b"x" * 100 + b"</p>", 0, 1.0, max_chars=10).html) == 10


def test_browser_command_uses_a_fresh_profile_and_headless_dump(tmp_path):
    bcfg = {"virtual_time_budget_ms": 5000, "user_agent": "UA", "extra_args": ["--x"]}
    cmd = render.browser_command(tmp_path / "chrome.exe", "https://a.com/", tmp_path / "prof", bcfg)
    assert cmd[1:3] == ["--headless=new", "--dump-dom"]
    assert f"--user-data-dir={tmp_path / 'prof'}" in cmd
    assert "--virtual-time-budget=5000" in cmd and "--user-agent=UA" in cmd
    assert "--disable-extensions" in cmd and cmd[-2:] == ["--x", "https://a.com/"]


def test_find_browser(tmp_path):
    with pytest.raises(FileNotFoundError):
        render.find_browser({"executable": str(tmp_path / "missing.exe")})
    exe = tmp_path / "Microsoft" / "Edge" / "Application" / "msedge.exe"
    exe.parent.mkdir(parents=True)
    exe.write_text("")
    found = render.find_browser({"prefer": ["edge"]}, env={"PROGRAMFILES(X86)": str(tmp_path)})
    assert found == exe
    with pytest.raises(FileNotFoundError):
        render.find_browser({"prefer": ["edge"]}, env={})


# --- checkpoints and index -------------------------------------------------------------------


def _fake(statuses: dict[str, str]):
    """Renderer returning a fixed status per URL (default ok) and recording calls."""
    calls: list[str] = []
    lock = threading.Lock()

    def renderer(url: str) -> render.Result:
        with lock:
            calls.append(url)
        st = statuses.get(url, render.OK)
        html = f"<html><body>{url}</body></html>".encode() if st == render.OK else None
        return render.Result(st, 0.5, html, "" if st == render.OK else "x")

    return renderer, calls


def test_render_all_checkpoints_and_skips_done_pages(tmp_path):
    sample = render.plan(tmp_path, CFG, _pages)
    bad = sample["url"][1]
    renderer, calls = _fake({bad: render.TIMEOUT})
    out = render.render_all(sample, tmp_path, renderer, workers=3, limit=4, printer=lambda _: None)
    assert out["rendered_now"] == 4 and len(calls) == 4
    index = pd.read_csv(tmp_path / render.INDEX_NAME, keep_default_na=False)
    assert list(index.columns) == render.INDEX_COLUMNS and len(index) == 6
    assert (index["status"] == render.PENDING).sum() == 2
    row = index.set_index("url").loc[bad]
    assert row["status"] == render.TIMEOUT and row["rendered_file"] == ""
    done = index[index["status"] == render.OK].iloc[0]
    assert (tmp_path / done["rendered_file"]).read_text().startswith("<html>")
    assert (tmp_path / done["raw_file"]).exists()
    status = json.loads((tmp_path / "status" / f"{done['id']}.json").read_text())
    assert status["status"] == render.OK and status["rendered_bytes"] > 0

    # rerun: only the 2 pages without a result; the timed-out page is not retried
    renderer2, calls2 = _fake({})
    out2 = render.render_all(sample, tmp_path, renderer2, workers=2, printer=lambda _: None)
    assert out2["done_before"] == 4 and len(calls2) == 2 and bad not in calls2
    # retry_failed: only the failed page
    renderer3, calls3 = _fake({})
    render.render_all(sample, tmp_path, renderer3, 2, retry_failed=True, printer=lambda _: None)
    assert calls3 == [bad]
    index = pd.read_csv(tmp_path / render.INDEX_NAME, keep_default_na=False)
    assert (index["status"] == render.OK).all()


def test_todo_ids():
    sample = pd.DataFrame({"id": ["a", "b", "c"]})
    st = {"a": {"status": "ok"}, "b": {"status": "timeout"}}
    assert render.todo_ids(sample, st, False) == ["c"]
    assert render.todo_ids(sample, st, True) == ["b", "c"]


def test_interrupt_keeps_finished_pages_and_writes_the_index(tmp_path):
    sample = render.plan(tmp_path, CFG, _pages)
    lines: list[str] = []

    def printer(line: str) -> None:  # Ctrl+C arrives in the main thread after 2 pages
        lines.append(line)
        if len(lines) == 3:
            raise KeyboardInterrupt

    def renderer(url: str) -> render.Result:
        return render.Result(render.OK, 0.1, b"<html><body>x</body></html>")

    with pytest.raises(KeyboardInterrupt):
        render.render_all(sample, tmp_path, renderer, workers=1, printer=printer)
    index = pd.read_csv(tmp_path / render.INDEX_NAME, keep_default_na=False)
    n_ok = int((index["status"] == render.OK).sum())
    assert 2 <= n_ok < len(sample)  # finished pages kept, queued pages cancelled
    assert len(list((tmp_path / "status").glob("*.json"))) == n_ok
    assert len(render.todo_ids(sample, render.load_statuses(tmp_path), False)) == 6 - n_ok


def test_run_refuses_without_browser(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "configs"
    cfg_dir.mkdir()
    (cfg_dir / "render.yaml").write_text(
        f"paths: {{ood_html_dir: {tmp_path / 'in'}, out_dir: {tmp_path / 'out'}}}\n"
        "sample: {seed: 1, size: 3, max_per_site: 1, min_html_chars: 1}\n"
        "browser: {executable: " + str(tmp_path / "nope.exe") + "}\n"
        "run: {workers: 1, retry_failed: false}\n"
    )
    assert render.run(config_dir=cfg_dir) == 1


# --- render_gap summaries --------------------------------------------------------------------


def _scored() -> pd.DataFrame:
    d = pd.DataFrame(
        {
            "id": list("abcd"),
            "url": [f"https://{x}.com/p" for x in "abcd"],
            "domain": [f"{x}.com" for x in "abcd"],
            "allowlisted": [False, False, True, False],
            "raw_hasHtml": [True, False, True, True],
            "rendered_hasHtml": [True, True, True, True],
            "raw_blended": [0.1, 0.2, 0.5, 0.95],
            "rendered_blended": [0.1, 0.6, 0.5, 0.9],
            "raw_verdict": ["safe", "safe", "suspicious", "dangerous"],
            "rendered_verdict": ["safe", "suspicious", "suspicious", "suspicious"],
        }
    )
    for form in render_gap.FORMS:
        d[f"{form}_warned"] = d[f"{form}_verdict"].isin(render_gap.WARN)
        d[f"{form}_dangerous"] = d[f"{form}_verdict"] == "dangerous"
    return d


def test_paired_and_mcnemar():
    p = render_gap.paired(_scored(), "warned")
    assert p == {"both": 2, "only_raw": 0, "only_rendered": 1, "neither": 1}
    assert render_gap.mcnemar_exact(0, 0) == 1.0
    assert render_gap.mcnemar_exact(0, 1) == 1.0
    assert render_gap.mcnemar_exact(0, 10) == pytest.approx(2 / 2**10)


def test_summarise_and_report():
    d = _scored()
    rows = render_gap.summarise(d)
    by = {(r["set"], r["html"]): r for r in rows}
    raw = by[("all pages (allowlist off)", "raw")]
    ren = by[("all pages (allowlist off)", "rendered")]
    assert (raw["warned"], raw["dangerous"], raw["usable_html"]) == (2, 1, 3)
    assert (ren["warned"], ren["dangerous"], ren["usable_html"]) == (3, 0, 4)
    assert by[("pages not on the allowlist", "raw")]["pages"] == 3
    index = pd.DataFrame({"status": ["ok"] * 4 + ["timeout"]})
    text = render_gap.render(index, d, rows, allowlist_used=True)
    assert "render status: ok 4, timeout 1" in text
    assert "| warned | 2 | 0 | 1 | 1 |" in text
    assert "## Pages whose verdict changes (2)" in text and "b.com" in text
    assert "without the user's extensions, cookies or sign-ins" in text


def test_load_index_keeps_pages_with_both_forms(tmp_path):
    p = tmp_path / "render_index.csv"
    pd.DataFrame(
        {
            "id": ["a", "b", "c"],
            "url": ["u1", "u2", "u3"],
            "domain": ["d", "d", "e"],
            "raw_file": ["raw/a.html", "raw/b.html", "raw/c.html"],
            "rendered_file": ["rendered/a.html", "", ""],
            "status": ["ok", "timeout", "pending"],
        }
    ).to_csv(p, index=False)
    index, ok = render_gap.load_index(p)
    assert len(index) == 3 and list(ok["id"]) == ["a"]
