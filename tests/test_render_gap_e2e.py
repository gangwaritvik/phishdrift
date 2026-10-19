"""End-to-end self-check of the render pipeline on local fixture pages (no internet).

Serves tests/fixtures/render/*.html on 127.0.0.1, renders them with the same headless
``--dump-dom`` command the PC uses (``collector.render``), and runs ``experiments.render_gap`` on
the result. The sample keeps made-up legitimate-looking addresses (what the models score); the
browser loads the same paths from the local server (Chrome upgrades http:// on a mapped host name
to https://, which a plain local server cannot answer). Skipped when node or a Chrome/Chromium
executable is missing.
"""

from __future__ import annotations

import contextlib
import shutil
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pandas as pd
import pytest

from collector import render
from experiments import render_gap

FIXTURES = Path(__file__).parent / "fixtures" / "render"
PAGES = {
    "/advice/roses-in-clay-soil": "static.html",
    "/notebooks": "spa.html",
    "/account": "inject.html",
}
URLS = {
    "http://www.northwind-garden.com/advice/roses-in-clay-soil": "northwind-garden.com",
    "http://app.harbor-notes.org/notebooks": "harbor-notes.org",
    "http://www.riverside-library.org/account": "riverside-library.org",
    "http://www.slow-bakery.com/menu": "slow-bakery.com",  # never answers in time
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        path = self.path.split("?")[0]
        if path == "/menu":
            time.sleep(30)  # longer than the test's per-page limit: the browser gets killed
        name = PAGES.get(path)
        body = (FIXTURES / name).read_bytes() if name else b"<html><body>not found</body></html>"
        self.send_response(200 if name else 404)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        with contextlib.suppress(OSError):  # the browser was killed mid-response
            self.wfile.write(body)

    def log_message(self, *args):
        pass


def _browser() -> Path | None:
    try:
        return render.find_browser({"prefer": ["chromium", "chrome", "edge"]})
    except FileNotFoundError:
        return None


@pytest.fixture
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()
    srv.server_close()


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.skipif(_browser() is None, reason="no Chrome/Chromium executable found")
def test_render_and_gap_end_to_end(tmp_path, server):
    exe = _browser()
    bcfg = {
        "virtual_time_budget_ms": 2000,
        "timeout_s": 20,  # a cold Chrome start on a 2-CPU CI runner takes over 6 s
        "window_size": "1366,768",
        "user_agent": None,
        "max_html_chars": 5_000_000,
        # CI runners block the sandbox and have a small /dev/shm
        "extra_args": [
            "--no-proxy-server",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
        ],
    }
    local = {url: f"http://127.0.0.1:{server}/" + url.split("/", 3)[3] for url in URLS}
    cfg = {"sample": {"seed": 1, "size": 10, "max_per_site": 2}}

    def load() -> pd.DataFrame:  # "raw HTML" = what a plain HTTP fetch returns
        rows = []
        for url, domain in URLS.items():
            name = PAGES.get("/" + url.split("/", 3)[3], "static.html")
            rows.append({"url": url, "domain": domain, "html": (FIXTURES / name).read_text()})
        return pd.DataFrame(rows)

    out = tmp_path / "render"
    sample = render.plan(out, cfg, load)
    assert len(sample) == 4
    registry = render.ProcessRegistry()
    summary = render.render_all(
        sample,
        out,
        lambda url: render.render_with_browser(exe, local[url], bcfg, registry),
        workers=4,
        registry=registry,
        printer=lambda _: None,
    )
    assert summary["rendered_now"] == 4
    index = pd.read_csv(out / render.INDEX_NAME, keep_default_na=False).set_index("url")
    assert index.loc["http://www.slow-bakery.com/menu", "status"] == render.TIMEOUT
    ok = index[index["status"] == render.OK]
    assert len(ok) == 3, index[["status", "error"]].to_dict("records")
    spa = ok.loc["http://app.harbor-notes.org/notebooks"]
    assert 'type="password"' not in (out / spa["raw_file"]).read_text()
    assert 'type="password"' in (out / spa["rendered_file"]).read_text()  # scripts ran

    # second run: everything has a result, nothing is rendered again
    again = render.render_all(sample, out, lambda url: 1 / 0, 2, printer=lambda _: None)
    assert again["rendered_now"] == 0

    reports = tmp_path / "reports"
    md = render_gap.run(out / render.INDEX_NAME, reports, allowlist=None)
    text = md.read_text()
    assert "Compared: 3 pages from 3 sites" in text
    pages = pd.read_csv(reports / "tables" / "render_gap_pages.csv").set_index("url")
    # the single-page app has no usable text before its script runs, and plenty after
    assert not pages.loc["http://app.harbor-notes.org/notebooks", "raw_hasHtml"]
    assert pages.loc["http://app.harbor-notes.org/notebooks", "rendered_hasHtml"]
    summary_rows = pd.read_csv(reports / "tables" / "render_gap.csv")
    assert set(summary_rows["html"]) == {"raw", "rendered"}
