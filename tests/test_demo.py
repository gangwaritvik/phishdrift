"""The demo server serves the page, the extension code and the model files from the repository."""

from __future__ import annotations

import functools
import http.server
import threading
import urllib.request

from demo.__main__ import ROOT, _Handler


def test_demo_server_serves_page_and_modules():
    handler = functools.partial(_Handler, directory=str(ROOT))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        with urllib.request.urlopen(f"{base}/demo/") as res:
            assert b"importmap" in res.read()
        for path in ("/demo/check.js", "/extension/src/combine.js", "/js/src/hybrid.js"):
            with urllib.request.urlopen(base + path) as res:
                assert res.headers["Content-Type"].startswith("text/javascript")
                assert res.headers["Cache-Control"] == "no-store"
    finally:
        server.shutdown()
        server.server_close()
