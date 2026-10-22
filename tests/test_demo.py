"""The demo server serves the page, the extension code and the model files from the repository."""

from __future__ import annotations

import functools
import http.server
import json
import threading
import urllib.error
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


def test_llm_proxy_forwards_only_the_host_and_fails_soft():
    backend_seen: list[bytes] = []

    class Backend(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            backend_seen.append(self.rfile.read(int(self.headers["Content-Length"])))
            body = b'{"raise": true, "brand": "X", "brand_domain": "x.com", "error": null}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    fake = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    threading.Thread(target=fake.serve_forever, daemon=True).start()
    _Handler.backend = f"http://127.0.0.1:{fake.server_address[1]}"
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), functools.partial(_Handler, directory=str(ROOT))
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/api/llm-check"

    def post(data: bytes):
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        return urllib.request.urlopen(req)

    try:
        with post(b'{"domain": "Paypal-Login.xyz", "path_words": ["evil"], "extra": 1}') as res:
            assert json.loads(res.read())["raise"] is True
        assert json.loads(backend_seen[0]) == {"domain": "paypal-login.xyz"}
        for bad in (b'{"domain": "a b/c"}', b"not json"):
            try:
                post(bad)
                raise AssertionError("expected an error status")
            except urllib.error.HTTPError as err:
                assert err.code in (400, 502)
    finally:
        _Handler.backend = "http://127.0.0.1:8000"
        for srv in (server, fake):
            srv.shutdown()
            srv.server_close()
