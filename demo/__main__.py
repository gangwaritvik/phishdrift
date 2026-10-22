"""Serve the URL check demo page on this machine and open it in the browser.

    python -m demo [--port 8765] [--backend http://127.0.0.1:8000] [--no-browser]

The page (demo/index.html) loads the extension's code and the model files from js/data at run
time, so a re-exported model shows up on the next reload. Only 127.0.0.1 is served.

``POST /api/llm-check`` forwards a host name (nothing else) to the local backend's ``/llm-check``
so the page can show the AI brand check; a browser page cannot call the backend itself (CORS).
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import http.server
import json
import re
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


_HOST_RE = re.compile(r"^[a-z0-9_.-]{1,253}$")


class _Handler(http.server.SimpleHTTPRequestHandler):
    backend = "http://127.0.0.1:8000"

    def do_POST(self) -> None:  # noqa: N802 - stdlib name
        status, body = 404, b"{}"
        if self.path == "/api/llm-check":
            status, body = self._llm_check()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _llm_check(self) -> tuple[int, bytes]:
        try:
            raw = self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 2048))
            host = str(json.loads(raw).get("domain", "")).lower()
            if not _HOST_RE.match(host):
                return 400, b"{}"
            request = urllib.request.Request(  # noqa: S310 - fixed http(s) backend URL
                f"{self.backend}/llm-check",
                data=json.dumps({"domain": host}).encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=25) as res:  # noqa: S310
                return 200, res.read(65536)
        except Exception:  # noqa: BLE001 - any failure means "backend not reachable"
            return 502, b"{}"

    extensions_map = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".js": "text/javascript",
        ".mjs": "text/javascript",
    }

    def end_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")  # always the current model files
        super().end_headers()

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        pass


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m demo", description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--backend", default=_Handler.backend, help="backend for the AI check")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    _Handler.backend = args.backend.rstrip("/")
    handler = functools.partial(_Handler, directory=str(ROOT))
    with http.server.ThreadingHTTPServer(("127.0.0.1", args.port), handler) as server:
        url = f"http://127.0.0.1:{args.port}/demo/"
        print(f"PhishDrift URL check: {url}  (Ctrl+C to stop)")
        if not args.no_browser:
            webbrowser.open(url)
        with contextlib.suppress(KeyboardInterrupt):
            server.serve_forever()


if __name__ == "__main__":
    main()
