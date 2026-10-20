"""Serve the URL check demo page on this machine and open it in the browser.

    python -m demo [--port 8765] [--no-browser]

The page (demo/index.html) loads the extension's code and the model files from js/data at run
time, so a re-exported model shows up on the next reload. Only 127.0.0.1 is served.
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import http.server
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class _Handler(http.server.SimpleHTTPRequestHandler):
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
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
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
