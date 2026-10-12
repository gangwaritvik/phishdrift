"""Backend CLI.

    python -m backend build-lists [--tranco-file PATH] [--out DIR]

Serve the API with: ``uvicorn backend.app:create_app --factory``.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from backend import lists
from backend.settings import Settings
from features.lists import read_platforms
from phishdrift.config import resolve

log = logging.getLogger("backend")


def cmd_build_lists(args: argparse.Namespace) -> int:
    settings = Settings.load()
    lcfg = settings.cfg["lists"]
    paths = settings.collector["paths"]
    urls = lists.collect_blocklist_urls(resolve(paths["raw_dir"]), resolve(paths["blocklist_dir"]))
    log.info("%d distinct phishing URLs for the blocklist", len(urls))

    top_n = lcfg["allowlist_top_n"]
    candidates: list[str] = []
    try:
        if args.tranco_file:
            candidates = lists.read_tranco_file(Path(args.tranco_file), top_n)
        else:
            cache_dir = resolve(settings.collector["crawler"]["tranco_cache_dir"])
            candidates = lists.tranco_from_package(cache_dir, top_n)
    except Exception as exc:  # noqa: BLE001 - an empty allowlist is better than no build
        log.warning("no Tranco list (%s: %s); the allowlist will be empty", type(exc).__name__, exc)

    docs = lists.build_lists(urls, candidates, read_platforms(), lcfg["prefix_bytes"])
    out_dir = Path(args.out) if args.out else settings.lists_dir
    lists.write_lists(docs, out_dir)
    log.info("wrote %s: %s", out_dir, docs["manifest"])
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m backend")
    sub = parser.add_subparsers(dest="cmd", required=True)
    build = sub.add_parser("build-lists", help="build the hashed blocklist and allowlist")
    build.add_argument("--tranco-file", help="Tranco CSV/text file (default: the tranco package)")
    build.add_argument("--out", help="output directory (default: lists.out_dir in backend.yaml)")
    build.set_defaults(func=cmd_build_lists)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
