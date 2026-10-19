"""Backend CLI.

    python -m backend build-lists [--tranco-file PATH] [--phishing-file PATH ...] [--out DIR]
    python -m backend make-signing-key [--private PATH] [--public PATH]

Serve the API with: ``uvicorn backend.app:create_app --factory``.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from backend import lists
from backend.settings import Settings
from features.lists import load_lists, read_platforms
from phishdrift.config import resolve
from phishdrift.http import HttpClient

log = logging.getLogger("backend")


def fetch_zone_evidence(settings: Settings) -> list[str]:
    """Phishing URL histories from ``lists.open_hosting.evidence_urls`` (cached on disk); a
    failed download is logged and skipped."""
    ocfg = settings.cfg["lists"]["open_hosting"]
    paths = settings.collector["paths"]
    client = HttpClient.from_config(settings.collector["http"], resolve(paths["http_cache_dir"]))
    out: list[str] = []
    for url in ocfg.get("evidence_urls", []):
        try:
            body = client.get(
                url, cache_ttl_s=ocfg["evidence_cache_ttl_s"], timeout_s=ocfg["evidence_timeout_s"]
            )
        except Exception as exc:  # noqa: BLE001 - the zones then come from the other inputs only
            log.warning("zone evidence %s not fetched (%s: %s)", url, type(exc).__name__, exc)
            continue
        got = lists.parse_url_lines(body.decode("utf-8", errors="replace"))
        log.info("%d zone-evidence URLs from %s", len(got), url)
        out += got
    return out


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

    extra = [u for path in args.phishing_file or [] for u in lists.read_phishing_file(Path(path))]
    if not args.no_evidence:
        extra += fetch_zone_evidence(settings)
    docs = lists.build_lists(
        urls,
        candidates,
        read_platforms(),
        lcfg["prefix_bytes"],
        allow_prefix_bytes=lcfg.get("allow_prefix_bytes"),
        sentinel_top_n=lcfg.get("sentinel_top_n", 1000),
        specific_segment_len=lcfg.get("specific_segment_len", 16),
        extra_phishing_urls=extra,
        min_tenant_children=lcfg["open_hosting"]["min_tenant_children"],
        min_children_per_url=lcfg["open_hosting"]["min_children_per_url"],
        min_children_whole=lcfg["open_hosting"].get("min_children_whole"),
        shorteners=load_lists().shorteners,
    )
    out_dir = Path(args.out) if args.out else settings.lists_dir
    key = settings.signing_key()
    if key is None:
        log.warning("no signing key at %s: the manifest is unsigned", settings.signing_key_path)
    lists.write_lists(docs, out_dir, key, lcfg.get("history_keep", 48))
    log.info("wrote %s: %s", out_dir, docs["manifest"])
    return 0


def cmd_make_signing_key(args: argparse.Namespace) -> int:
    settings = Settings.load()
    private = Path(args.private) if args.private else settings.signing_key_path
    targets = [Path(p) for p in (args.public or ["extension/src/lists_pubkey.js"])]
    public = lists.make_signing_key(private, targets)
    log.info("private key %s (keep it secret); public key in %s", private, targets)
    log.info("rebuild or reload the extension so it checks signatures with %s", public["spki"])
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m backend")
    sub = parser.add_subparsers(dest="cmd", required=True)
    build = sub.add_parser("build-lists", help="build the hashed blocklist and allowlist")
    build.add_argument("--tranco-file", help="Tranco CSV/text file (default: the tranco package)")
    build.add_argument(
        "--phishing-file",
        action="append",
        help="extra phishing URLs (parquet/CSV with a url column) used only to find open-hosting "
        "zones, e.g. data/processed/meta_pool.parquet; repeatable",
    )
    build.add_argument(
        "--no-evidence",
        action="store_true",
        help="skip downloading lists.open_hosting.evidence_urls",
    )
    build.add_argument("--out", help="output directory (default: lists.out_dir in backend.yaml)")
    build.set_defaults(func=cmd_build_lists)
    keygen = sub.add_parser("make-signing-key", help="create the ECDSA key that signs the lists")
    keygen.add_argument("--private", help="private key path (default: lists.signing_key)")
    keygen.add_argument(
        "--public",
        action="append",
        help="lists_pubkey.js to write (repeatable; default extension/src/lists_pubkey.js; also "
        "pass the built extension's copy, e.g. extension/dist/lists_pubkey.js)",
    )
    keygen.set_defaults(func=cmd_make_signing_key)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
