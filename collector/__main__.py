"""Collector entry point. Schedule ``run`` every 12 hours (scripts/cron_example.txt).

    python -m collector run                 # feeds, benign crawl, first-seen domain capture
    python -m collector run --no-crawl      # feeds and domain capture only
    python -m collector run --no-capture
    python -m collector crawl --seeds phiusiil   # crawl only (e.g. after `data_pipeline seeds`)

Training feeds go into the first-seen index; blocklist-only feeds (URLhaus) are stored
separately and never become training data. Safe to run more often than every 12 hours:
feed downloads are cached for their polling interval, the index ignores URLs it already
has, the crawler skips seed domains it already tried, and domain capture skips hosts it
already captured.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import UTC, datetime

import pandas as pd

from collector import benign, domain_capture, feeds, store
from phishdrift.config import load_config, resolve
from phishdrift.http import HttpClient

log = logging.getLogger("collector")


def collect_feeds(client: HttpClient, cfg: dict, now: datetime) -> tuple[pd.DataFrame, int]:
    """Fetch every enabled feed. Returns (training rows, number of failed feeds)."""
    paths = cfg["paths"]
    training: list[pd.DataFrame] = []
    failures = 0
    for name, fcfg in cfg["feeds"].items():
        if not fcfg.get("enabled", True):
            continue
        try:
            df = feeds.FETCHERS[name](client, fcfg)
        except Exception as exc:  # noqa: BLE001 - one bad feed must not stop the run
            failures += 1
            log.error("%s: failed: %s", name, exc)
            continue
        if df is None:
            continue
        role = fcfg.get("role", "training")
        out_dir = paths["raw_dir"] if role == "training" else paths["blocklist_dir"]
        store.write_daily(df, resolve(out_dir), now.date(), name)
        log.info("%s (%s): %d urls", name, role, len(df))
        if role == "training":
            training.append(df)
    batch = pd.concat(training, ignore_index=True) if training else pd.DataFrame()
    return batch, failures


def capture_targets(new_feed_rows: pd.DataFrame, crawl_summary: dict) -> list[dict]:
    """Hosts to capture, phishing feed hosts first (they go offline fastest), then the
    live crawl's benign seed domains."""
    rows = new_feed_rows.sort_values("label", ascending=False, kind="stable")
    targets = [
        {"url": r.url, "label": int(r.label), "first_seen": r.first_seen}
        for r in rows.itertuples(index=False)
    ]
    for domain in crawl_summary.get("live", {}).get("domains_with_pages", []):
        targets.append({"url": f"https://{domain}/", "label": 0, "first_seen": None})
    return targets


def run(no_crawl: bool = False, no_capture: bool = False) -> int:
    cfg = load_config("collector")
    paths = cfg["paths"]
    client = HttpClient.from_config(cfg["http"], resolve(paths["http_cache_dir"]))
    now = datetime.now(UTC)

    batch, failures = collect_feeds(client, cfg, now)
    new_rows = pd.DataFrame(columns=store.INDEX_COLUMNS)
    if len(batch):
        index_path = resolve(paths["index_path"])
        index, n_new = store.update_index(store.load_index(index_path), batch, now)
        store.save_index(index, index_path)
        new_rows = index.loc[index["first_seen"] == pd.Timestamp(now)]
        log.info("index: %d new urls, %d total (%s)", n_new, len(index), index_path)
    else:
        log.error("no training feed returned data")
        failures += 1

    crawl_summary: dict = {}
    if not no_crawl and cfg["crawler"].get("enabled", True):
        crawl_summary = run_crawl(client, cfg, now)

    if not no_capture and cfg["domain_capture"].get("enabled", True):
        try:
            domain_capture.capture(
                capture_targets(new_rows, crawl_summary),
                client,
                cfg["domain_capture"],
                resolve(paths["domain_info_dir"]),
                now,
            )
        except Exception as exc:  # noqa: BLE001
            failures += 1
            log.error("domain capture: failed: %s", exc)
    return 0 if failures == 0 else 2


def run_crawl(client: HttpClient, cfg: dict, now: datetime, only: list[str] | None = None):
    paths = cfg["paths"]
    crawler_cfg = {
        **cfg["crawler"],
        "tranco_cache_dir": resolve(cfg["crawler"]["tranco_cache_dir"]),
    }
    return benign.crawl(
        client, crawler_cfg, resolve(paths["crawl_dir"]), resolve(paths["seed_dir"]), now, only
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m collector")
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="feeds, benign crawl and first-seen domain capture")
    r.add_argument("--no-crawl", action="store_true", help="skip the benign inner-page crawl")
    r.add_argument("--no-capture", action="store_true", help="skip RDAP/DNS/TLS capture")
    c = sub.add_parser("crawl", help="benign inner-page crawl only")
    c.add_argument("--seeds", nargs="+", help="seed sets to crawl (default: all)")
    for p in (r, c):
        p.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if args.cmd == "crawl":
        cfg = load_config("collector")
        client = HttpClient.from_config(cfg["http"], resolve(cfg["paths"]["http_cache_dir"]))
        run_crawl(client, cfg, datetime.now(UTC), args.seeds)
        return 0
    return run(no_crawl=args.no_crawl, no_capture=args.no_capture)


if __name__ == "__main__":
    sys.exit(main())
