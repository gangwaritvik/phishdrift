"""Daily collector entry point.

    python -m collector run            # feeds + benign sample for today (UTC)
    python -m collector run --no-benign

Safe to run more than once a day: feed downloads are cached for their polling interval
and the first-seen index ignores URLs it already has.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import UTC, datetime

import pandas as pd

from collector import benign, feeds, store
from phishdrift.config import load_config, resolve
from phishdrift.http import HttpClient

log = logging.getLogger("collector")


def run(no_benign: bool = False) -> int:
    cfg = load_config("collector")
    paths = cfg["paths"]
    client = HttpClient.from_config(cfg["http"], resolve(paths["http_cache_dir"]))
    now = datetime.now(UTC)
    day = now.date()

    batches: list[pd.DataFrame] = []
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
        store.write_daily(df, resolve(paths["raw_dir"]), day, name)
        log.info("%s: %d urls", name, len(df))
        batches.append(df)

    if not no_benign and cfg["benign"].get("enabled", True):
        try:
            bdf = benign.collect_benign(client, cfg["benign"], day)
            store.write_daily(bdf, resolve(paths["raw_dir"]), day, "benign")
            log.info("benign: %d urls", len(bdf))
            batches.append(bdf[feeds.FEED_COLUMNS])
        except Exception as exc:  # noqa: BLE001
            failures += 1
            log.error("benign: failed: %s", exc)

    if not batches:
        log.error("nothing collected")
        return 1

    index_path = resolve(paths["index_path"])
    index, n_new = store.update_index(
        store.load_index(index_path), pd.concat(batches, ignore_index=True), now
    )
    store.save_index(index, index_path)
    log.info("index: %d new urls, %d total (%s)", n_new, len(index), index_path)
    return 0 if failures == 0 else 2


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m collector")
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="collect today's feeds and benign sample")
    r.add_argument("--no-benign", action="store_true", help="skip the Tranco benign crawl")
    r.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    return run(no_benign=args.no_benign)


if __name__ == "__main__":
    sys.exit(main())
