"""Collector entry point. Schedule ``run`` every 12 hours (scripts/cron_example.txt).

    python -m collector run                 # feeds, benign crawl, first-seen domain capture
    python -m collector run --no-crawl      # feeds and domain capture only
    python -m collector run --no-capture
    python -m collector crawl --seeds phiusiil   # crawl only (e.g. after `data_pipeline seeds`)
    python -m collector crawl-ood           # legitimate inner pages for the OOD false-positive set

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

from collector import benign, domain_capture, feeds, ood, store
from collector.lock import AlreadyRunning, run_lock
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


def recent_rows(index: pd.DataFrame, now: datetime, hours: float) -> pd.DataFrame:
    """Index rows first seen within the last ``hours``. Using a window instead of only this
    run's new rows means hosts left over from a stopped run, or beyond the per-run capture cap,
    are picked up by the next run (hosts already captured are skipped there)."""
    if not len(index):
        return index
    return index.loc[index["first_seen"] >= pd.Timestamp(now) - pd.Timedelta(hours=hours)]


def capture_targets(new_feed_rows: pd.DataFrame, crawl_summary: dict) -> list[dict]:
    """Hosts to capture, phishing feed hosts first (they go offline fastest, so newest first),
    then the live crawl's benign seed domains."""
    rows = new_feed_rows.sort_values(
        ["label", "first_seen"], ascending=[False, False], kind="stable"
    )
    targets = [
        {"url": r.url, "label": int(r.label), "first_seen": r.first_seen}
        for r in rows.itertuples(index=False)
    ]
    for domain in crawl_summary.get("live", {}).get("domains_with_pages", []):
        targets.append({"url": f"https://{domain}/", "label": 0, "first_seen": None})
    return targets


def benign_targets(cfg: dict, now: datetime) -> list[dict]:
    """Legitimate hosts for tier C: a fresh Tranco sample each run (``domain_capture.benign``),
    excluding every domain in the corpus, the training crawl, the OOD set, the feed index and
    earlier captures. Each domain is captured as ``<domain>`` and ``www.<domain>``, because feed
    phishing hosts are mostly subdomains and a bare-domain-only benign class would make host
    form (CNAME, A records) separate the classes. Label 0; first seen = now."""
    bcfg = cfg["domain_capture"].get("benign") or {}
    if not bcfg.get("enabled", False) or not bcfg.get("per_run"):
        return []
    paths = cfg["paths"]
    processed_dir = resolve(load_config("datasets")["paths"]["processed_dir"])
    exclude, found = ood.excluded_domains(
        cfg["ood"], processed_dir, resolve(paths["crawl_dir"]), resolve(paths["index_path"])
    )
    ood_dir = resolve(paths["ood_dir"])
    for sample in (ood_dir / ood.SAMPLE_NAME, ood_dir.parent / "ood_html" / ood.SAMPLE_NAME):
        if sample.exists():
            exclude |= set(benign.read_seed_file(sample))
    hosts, domains, failures = domain_capture.load_state(resolve(paths["domain_info_dir"]))
    exclude |= hosts | domains | set(failures)
    log.info("benign capture: %d domains excluded (%s)", len(exclude), found or "no corpus files")
    top_n = max(b["to_rank"] for b in bcfg["bands"])
    ranked = benign.tranco_domains(top_n, resolve(cfg["crawler"]["tranco_cache_dir"]))
    run_cfg = {**bcfg, "seed": bcfg["seed"] + now.toordinal() * 2 + now.hour // 12}
    picked = ood.sample_ood_domains(ranked, run_cfg, exclude, ood.load_platforms(), bcfg["per_run"])
    return [
        {"url": f"https://{host}/", "label": 0, "first_seen": pd.Timestamp(now)}
        for d in picked
        for host in (d, f"www.{d}")
    ]


def run(no_crawl: bool = False, no_capture: bool = False) -> int:
    cfg = load_config("collector")
    try:
        with run_lock(resolve(cfg["run"]["lock_path"]), cfg["run"]["lock_stale_s"]):
            return _run(cfg, no_crawl, no_capture)
    except AlreadyRunning as exc:
        log.warning("collector run skipped: %s", exc)
        return 0


def _run(cfg: dict, no_crawl: bool, no_capture: bool) -> int:
    paths = cfg["paths"]
    client = HttpClient.from_config(cfg["http"], resolve(paths["http_cache_dir"]))
    now = datetime.now(UTC)

    batch, failures = collect_feeds(client, cfg, now)
    index_path = resolve(paths["index_path"])
    index = store.load_index(index_path)
    if len(batch):
        index, n_new = store.update_index(index, batch, now)
        store.save_index(index, index_path)
        log.info("index: %d new urls, %d total (%s)", n_new, len(index), index_path)
    else:
        log.error("no training feed returned data")
        failures += 1

    crawl_summary: dict = {}
    if not no_crawl and cfg["crawler"].get("enabled", True):
        try:
            crawl_summary = run_crawl(client, cfg, now)
        except Exception as exc:  # noqa: BLE001 - a crawl failure must not skip domain capture
            failures += 1
            log.error("benign crawl: failed: %s", exc)

    if not no_capture and cfg["domain_capture"].get("enabled", True):
        targets = capture_targets(
            recent_rows(index, now, cfg["domain_capture"]["backlog_hours"]), crawl_summary
        )
        try:
            targets += benign_targets(cfg, now)  # after the feed hosts: phishing goes first
        except Exception as exc:  # noqa: BLE001 - no benign sample must not stop phishing capture
            failures += 1
            log.error("benign capture targets: failed: %s", exc)
        try:
            domain_capture.capture(
                targets,
                client,
                cfg["domain_capture"],
                resolve(paths["domain_info_dir"]),
                now,
            )
        except Exception as exc:  # noqa: BLE001
            failures += 1
            log.error("domain capture: failed: %s", exc)
    return 0 if failures == 0 else 2


def crawler_client(client: HttpClient, cfg: dict) -> HttpClient:
    """The crawler meets many dead sites, so it can use fewer retries and a shorter connect wait."""
    overrides = cfg["crawler"].get("http")
    if not overrides:
        return client
    return HttpClient.from_config(
        {**cfg["http"], **overrides}, resolve(cfg["paths"]["http_cache_dir"])
    )


def run_crawl(client: HttpClient, cfg: dict, now: datetime, only: list[str] | None = None):
    paths = cfg["paths"]
    crawler_cfg = {
        **cfg["crawler"],
        "tranco_cache_dir": resolve(cfg["crawler"]["tranco_cache_dir"]),
    }
    client = crawler_client(client, cfg)
    return benign.crawl(
        client, crawler_cfg, resolve(paths["crawl_dir"]), resolve(paths["seed_dir"]), now, only
    )


def run_crawl_ood(
    sample_size: int | None = None,
    limit: int | None = None,
    resample: bool = False,
    allow_no_exclusions: bool = False,
    html_pass: bool = False,
) -> int:
    """Crawl naturally browsed legitimate inner pages into ``paths.ood_dir`` (evaluation only).
    ``html_pass``: second pass over the sites that gave usable pages in the first one, with the
    HTML stored, into the sibling folder ``ood_html`` (for the page-feature false-alarm check).
    Exit codes: 0 done, 1 refused (no exclusion list found, or ood_dir inside crawl_dir)."""
    cfg = load_config("collector")
    paths, ood_cfg = cfg["paths"], dict(cfg["ood"])
    if sample_size is not None:
        ood_cfg["sample_size"] = sample_size
    ood_dir, crawl_dir = resolve(paths["ood_dir"]), resolve(paths["crawl_dir"])
    first_pass_dir = ood_dir
    if html_pass:
        ood_dir = ood_dir.parent / "ood_html"
        ood_cfg["store_html"] = True
    ood.check_separate_dirs(ood_dir, crawl_dir)
    now = datetime.now(UTC)
    processed_dir = resolve(load_config("datasets")["paths"]["processed_dir"])

    def draw() -> list[str]:
        exclude, found = ood.excluded_domains(
            ood_cfg, processed_dir, crawl_dir, resolve(paths["index_path"])
        )
        log.info("ood: excluded domains by source: %s", found or "none")
        if not any(name.endswith(".parquet") for name in found) and not allow_no_exclusions:
            raise FileNotFoundError(
                f"none of {ood_cfg['exclude_files']} found in {processed_dir}: build the corpus "
                "first (or copy meta_pool.parquet etc. there), or pass --allow-no-exclusions"
            )
        top_n = max(b["to_rank"] for b in ood_cfg["bands"])
        ranked = benign.tranco_domains(top_n, resolve(cfg["crawler"]["tranco_cache_dir"]))
        platforms = ood.load_platforms() if ood_cfg.get("skip_platforms", True) else frozenset()
        return ood.sample_ood_domains(ranked, ood_cfg, exclude, platforms)

    try:
        if html_pass:
            urls_csv = first_pass_dir / "ood_urls.csv"
            if not urls_csv.exists():
                log.error("html pass needs the first pass output %s", urls_csv)
                return 1
            table = pd.read_csv(urls_csv)
            ok = table[table["ok"].astype(str).str.lower() == "true"]
            domains = sorted(set(ok["domain"].astype(str)))
            log.info("ood html pass: %d sites with usable pages in the first pass", len(domains))
        else:
            domains = ood.plan_sample(ood_dir, ood_cfg, draw, now, resample)
    except FileNotFoundError as exc:
        log.error("%s", exc)
        return 1
    client = crawler_client(
        HttpClient.from_config(cfg["http"], resolve(paths["http_cache_dir"])), cfg
    )
    try:
        with run_lock(ood_dir / "crawl_ood.lock", ood_cfg["lock_stale_s"]) as lock:
            summary = ood.crawl_ood(
                client, cfg["crawler"], ood_cfg, ood_dir, domains, now, limit, lock
            )
    except AlreadyRunning as exc:
        log.error("crawl-ood: %s", exc)
        return 1
    log.info("ood crawl finished: %s", summary)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m collector")
    sub = parser.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="feeds, benign crawl and first-seen domain capture")
    r.add_argument("--no-crawl", action="store_true", help="skip the benign inner-page crawl")
    r.add_argument("--no-capture", action="store_true", help="skip RDAP/DNS/TLS capture")
    c = sub.add_parser("crawl", help="benign inner-page crawl only")
    c.add_argument("--seeds", nargs="+", help="seed sets to crawl (default: all)")
    o = sub.add_parser("crawl-ood", help="legitimate inner pages for the OOD false-positive set")
    o.add_argument("--sample-size", type=int, help="override ood.sample_size (first draw only)")
    o.add_argument("--limit", type=int, help="crawl at most this many sites in this run")
    o.add_argument(
        "--resample", action="store_true", help="draw a new sample (done sites stay done)"
    )
    o.add_argument(
        "--allow-no-exclusions",
        action="store_true",
        help="do not require the processed corpus files for the domain exclusion list",
    )
    o.add_argument(
        "--html-pass",
        action="store_true",
        help="second pass over the sites that worked, HTML stored, into data/raw/ood_html",
    )
    for p in (r, c, o):
        p.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    if args.cmd == "crawl":
        cfg = load_config("collector")
        client = HttpClient.from_config(cfg["http"], resolve(cfg["paths"]["http_cache_dir"]))
        try:
            with run_lock(resolve(cfg["run"]["lock_path"]), cfg["run"]["lock_stale_s"]):
                run_crawl(client, cfg, datetime.now(UTC), args.seeds)
        except AlreadyRunning as exc:
            log.warning("crawl skipped: %s", exc)
        return 0
    if args.cmd == "crawl-ood":
        try:
            return run_crawl_ood(
                args.sample_size,
                args.limit,
                args.resample,
                args.allow_no_exclusions,
                args.html_pass,
            )
        except KeyboardInterrupt:
            log.warning("crawl-ood interrupted; finished sites are saved, rerun to continue")
            return 130
    return run(no_crawl=args.no_crawl, no_capture=args.no_capture)


if __name__ == "__main__":
    sys.exit(main())
