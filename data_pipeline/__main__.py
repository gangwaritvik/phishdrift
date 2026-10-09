"""Build the pooled corpus.

    python -m data_pipeline build                    # load every available source, then build
    python -m data_pipeline build --reuse-interim    # skip re-loading sources already converted
    python -m data_pipeline build --reuse-interim --reload live phiusiil   # refresh just these
    python -m data_pipeline build --sources phiusiil live phreshphish
    python -m data_pipeline inspect phish360         # raw column names, to check the config
    python -m data_pipeline seeds                    # crawl seed lists from homepage-only sources

A source that cannot be loaded (not downloaded yet, missing dependency, no network) is
skipped with an error; the build continues with the others and the data card lists what
was used. The build fails if the depth check fails.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

import pyarrow.parquet as pq

from collector.store import load_attempts
from data_pipeline import sources
from data_pipeline.corpus import DepthImbalanceError
from data_pipeline.pipeline import build
from phishdrift.config import load_config, resolve

log = logging.getLogger("data_pipeline")


def _config() -> dict:
    cfg = load_config("datasets")
    cfg["paths"] = {k: str(resolve(v)) for k, v in cfg["paths"].items()}
    return cfg


def write_seeds(cfg: dict) -> dict[str, int]:
    """Benign registrable domains of homepage-only sources -> crawl seed lists."""
    interim_dir = Path(cfg["paths"]["interim_dir"])
    seed_dir = resolve(load_config("collector")["paths"]["seed_dir"])
    seed_dir.mkdir(parents=True, exist_ok=True)
    written = {}
    for name, scfg in cfg["sources"].items():
        path = interim_dir / f"{name}.parquet"
        if not scfg.get("homepage_only_benign") or not path.exists():
            continue
        df = pq.read_table(path, columns=["domain", "label", "origin"]).to_pandas()
        domains = sorted(set(df.loc[(df["label"] == 0) & (df["origin"] != "crawl"), "domain"]))
        (seed_dir / f"{name}.txt").write_text("\n".join(domains) + "\n")
        written[name] = len(domains)
        log.info("seeds: %d %s benign domains -> %s", len(domains), name, seed_dir / f"{name}.txt")
    return written


def run_build(names: list[str], reuse_interim: bool, reload: list[str] | None = None) -> int:
    cfg = _config()
    split_cfg = load_config("splits")
    interim_dir = Path(cfg["paths"]["interim_dir"])
    interim_dir.mkdir(parents=True, exist_ok=True)
    stats_path = interim_dir / "load_stats.json"
    load_stats = json.loads(stats_path.read_text()) if stats_path.exists() else {}

    interim, failed = {}, []
    for name in names:
        path = interim_dir / f"{name}.parquet"
        try:
            if not (
                reuse_interim
                and path.exists()
                and sources.interim_complete(path)
                and name not in (reload or [])
            ):
                path, load_stats[name] = sources.load_source_to_interim(name, cfg)
                stats_path.write_text(json.dumps(load_stats, indent=2))
            interim[name] = path
        except Exception as exc:  # noqa: BLE001 - report and continue with other sources
            log.error("%s: skipped: %s", name, exc)
            failed.append(name)
    if not interim:
        log.error("no source could be loaded")
        return 1
    write_seeds(cfg)
    attempts = load_attempts(resolve(load_config("collector")["paths"]["crawl_dir"]))
    try:
        build(interim, cfg, split_cfg, load_stats, attempts)
    except DepthImbalanceError as exc:
        log.error("depth check failed (see reports/data_card.md): %s", exc)
        return 3
    log.info("built from %s; skipped: %s", ", ".join(interim), ", ".join(failed) or "none")
    return 0 if not failed else 2


def main(argv: list[str] | None = None) -> int:
    all_sources = list(load_config("datasets")["sources"])
    parser = argparse.ArgumentParser(prog="python -m data_pipeline")
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="load sources, build the pooled corpus, splits and data card")
    b.add_argument("--sources", nargs="+", choices=all_sources, default=all_sources)
    b.add_argument("--reuse-interim", action="store_true")
    b.add_argument("--reload", nargs="+", choices=all_sources, help="with --reuse-interim")
    i = sub.add_parser("inspect", help="print raw columns of a source")
    i.add_argument("source", choices=all_sources)
    sub.add_parser("seeds", help="write crawl seed lists from homepage-only sources")
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    if args.cmd == "inspect":
        print(sources.inspect(args.source, _config()))
        return 0
    if args.cmd == "seeds":
        write_seeds(_config())
        return 0
    return run_build(args.sources, args.reuse_interim, args.reload)


if __name__ == "__main__":
    sys.exit(main())
