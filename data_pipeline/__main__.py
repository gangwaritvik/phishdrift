"""Build the processed datasets.

    python -m data_pipeline build                         # all datasets
    python -m data_pipeline build --datasets phiusiil     # one dataset
    python -m data_pipeline build --reuse-interim         # skip downloading/converting
    python -m data_pipeline inspect phreshphish           # check raw column names

Datasets that cannot be loaded (missing dependency, no network, no collector data yet)
are skipped with an error message; the others are still built.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

from data_pipeline import loaders
from data_pipeline.datacard import write_card
from data_pipeline.pipeline import build_dataset
from phishdrift.config import load_config, resolve

log = logging.getLogger("data_pipeline")
ALL = list(loaders.LOADERS)


def build(datasets: list[str], reuse_interim: bool) -> int:
    cfg = load_config("datasets")
    split_cfg = load_config("splits")
    cfg["paths"] = {k: str(resolve(v)) for k, v in cfg["paths"].items()}
    interim_dir = resolve(cfg["paths"]["interim_dir"])
    stats_path = interim_dir / "load_stats.json"
    load_stats = json.loads(stats_path.read_text()) if stats_path.exists() else {}

    cards, failed = [], []
    for name in datasets:
        interim = interim_dir / f"{name}.parquet"
        try:
            if not (reuse_interim and interim.exists()):
                interim, load_stats[name] = loaders.load_dataset_to_interim(name, cfg)
                interim_dir.mkdir(parents=True, exist_ok=True)
                stats_path.write_text(json.dumps(load_stats, indent=2))
            cards.append(build_dataset(name, interim, cfg, split_cfg, load_stats.get(name)))
        except Exception as exc:  # noqa: BLE001 - report and continue with other datasets
            log.error("%s: skipped: %s", name, exc)
            failed.append(name)

    if cards:
        md, csv = write_card(cards, resolve(cfg["paths"]["reports_dir"]))
        log.info("data card: %s, %s", md, csv)
    if failed:
        log.error("failed: %s", ", ".join(failed))
    return 0 if not failed else (2 if cards else 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m data_pipeline")
    sub = parser.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="load, dedup, split and write the data card")
    b.add_argument("--datasets", nargs="+", choices=ALL, default=ALL)
    b.add_argument("--reuse-interim", action="store_true")
    i = sub.add_parser("inspect", help="print raw columns of a dataset")
    i.add_argument("dataset", choices=["phreshphish", "phiusiil"])
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    if args.cmd == "inspect":
        print(loaders.inspect(args.dataset, load_config("datasets")))
        return 0
    return build(args.datasets, args.reuse_interim)


if __name__ == "__main__":
    sys.exit(main())
