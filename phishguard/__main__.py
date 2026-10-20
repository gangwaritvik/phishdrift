# ruff: noqa: E501
"""PhishGuard verification study: one command does everything, resumably.

    python -m phishguard all [--data data/processed] [--workers 4]

Steps: prepare (populations + feature cache), run (all jobs in parallel, one file each),
analyze (verdicts + reports/phishguard/verification.md). Rerun the same command to resume.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import yaml

from features.lists import load_lists
from phishguard import analyze, data, run


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="phishguard")
    ap.add_argument("step", choices=["prepare", "run", "analyze", "all"])
    ap.add_argument("--data", type=Path, default=Path("data/processed"))
    ap.add_argument("--out", type=Path, default=Path("data/interim/phishguard"))
    ap.add_argument("--reports", type=Path, default=Path("reports/phishguard"))
    ap.add_argument("--config", type=Path, default=Path("configs/phishguard.yaml"))
    ap.add_argument("--platforms-file", default=None)
    ap.add_argument("--lists-dir", default=None)
    ap.add_argument("--natural-urls", type=Path, default=Path("data/raw/ood/ood_urls.csv"))
    ap.add_argument("--natural-html", type=Path, default=Path("data/raw/ood_html"))
    ap.add_argument("--workers", type=int, default=4)
    a = ap.parse_args(argv)
    cfg = yaml.safe_load(a.config.read_text(encoding="utf-8"))
    lists = load_lists(a.lists_dir, a.platforms_file)
    if a.step in ("prepare", "all"):
        data.prepare(
            a.data,
            a.out,
            cfg,
            lists,
            a.workers,
            a.natural_urls if a.natural_urls.exists() else None,
        )
        data.prepare_natural_b(a.natural_html, a.out, lists)
    if a.step in ("run", "all"):
        failed = run.run_all(a.out, cfg, lists, a.workers)
        if failed:
            print(f"{failed} jobs failed; rerun the same command to retry them", file=sys.stderr)
            return 1
    if a.step in ("analyze", "all"):
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True
        ).stdout.strip()
        print(analyze.write(a.out, a.data, a.reports, cfg, commit or "unknown"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
