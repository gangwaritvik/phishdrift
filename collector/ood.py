"""Out-of-distribution legitimate pages: the evaluation-only set for "OOD false-positive rate".

CLAUDE.md asks for the false-positive rate of every model on legitimate inner pages that were
not part of any training pool. This module picks such sites and lists their inner pages.

Selection (``configs/collector.yaml`` -> ``ood``)
  * domains come from the Tranco list (popularity only chooses seeds: the rank is never
    written to any file, so it cannot become a feature);
  * the head of the list (``skip_top_n``) is skipped, and so is every registrable domain that
    appears in the processed pool, time slice, held-out source or eval-only parts, in the
    benign crawl log, or in the live-feed index, and hosting platforms
    (``configs/platforms.yaml``);
  * a fixed number of domains (``sample_size``) is drawn with a fixed seed, spread over rank
    bands. The sample is saved in ``ood_sample.txt`` the first time and reused on reruns, so a
    stopped run continues with the same sites even if Tranco published a new list meanwhile.

Crawl: 3-5 inner pages per site with the benign crawler's ``crawl_domain`` (robots.txt, Crawl-delay,
per-site deadline, per-download cap, parallel workers). HTML is stored only when
``ood.store_html`` is true (default false: URLs and crawl status only).

Output goes to ``paths.ood_dir`` (default ``data/raw/ood``), a folder the corpus build never
reads (it reads ``paths.crawl_dir`` only; the two folders may not be nested):
  ood_sample.txt            the sampled domains, in crawl order
  attempts.parquet          every site tried and its outcome (status ``timed_out`` etc.)
  pages/YYYY-MM-DD.parquet  url, domain, origin ("ood"), html, crawled_at
  ood_urls.csv              url, domain, label (always 0), crawled_at, ok: the small file to copy
                            to the cloud. ``ok`` is true for a page URL found by the crawler
                            (and fetched, if ``store_html``); a site that could not be crawled
                            (robots.txt unreadable or forbidding, Crawl-delay too long, timeout,
                            no pages) has one row with its homepage URL and ``ok`` false. Use
                            only ``ok == true`` rows as evaluation URLs.
"""

from __future__ import annotations

import logging
import os
import random
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq
import yaml

from collector import benign, store
from collector.lock import Lock
from phishdrift.config import CONFIG_DIR
from phishdrift.domains import normalize_url, registered_domain

log = logging.getLogger(__name__)

OOD = "ood"
CSV_NAME = "ood_urls.csv"
SAMPLE_NAME = "ood_sample.txt"
CSV_COLUMNS = ["url", "domain", "label", "crawled_at", "ok"]
PAGE_COLUMNS = ["url", "domain", "origin", "html", "crawled_at"]


# --- guards ----------------------------------------------------------------------------


def check_separate_dirs(ood_dir: Path, crawl_dir: Path) -> None:
    """The corpus build ingests ``crawl_dir``; the OOD folder must be neither it nor inside it
    (nor contain it), or OOD pages could end up in training data."""
    a, b = Path(ood_dir).resolve(), Path(crawl_dir).resolve()
    if a == b or a in b.parents or b in a.parents:
        raise ValueError(f"paths.ood_dir ({a}) must be separate from paths.crawl_dir ({b})")


# --- exclusions ------------------------------------------------------------------------


def _parquet_domains(path: Path) -> set[str]:
    table = pq.read_table(path, columns=["domain"])  # one column only: pool.parquet holds HTML
    return {str(d).strip().lower() for d in table.column("domain").to_pylist() if d}


def excluded_domains(
    ood_cfg: dict, processed_dir: Path, crawl_dir: Path, index_path: Path
) -> tuple[set[str], dict[str, int]]:
    """Registrable domains the OOD set must not contain, and how many came from where."""
    found: dict[str, int] = {}
    out: set[str] = set()

    def add(label: str, domains: set[str]) -> None:
        found[label] = len(domains)
        out.update(domains)

    for name in ood_cfg["exclude_files"]:
        path = Path(processed_dir) / name
        if path.exists():
            add(name, _parquet_domains(path))
    if ood_cfg.get("exclude_crawl_attempts", True):
        attempts = store.load_attempts(crawl_dir)
        add("crawl attempts", {str(d).lower() for d in attempts["seed_domain"]})
    if ood_cfg.get("exclude_feed_index", True) and Path(index_path).exists():
        urls = store.load_index(index_path)["url"]
        add("feed index", {d for d in urls.map(registered_domain) if d})
    return out, found


def load_platforms(path: Path | None = None) -> frozenset[str]:
    path = path or CONFIG_DIR / "platforms.yaml"
    with Path(path).open(encoding="utf-8") as fh:
        return frozenset(str(d).lower() for d in (yaml.safe_load(fh) or {}).get("platforms", []))


# --- sampling --------------------------------------------------------------------------


def band_quotas(bands: list[dict], n: int) -> list[int]:
    """Domains to draw per band: ``n`` split by ``share`` (the last band takes the rounding)."""
    total = sum(b["share"] for b in bands)
    quotas = [int(n * b["share"] / total) for b in bands]
    quotas[-1] += n - sum(quotas)
    return quotas


def sample_ood_domains(
    ranked: list[str],
    ood_cfg: dict,
    exclude: set[str],
    platforms: frozenset[str] = frozenset(),
    n: int | None = None,
) -> list[str]:
    """Seeded sample of ``n`` domains from the Tranco-ordered ``ranked`` list.

    Bands are rank ranges (1-based, inclusive) from the config, cut off below
    ``skip_top_n``. Within a band candidates are visited in a seeded random order and kept
    when they are a registrable domain, not excluded and not a hosting platform. The result
    is shuffled (seeded) so any prefix of it covers every band. Rank is used here only.
    """
    n = ood_cfg["sample_size"] if n is None else n
    seed = ood_cfg["seed"]
    skip = ood_cfg["skip_top_n"]
    chosen: list[str] = []
    taken: set[str] = set()
    quotas = band_quotas(ood_cfg["bands"], n)
    for i, (band, quota) in enumerate(zip(ood_cfg["bands"], quotas, strict=True), 1):
        lo = max(band["from_rank"], skip + 1)
        hi = min(band["to_rank"], len(ranked))
        if lo > hi:
            log.warning("band %d (%s-%s) is empty", i, band["from_rank"], band["to_rank"])
            continue
        order = list(range(lo - 1, hi))
        random.Random(seed * 100 + i).shuffle(order)
        kept = 0
        for pos in order:
            if kept >= quota:
                break
            d = ranked[pos].strip().lower()
            if d in exclude or d in taken or d in platforms:
                continue
            if registered_domain(f"https://{d}/") != d:  # not a registrable domain
                continue
            chosen.append(d)
            taken.add(d)
            kept += 1
        if kept < quota:
            log.warning("band %d: only %d of %d domains available", i, kept, quota)
    random.Random(seed).shuffle(chosen)
    return chosen


def write_sample(domains: list[str], path: Path, ood_cfg: dict, now: datetime) -> None:
    header = (
        f"# OOD sample drawn {now.date().isoformat()}: seed {ood_cfg['seed']}, "
        f"{len(domains)} registrable domains, head of {ood_cfg['skip_top_n']} skipped.\n"
        "# Crawl order. Delete this file to draw a new sample (done sites are never repeated).\n"
    )
    tmp = Path(path).with_name(Path(path).name + ".tmp")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(header + "\n".join(domains) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def plan_sample(
    ood_dir: Path,
    ood_cfg: dict,
    draw: Callable[[], list[str]],
    now: datetime,
    resample: bool = False,
) -> list[str]:
    """The saved sample, or a fresh one from ``draw()`` (saved for reruns). ``draw`` is not
    called when a sample exists, so a rerun needs no network access for seeds."""
    path = Path(ood_dir) / SAMPLE_NAME
    if path.exists() and not resample:
        domains = benign.read_seed_file(path)
        log.info("ood: reusing the saved sample of %d domains (%s)", len(domains), path)
        return domains
    domains = draw()
    write_sample(domains, path, ood_cfg, now)
    log.info("ood: drew a sample of %d domains -> %s", len(domains), path)
    return domains


# --- storage ---------------------------------------------------------------------------


def append_pages(df: pd.DataFrame, ood_dir: Path, day: str) -> Path:
    """Append crawled pages to ``pages/<day>.parquet`` (atomic replace)."""
    out = Path(ood_dir) / "pages" / f"{day}.parquet"
    if out.exists():
        df = pd.concat([pd.read_parquet(out), df], ignore_index=True)
    return store.atomic_parquet(df[PAGE_COLUMNS], out)


def load_pages(ood_dir: Path) -> pd.DataFrame:
    files = sorted((Path(ood_dir) / "pages").glob("*.parquet"))
    if not files:
        return pd.DataFrame(columns=PAGE_COLUMNS)
    return pd.concat([pd.read_parquet(f) for f in files], ignore_index=True)


def build_urls_table(pages: pd.DataFrame, attempts: pd.DataFrame) -> pd.DataFrame:
    """The ``ood_urls.csv`` rows: every page (ok), plus one homepage row per site that gave
    no page (not ok). A page URL is listed once (first crawl kept)."""
    rows = pd.DataFrame(
        {
            "url": pages["url"],
            "domain": pages["domain"],
            "label": 0,
            "crawled_at": pd.to_datetime(pages["crawled_at"], utc=True),
            "ok": True,
        }
    )
    rows = rows.assign(_k=rows["url"].map(normalize_url)).sort_values("crawled_at", kind="stable")
    rows = rows.drop_duplicates("_k").drop(columns="_k")
    ood = attempts.loc[attempts["seed_source"] == OOD].drop_duplicates("seed_domain", keep="last")
    bad = ood.loc[~ood["seed_domain"].isin(set(rows["domain"]))]  # no page found for this site
    failed = pd.DataFrame(
        {
            "url": "https://" + bad["seed_domain"].astype(str) + "/",
            "domain": bad["seed_domain"].astype(str),
            "label": 0,
            "crawled_at": pd.to_datetime(bad["attempted_at"], utc=True),
            "ok": False,
        }
    )
    parts = [p for p in (rows, failed) if len(p)]
    out = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=CSV_COLUMNS)
    return out[CSV_COLUMNS].sort_values(["domain", "url"], kind="stable").reset_index(drop=True)


def write_urls_csv(ood_dir: Path) -> Path:
    table = build_urls_table(load_pages(ood_dir), store.load_attempts(ood_dir))
    path = Path(ood_dir) / CSV_NAME
    tmp = path.with_name(path.name + ".tmp")
    table["crawled_at"] = table["crawled_at"].map(lambda t: t.isoformat() if pd.notna(t) else "")
    table.to_csv(tmp, index=False, lineterminator="\n", encoding="utf-8")
    os.replace(tmp, path)
    return path


# --- crawl -----------------------------------------------------------------------------


def _eta(done: int, total: int, elapsed_s: float) -> str:
    if done <= 0 or elapsed_s <= 0:
        return "n/a"
    left_s = (total - done) * elapsed_s / done
    return f"{int(left_s // 3600)}h{int(left_s % 3600 // 60):02d}m"


def crawl_ood(
    client,
    crawl_cfg: dict,
    ood_cfg: dict,
    ood_dir: Path,
    domains: list[str],
    now: datetime,
    limit: int | None = None,
    lock: Lock | None = None,
    parallel=benign.run_parallel,
) -> dict:
    """Crawl the sample's sites that have no attempt yet. Safe to stop (Ctrl+C or kill) and
    rerun: finished sites are saved every ``checkpoint_every`` sites and when the loop ends or
    is interrupted. Returns a summary."""
    ood_dir = Path(ood_dir)
    site_cfg = {
        **crawl_cfg,
        **{
            k: ood_cfg[k]
            for k in (
                "store_html",
                "inner_pages_min",
                "inner_pages_max",
                "workers",
                "domain_deadline_s",
            )
            if k in ood_cfg
        },
    }
    attempts = store.load_attempts(ood_dir)
    done = set(attempts.loc[attempts["seed_source"] == OOD, "seed_domain"])
    todo = [(i, d) for i, d in enumerate(domains) if d not in done]
    if limit is not None:
        todo = todo[:limit]
    total = len(domains)
    before = len(done & set(domains))
    workers = max(1, int(site_cfg.get("workers", 1)))
    chunk = max(1, int(ood_cfg["checkpoint_every"]))
    hard_limit_s = site_cfg.get("domain_deadline_s", 240) + 180  # deadline + a slow last request
    base_seed = ood_cfg["seed"]
    day = now.date().isoformat()
    log.info(
        "ood crawl: %d sites in the sample, %d done, %d to crawl now (%d workers)",
        total,
        before,
        len(todo),
        workers,
    )

    def one(item: tuple[int, str]) -> benign.DomainResult:
        i, domain = item
        try:
            return benign.crawl_domain(client, domain, site_cfg, base_seed + i, False)
        except Exception as exc:  # noqa: BLE001 - one bad site must not stop the run
            log.debug("ood crawl %s: %s", domain, exc)
            return benign.DomainResult(domain, benign.ERROR, [])

    statuses: dict[str, int] = {}
    n_pages = 0
    chunk_pages: list[dict] = []
    chunk_log: list[dict] = []
    started = time.monotonic()
    n_done = 0

    def flush() -> bool:
        nonlocal chunk_pages, chunk_log
        if not chunk_log:
            return False
        # Pages first, then the attempt log: a stop in between re-crawls those sites, and
        # the duplicate pages are dropped when ood_urls.csv is built.
        if chunk_pages:
            append_pages(pd.DataFrame(chunk_pages, columns=PAGE_COLUMNS), ood_dir, day)
        store.append_attempts(pd.DataFrame(chunk_log, columns=store.ATTEMPT_COLUMNS), ood_dir)
        write_urls_csv(ood_dir)
        chunk_pages, chunk_log = [], []
        if lock is not None:
            lock.touch()
        return True

    def progress() -> None:
        ok = statuses.get(benign.OK, 0)
        few = statuses.get(benign.FEW_PAGES, 0)
        failed = n_done - ok - few
        log.info(
            "ood crawl: %d/%d sites (%.1f%%) | this run: ok %d, few pages %d, failed %d | "
            "%d pages | eta %s",
            before + n_done,
            total,
            100 * (before + n_done) / max(total, 1),
            ok,
            few,
            failed,
            n_pages,
            _eta(n_done, len(todo), time.monotonic() - started),
        )

    try:
        for (_, domain), res in parallel(todo, one, workers, hard_limit_s):
            if res is None:  # abandoned: a stuck site is recorded and skipped on reruns
                res = benign.DomainResult(domain, benign.TIMED_OUT, [])
            n_done += 1
            statuses[res.status] = statuses.get(res.status, 0) + 1
            n_pages += len(res.pages)
            chunk_log.append(
                {
                    "seed_source": OOD,
                    "seed_domain": res.domain,
                    "status": res.status,
                    "pages": len(res.pages),
                    "attempted_at": datetime.now(UTC),
                }
            )
            chunk_pages += [
                {
                    "url": p["url"],
                    "domain": res.domain,
                    "origin": OOD,
                    "html": p["html"],
                    "crawled_at": datetime.now(UTC),
                }
                for p in res.pages
            ]
            if len(chunk_log) >= chunk and flush():
                progress()
    finally:  # also on Ctrl+C: keep every site that finished
        if flush():
            progress()
    csv_path = write_urls_csv(ood_dir)
    return {
        "sites_in_sample": total,
        "done_before": before,
        "crawled_now": n_done,
        "pages_now": n_pages,
        "status_now": statuses,
        "csv": str(csv_path),
    }
