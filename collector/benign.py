"""Benign inner-page crawler.

Seed sets (configs/collector.yaml ``crawler.seeds``):
  live      Tranco top domains via the ``tranco`` package; pages belong to the live source
  phiusiil  PhiUSIIL legitimate domains   (seed file from ``python -m data_pipeline seeds``)
  urlphish  URL-Phish benign domains      (same)

Per seed domain: read robots.txt with ``urllib.robotparser``; skip the domain if robots.txt
cannot be read (5xx, network error), forbids everything, or asks for a Crawl-delay above
``max_crawl_delay_s``. Otherwise find inner pages from its sitemaps (falling back to
homepage links), keep only URLs robots.txt allows, pick 3-5 and fetch their HTML, waiting
at least the Crawl-delay between requests. Only benign seed domains are crawled here. The
Tranco rank is never stored, so it cannot become a feature.

Every attempted domain is logged (``crawl_dir/attempts.parquet``) so later runs move on to
new domains, and the data card can report crawl success.
"""

from __future__ import annotations

import gzip
import logging
import random
import re
import zlib
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from urllib.parse import urljoin
from urllib.robotparser import RobotFileParser

import pandas as pd
import requests

from collector import store
from phishdrift.domains import normalize_url, registered_domain
from phishdrift.http import HttpClient

log = logging.getLogger(__name__)

_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_HREF_RE = re.compile(r"""<a\s[^>]*?href\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)
_SKIP_EXT = re.compile(r"\.(?:jpe?g|png|gif|svg|webp|ico|pdf|zip|gz|mp4|mp3|css|js|xml)$", re.I)

# Crawl outcomes written to the attempts log.
OK, FEW_PAGES, NO_PAGES, ERROR = "ok", "few_pages", "no_pages", "error"
ROBOTS_UNREADABLE, ROBOTS_DISALLOW_ALL, CRAWL_DELAY_TOO_LONG = (
    "robots_unreadable",
    "robots_disallow_all",
    "crawl_delay_too_long",
)


# --- seeds -----------------------------------------------------------------------------


def tranco_domains(top_n: int, cache_dir: Path) -> list[str]:
    """Latest Tranco list (top ``top_n``), cached on disk by the ``tranco`` package."""
    from tranco import Tranco  # imported lazily: only the live seed set needs it

    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    return Tranco(cache_dir=str(cache_dir)).list().top(top_n)


def read_seed_file(path: Path) -> list[str]:
    if not Path(path).exists():
        raise FileNotFoundError(f"{path} not found; run `python -m data_pipeline seeds` first")
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [ln.strip().lower() for ln in lines if ln.strip() and not ln.startswith("#")]


def sample_domains(domains: list[str], k: int, seed: int, exclude: set[str]) -> list[str]:
    """Seeded sample of ``k`` domains not in ``exclude`` (already attempted)."""
    pool = sorted({d for d in domains if d not in exclude})
    return sorted(random.Random(seed).sample(pool, min(k, len(pool))))


def run_seed(day: date, name: str) -> int:
    """Seed that varies by day and seed set, stable across runs on the same day."""
    return day.toordinal() * 1000 + zlib.crc32(name.encode()) % 1000


# --- robots.txt and sitemaps -----------------------------------------------------------


@dataclass
class Robots:
    parser: RobotFileParser
    user_agent: str

    def allowed(self, url: str) -> bool:
        return self.parser.can_fetch(self.user_agent, url)

    @property
    def crawl_delay(self) -> float | None:
        delay = self.parser.crawl_delay(self.user_agent)
        return float(delay) if delay is not None else None

    @property
    def sitemaps(self) -> list[str]:
        return list(self.parser.site_maps() or [])


def parse_robots(text: str | None, user_agent: str, status: int = 200) -> Robots:
    """robots.txt rules, following ``urllib.robotparser``'s conventions for missing files:
    401/403 means nothing may be fetched; any other 4xx means everything may."""
    rp = RobotFileParser()
    if status in (401, 403):
        rp.disallow_all = True
    elif 400 <= status < 500:
        rp.allow_all = True
    rp.parse((text or "").splitlines())
    return Robots(rp, user_agent)


def fetch_robots(client: HttpClient, homepage: str, max_bytes: int) -> Robots | None:
    """None when robots.txt cannot be read (5xx or network error): the domain is skipped."""
    url = urljoin(homepage, "/robots.txt")
    try:
        return parse_robots(_decode(client.get(url, max_bytes=max_bytes)), client.user_agent)
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else 500
        if status >= 500:
            return None
        return parse_robots(None, client.user_agent, status)
    except requests.RequestException as exc:
        log.debug("%s: %s", url, exc)
        return None


def _decode(body: bytes) -> str:
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)
    return body.decode("utf-8", errors="replace")


def parse_sitemap_locs(xml_text: str) -> tuple[list[str], bool]:
    """Return (<loc> URLs, is_sitemap_index)."""
    return _LOC_RE.findall(xml_text), "<sitemapindex" in xml_text[:2000].lower()


def extract_same_site_links(html: str, base_url: str) -> list[str]:
    """Absolute http(s) links on ``html`` whose registrable domain matches ``base_url``'s."""
    site = registered_domain(base_url)
    out = []
    for href in _HREF_RE.findall(html):
        url = urljoin(base_url, href.strip())
        if url.startswith(("http://", "https://")) and registered_domain(url) == site:
            out.append(url)
    return out


def select_inner_pages(
    candidates: list[str], homepage: str, k: int, seed: int, robots: Robots | None = None
) -> list[str]:
    """Up to ``k`` distinct same-site inner pages: not the homepage, not static files, and
    allowed by robots.txt."""
    home = normalize_url(homepage)
    site = registered_domain(homepage)
    seen, pages = set(), []
    for url in candidates:
        url = url.strip()
        if not url.startswith(("http://", "https://")) or registered_domain(url) != site:
            continue
        norm = normalize_url(url)
        path = norm.split("://", 1)[-1].partition("/")[2]
        if norm == home or not path or _SKIP_EXT.search(path.split("?")[0]) or norm in seen:
            continue
        if robots is not None and not robots.allowed(url):
            continue
        seen.add(norm)
        pages.append(url)
    return sorted(random.Random(seed).sample(pages, min(k, len(pages))))


# --- one domain ------------------------------------------------------------------------


@dataclass
class DomainResult:
    domain: str
    status: str
    pages: list[dict]


def crawl_domain(
    client: HttpClient, domain: str, cfg: dict, seed: int, include_homepage: bool
) -> DomainResult:
    """Fetch 3-5 robots-allowed inner pages of ``domain`` (plus the homepage if asked)."""
    homepage = f"https://{domain}/"
    max_bytes = cfg["max_page_bytes"]
    robots = fetch_robots(client, homepage, max_bytes)
    if robots is None:
        return DomainResult(domain, ROBOTS_UNREADABLE, [])
    if robots.parser.disallow_all:
        return DomainResult(domain, ROBOTS_DISALLOW_ALL, [])
    delay = robots.crawl_delay
    if delay is not None and delay > cfg["max_crawl_delay_s"]:
        return DomainResult(domain, CRAWL_DELAY_TOO_LONG, [])

    def get(url: str) -> str:
        return _decode(client.get(url, max_bytes=max_bytes, min_interval_s=delay))

    candidates: list[str] = []
    for sm in (robots.sitemaps or [urljoin(homepage, "/sitemap.xml")])[
        : cfg["max_sitemaps_per_domain"]
    ]:
        if not robots.allowed(sm):
            continue
        try:
            locs, is_index = parse_sitemap_locs(get(sm))
            if is_index and locs and robots.allowed(locs[0]):
                locs, _ = parse_sitemap_locs(get(locs[0]))
            candidates.extend(locs)
        except requests.RequestException as exc:
            log.debug("%s sitemap %s: %s", domain, sm, exc)

    home_html = None
    if robots.allowed(homepage) and (include_homepage or not candidates):
        try:
            home_html = get(homepage)
        except requests.RequestException as exc:
            log.debug("%s homepage: %s", domain, exc)
    if not candidates and home_html:
        candidates = extract_same_site_links(home_html, homepage)

    chosen = select_inner_pages(candidates, homepage, cfg["inner_pages_max"], seed, robots)
    pages = []
    if include_homepage and home_html is not None:
        pages.append({"url": homepage, "html": home_html if cfg["store_html"] else None})
    for url in chosen:
        html = None
        if cfg["store_html"]:
            try:
                html = get(url)
            except requests.RequestException as exc:
                log.debug("%s: %s", url, exc)
                continue  # dead sitemap entry: not a usable page
        pages.append({"url": url, "html": html})

    n_inner = len(pages) - (1 if include_homepage and home_html is not None else 0)
    status = NO_PAGES if n_inner == 0 else FEW_PAGES if n_inner < cfg["inner_pages_min"] else OK
    if n_inner == 0 and not robots.allowed(homepage):
        status = ROBOTS_DISALLOW_ALL
    return DomainResult(domain, status, pages)


# --- one run ---------------------------------------------------------------------------


def seed_domains(name: str, scfg: dict, cfg: dict, seed_dir: Path) -> list[str]:
    if scfg["from"] == "tranco":
        return tranco_domains(scfg["top_n"], Path(cfg["tranco_cache_dir"]))
    if scfg["from"] == "seed_file":
        return read_seed_file(Path(seed_dir) / f"{name}.txt")
    raise ValueError(f"unknown seed type {scfg['from']!r} for {name}")


def crawl(
    client: HttpClient,
    cfg: dict,
    crawl_dir: Path,
    seed_dir: Path,
    now: datetime,
    only: list[str] | None = None,
) -> dict[str, dict]:
    """Crawl each seed set once. Returns per seed set: domains tried, pages kept, the
    seed domains that yielded pages, and outcome counts."""
    attempts = store.load_attempts(crawl_dir)
    summary: dict[str, dict] = {}
    for name, scfg in cfg["seeds"].items():
        if only and name not in only:
            continue
        try:
            domains = seed_domains(name, scfg, cfg, seed_dir)
        except Exception as exc:  # noqa: BLE001 - a missing seed list must not stop the run
            log.error("crawl %s: no seeds: %s", name, exc)
            continue
        done = set(attempts.loc[attempts["seed_source"] == name, "seed_domain"])
        picked = sample_domains(domains, scfg["domains_per_run"], run_seed(now.date(), name), done)
        rows, log_rows = [], []
        for i, domain in enumerate(picked):
            try:
                res = crawl_domain(
                    client, domain, cfg, run_seed(now.date(), name) + i, scfg["include_homepage"]
                )
            except Exception as exc:  # noqa: BLE001 - one bad site must not stop the run
                log.debug("crawl %s: %s", domain, exc)
                res = DomainResult(domain, ERROR, [])
            log_rows.append(
                {
                    "seed_source": name,
                    "seed_domain": domain,
                    "status": res.status,
                    "pages": len(res.pages),
                    "attempted_at": now,
                }
            )
            rows += [{**p, "seed_source": name, "seed_domain": domain} for p in res.pages]
        if rows:
            pages = pd.DataFrame(rows).assign(crawled_at=now)
            store.write_crawl(pages, crawl_dir, now.date(), name)
        store.append_attempts(pd.DataFrame(log_rows, columns=store.ATTEMPT_COLUMNS), crawl_dir)
        statuses = pd.Series([r["status"] for r in log_rows], dtype=object).value_counts()
        summary[name] = {
            "domains": len(picked),
            "pages": len(rows),
            "domains_with_pages": sorted({r["seed_domain"] for r in rows}),
            "status": {k: int(v) for k, v in statuses.items()},
        }
        log.info("crawl %s: %d domains, %d pages, %s", name, len(picked), len(rows), statuses)
    return summary
