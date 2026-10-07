"""Benign URL sampler: Tranco top domains plus their inner pages, and free-hosted seeds.

Only well-known benign sites are fetched here (robots.txt, sitemaps, homepages). The
Tranco rank is kept in raw collector output for the extension's allowlist work but is
never part of the processed dataset, so it cannot leak into model features.
"""

from __future__ import annotations

import csv
import gzip
import io
import logging
import random
import re
import zipfile
from datetime import date
from urllib.parse import urljoin

import pandas as pd

from collector.feeds import FEED_COLUMNS
from phishdrift.domains import normalize_url, registered_domain
from phishdrift.http import HttpClient

log = logging.getLogger(__name__)

_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.IGNORECASE)
_HREF_RE = re.compile(r"""<a\s[^>]*?href\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)
_SKIP_EXT = re.compile(r"\.(?:jpe?g|png|gif|svg|webp|ico|pdf|zip|gz|mp4|mp3|css|js|xml)$", re.I)


def parse_tranco_zip(zip_bytes: bytes) -> list[str]:
    """Domains in rank order from the Tranco ``top-1m.csv.zip`` (rows: rank,domain)."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".csv"))
        text = zf.read(name).decode("utf-8")
    return [row[1].strip() for row in csv.reader(text.splitlines()) if len(row) >= 2]


def sample_domains(ranked: list[str], top_n: int, k: int, day: date) -> list[tuple[int, str]]:
    """Seeded (by day) sample of ``k`` (rank, domain) pairs from the top ``top_n``."""
    pool = list(enumerate(ranked[:top_n], start=1))
    rng = random.Random(day.toordinal())
    return sorted(rng.sample(pool, min(k, len(pool))))


def _decode(body: bytes) -> str:
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)
    return body.decode("utf-8", errors="replace")


def parse_sitemap_locs(xml_text: str) -> tuple[list[str], bool]:
    """Return (<loc> URLs, is_sitemap_index)."""
    return _LOC_RE.findall(xml_text), "<sitemapindex" in xml_text[:2000].lower()


def parse_robots_sitemaps(robots_text: str) -> list[str]:
    return [
        ln.split(":", 1)[1].strip()
        for ln in robots_text.splitlines()
        if ln.lower().startswith("sitemap:")
    ]


def extract_same_site_links(html: str, base_url: str) -> list[str]:
    """Absolute http(s) links on ``html`` whose registered domain matches ``base_url``'s."""
    site = registered_domain(base_url)
    out = []
    for href in _HREF_RE.findall(html):
        url = urljoin(base_url, href.strip())
        if url.startswith(("http://", "https://")) and registered_domain(url) == site:
            out.append(url)
    return out


def select_inner_pages(candidates: list[str], homepage: str, k: int, seed: int) -> list[str]:
    """Pick up to ``k`` distinct same-site inner pages (not the homepage, not static files)."""
    home = normalize_url(homepage)
    site = registered_domain(homepage)
    seen, pages = set(), []
    for url in candidates:
        url = url.strip()
        if registered_domain(url) != site:
            continue
        norm = normalize_url(url)
        path = norm.split("://", 1)[-1].partition("/")[2]
        if norm == home or not path or _SKIP_EXT.search(path.split("?")[0]) or norm in seen:
            continue
        seen.add(norm)
        pages.append(url)
    rng = random.Random(seed)
    return sorted(rng.sample(pages, min(k, len(pages))))


def discover_inner_pages(client: HttpClient, domain: str, cfg: dict, seed: int) -> list[str]:
    """Inner pages of ``domain`` from its sitemaps, falling back to homepage links."""
    homepage = f"https://{domain}/"
    get = lambda u: _decode(client.get(u, max_bytes=cfg["max_page_bytes"]))  # noqa: E731
    candidates: list[str] = []
    try:
        sitemaps = parse_robots_sitemaps(get(urljoin(homepage, "/robots.txt")))
    except Exception as exc:  # noqa: BLE001 - any network/HTTP error just means "no robots"
        log.debug("%s robots.txt: %s", domain, exc)
        sitemaps = []
    sitemaps = sitemaps or [urljoin(homepage, "/sitemap.xml")]
    for sm in sitemaps[: cfg["max_sitemaps_per_domain"]]:
        try:
            locs, is_index = parse_sitemap_locs(get(sm))
            if is_index and locs:
                locs, _ = parse_sitemap_locs(get(locs[0]))
            candidates.extend(locs)
        except Exception as exc:  # noqa: BLE001
            log.debug("%s sitemap %s: %s", domain, sm, exc)
    if not candidates:
        try:
            candidates = extract_same_site_links(get(homepage), homepage)
        except Exception as exc:  # noqa: BLE001
            log.debug("%s homepage: %s", domain, exc)
    return select_inner_pages(candidates, homepage, cfg["inner_pages_per_domain"], seed)


def collect_benign(client: HttpClient, cfg: dict, day: date) -> pd.DataFrame:
    """One day's benign sample. Extra column ``tranco_rank`` (raw output only)."""
    body = client.get(cfg["tranco_url"], cache_ttl_s=cfg["tranco_cache_ttl_s"])
    ranked = parse_tranco_zip(body)
    rows: list[dict] = []
    for rank, domain in sample_domains(ranked, cfg["top_n"], cfg["domains_per_day"], day):
        if cfg["include_homepage"]:
            rows.append({"url": f"https://{domain}/", "source": "tranco", "tranco_rank": rank})
        for url in discover_inner_pages(client, domain, cfg, seed=day.toordinal() + rank):
            rows.append({"url": url, "source": "tranco", "tranco_rank": rank})
    for url in cfg.get("free_hosted_seeds") or []:
        rows.append({"url": url, "source": "free_hosted", "tranco_rank": None})
    df = pd.DataFrame(rows, columns=["url", "source", "tranco_rank"])
    df["threat"] = "benign"
    df["label"] = pd.Series([0] * len(df), dtype="int8")
    df["feed_time"] = pd.Series(pd.NaT, index=df.index, dtype="datetime64[ns, UTC]")
    df["target"] = None
    return df[[*FEED_COLUMNS, "tranco_rank"]]
