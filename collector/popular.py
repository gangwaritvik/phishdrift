"""Seeds and workers for the "popular sites" legitimate-URL sources.

Why: the address model flagged real pages with long ids on popular sites
(``stitch.withgoogle.com``) because its benign training URLs are mostly bare homepages. Two seed
sets feed one source (``popular``, benign only) with deep URLs of popular sites:

  popular      the crawler (collector/benign.py): 3-5 inner pages per host from its sitemap, HTML
               kept
  commoncrawl  URLs the Common Crawl index already holds for the host (no page fetch, no HTML)

Both start from the same host list: Chrome's most visited origins (CrUX, monthly file of
``origin,rank`` in rank buckets). Rank only picks which hosts to visit and is never stored or used
as a feature (CLAUDE.md popularity ban). A host is left out when its registrable domain is
already in the corpus, the OOD evaluation set (natural pages stay evaluation-only), the feed index
or an earlier crawl, when it is a hosting platform itself or a shortener, or when phishing was
reported on that exact host. Hosting-platform *tenants* (``stitch.withgoogle.com``) are kept as
hosts, because each is its own site; the corpus still gives a registrable domain at most
``max_urls_per_domain`` URLs.
"""

from __future__ import annotations

import gzip
import json
import logging
import random
import re
from collections.abc import Iterable
from datetime import datetime
from urllib.parse import quote, urlsplit

import requests

from collector import benign, ood, store
from phishdrift.domains import registered_domain, url_depth
from phishdrift.http import HttpClient

log = logging.getLogger(__name__)

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


# --- the host list ---------------------------------------------------------------------


def parse_crux(text: str, skip_rank: int, max_rank: int) -> list[tuple[str, int]]:
    """``(host, rank)`` for CrUX origins with ``skip_rank < rank <= max_rank``, best rank per host.

    CrUX rows are ``origin,rank`` (``https://m.cricbuzz.com,1000``); ``rank`` is the bucket's upper
    bound (1000, 5000, 10000, ...). Plain ``http`` origins, ports, IP hosts and anything that is not
    a plain hostname are skipped."""
    best: dict[str, int] = {}
    for line in text.splitlines():
        origin, _, rank = line.strip().rpartition(",")
        if not rank.isdigit() or not origin.startswith("https://"):
            continue
        r = int(rank)
        if r <= skip_rank or r > max_rank:
            continue
        host = urlsplit(origin).netloc.lower()
        if ":" in host or _IPV4_RE.match(host) or not _HOST_RE.match(host) or "." not in host:
            continue
        if host not in best or r < best[host]:
            best[host] = r
    return sorted(best.items())


def fetch_crux(client: HttpClient, pcfg: dict, now: datetime) -> list[tuple[str, int]]:
    """The newest monthly CrUX file that downloads (cached on disk), parsed by ``parse_crux``."""
    year, month = now.year, now.month
    for _ in range(pcfg["months_back"]):
        year, month = (year, month - 1) if month > 1 else (year - 1, 12)
        url = pcfg["origins_url"].format(month=f"{year}{month:02d}")
        try:
            body = client.get(url, cache_ttl_s=pcfg["cache_ttl_s"], timeout_s=pcfg["timeout_s"])
        except Exception as exc:  # noqa: BLE001 - try the month before
            log.warning("popular hosts %s not fetched (%s: %s)", url, type(exc).__name__, exc)
            continue
        if body[:2] == b"\x1f\x8b":
            body = gzip.decompress(body)
        rows = parse_crux(
            body.decode("utf-8", errors="replace"), pcfg["skip_rank"], pcfg["max_rank"]
        )
        log.info("%d popular hosts from %s", len(rows), url)
        return rows
    raise RuntimeError("no CrUX origin list could be downloaded")


def select_hosts(
    rows: Iterable[tuple[str, int]],
    *,
    exclude_domains: set[str],
    exclude_hosts: set[str],
    platforms: frozenset[str] | set[str],
    shorteners: frozenset[str] | set[str],
    k: int,
    seed: int,
) -> list[str]:
    """Seeded sample of up to ``k`` hosts, one per registrable domain, except that each tenant
    of a hosting platform counts on its own. ``exclude_domains`` apply to ordinary hosts only
    (feed phishing on ``github.io`` must not hide every ``github.io`` tenant); tenants are
    excluded by exact host. The platform's own bare domain and shorteners are never chosen."""
    order = sorted(rows)
    random.Random(seed).shuffle(order)
    chosen: list[str] = []
    taken: set[str] = set()
    for host, _rank in order:
        if len(chosen) >= k:
            break
        domain = registered_domain(f"https://{host}/")
        if host in exclude_hosts or not domain or domain in shorteners:
            continue
        if domain in platforms:
            if host == domain:
                continue  # the platform itself says nothing about its tenants
            key = host
        elif domain in exclude_domains:
            continue
        else:
            key = domain
        if key in taken:
            continue
        taken.add(key)
        chosen.append(host)
    return chosen


def build_exclusions(cfg: dict, now: datetime) -> tuple[set[str], set[str]]:
    """``(domains, hosts)`` the popular seed sets must not visit: the corpus files, the training
    crawl attempts and the feed index (as in ``ood.excluded_domains``), the OOD evaluation samples,
    and every host the feed index lists as phishing."""
    paths = cfg["paths"]
    from phishdrift.config import load_config, resolve

    processed_dir = resolve(load_config("datasets")["paths"]["processed_dir"])
    domains, found = ood.excluded_domains(
        cfg["ood"], processed_dir, resolve(paths["crawl_dir"]), resolve(paths["index_path"])
    )
    hosts: set[str] = set()
    ood_dir = resolve(paths["ood_dir"])
    for sample in (ood_dir / ood.SAMPLE_NAME, ood_dir.parent / "ood_html" / ood.SAMPLE_NAME):
        if sample.exists():
            for d in benign.read_seed_file(sample):
                domains.add(d)
    index_path = resolve(paths["index_path"])
    if index_path.exists():
        urls = store.load_index(index_path)["url"]
        hosts |= {urlsplit(u).hostname or "" for u in urls}
        hosts.discard("")
    attempts = store.load_attempts(resolve(paths["crawl_dir"]))
    hosts |= {str(h).lower() for h in attempts["seed_domain"]}
    log.info(
        "popular: %d domains and %d hosts excluded (%s)",
        len(domains),
        len(hosts),
        found or "no corpus files",
    )
    return domains, hosts


# --- Common Crawl ----------------------------------------------------------------------

_SKIP_EXT = re.compile(
    r"\.(?:jpe?g|png|gif|svg|webp|ico|bmp|pdf|zip|gz|tgz|rar|7z|exe|apk|dmg|mp[34]|avi|mov|css|js|json|xml|txt|woff2?|ttf)$",
    re.I,
)


def parse_cdx(text: str) -> list[str]:
    """URLs of the 200 ``text/html`` captures in a CDX answer (one JSON object per line)."""
    out: list[str] = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        url = row.get("url") if isinstance(row, dict) else None
        if not url or str(row.get("status", "200")) != "200":
            continue
        if "html" not in str(row.get("mime", "text/html")):
            continue
        out.append(url)
    return out


def pick_urls(urls: Iterable[str], host: str, per_host: int, seed: int) -> list[str]:
    """Up to ``per_host`` deep (depth >= 1) page URLs of exactly ``host``: ``https`` only, no
    credentials, ports or file downloads, one per canonical URL, seeded sample."""
    seen: set[str] = set()
    cands: list[str] = []
    for url in urls:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or (parts.hostname or "") != host:
            continue
        if parts.port or parts.username or _SKIP_EXT.search(parts.path):
            continue
        if url_depth(url) < 1:
            continue
        key = benign.normalize_url(url)
        if key in seen:
            continue
        seen.add(key)
        cands.append(f"https://{host}{parts.path}" + (f"?{parts.query}" if parts.query else ""))
    cands.sort()
    random.Random(seed).shuffle(cands)
    return cands[:per_host]


def latest_collection(client: HttpClient, pcfg: dict) -> str:
    """CDX endpoint of the newest Common Crawl collection (``collinfo.json``, cached a day)."""
    body = client.get(
        pcfg["commoncrawl"]["collections_url"],
        cache_ttl_s=86400,
        timeout_s=pcfg["commoncrawl"]["timeout_s"],
    )
    info = json.loads(body)
    if not info or "cdx-api" not in info[0]:
        raise RuntimeError("unexpected collinfo.json")
    return info[0]["cdx-api"]


def commoncrawl_pages(
    client: HttpClient, endpoint: str, host: str, pcfg: dict, seed: int
) -> benign.DomainResult:
    """URLs the Common Crawl index holds for ``host``. A site with several index pages is read at
    one seeded random page (the index is in URL order, so its first page is alphabetical).
    No page is fetched, so ``html`` is None."""
    ccfg = pcfg["commoncrawl"]
    base = f"{endpoint}?url={quote(host)}/*&output=json&fl=url,status,mime"
    flt = "&filter==status:200&filter==mime:text/html"
    try:
        page = 0
        try:
            info = json.loads(
                client.get(
                    base + "&showNumPages=true",
                    timeout_s=ccfg["timeout_s"],
                    min_interval_s=ccfg["min_interval_s"],
                )
            )
            pages = int(info.get("pages", 1)) if isinstance(info, dict) else 1
            page = random.Random(seed).randrange(max(1, pages))
        except (ValueError, TypeError):
            page = 0
        body = client.get(
            f"{base}{flt}&page={page}&limit={ccfg['fetch_limit']}",
            timeout_s=ccfg["timeout_s"],
            min_interval_s=ccfg["min_interval_s"],
        )
    except requests.HTTPError as exc:
        status = (
            benign.NO_PAGES
            if exc.response is not None and exc.response.status_code == 404
            else benign.ERROR
        )
        return benign.DomainResult(host, status, [])
    except requests.RequestException:
        return benign.DomainResult(host, benign.ERROR, [])
    urls = pick_urls(
        parse_cdx(body.decode("utf-8", errors="replace")), host, ccfg["per_host"], seed
    )
    n = len(urls)
    status = benign.NO_PAGES if n == 0 else benign.FEW_PAGES if n < ccfg["min_pages"] else benign.OK
    return benign.DomainResult(host, status, [{"url": u, "html": None} for u in urls])
