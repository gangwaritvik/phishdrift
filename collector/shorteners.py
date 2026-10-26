"""Learn link shorteners from the feeds: hosts whose short URLs only forward the visitor.

Candidates are registrable domains with many one-segment, short-token URLs in the feeds (the
shape of a short link). Each candidate gets a few HEAD probes (redirects not followed, no body
read). A domain is a shortener when most answered probes redirect to another registrable domain.
The result is merged into the shortener list by ``python -m features lists shorteners``.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import pandas as pd

from phishdrift.config import load_config, resolve
from phishdrift.domains import registered_domain
from phishdrift.http import HttpClient

log = logging.getLogger(__name__)
REDIRECTS = {301, 302, 303, 307, 308}


def short_link_domains(urls, *, max_token_len: int, min_short_urls: int, skip=frozenset()) -> dict:
    """{registrable domain: its short-link URLs}, for domains with at least ``min_short_urls``."""
    found: dict[str, list[str]] = {}
    for url in urls:
        parts = urlsplit(url)
        token = parts.path.strip("/")
        if parts.scheme not in ("http", "https") or parts.query or not token or "/" in token:
            continue
        if len(token) > max_token_len:
            continue
        domain = registered_domain(url)
        if domain and domain not in skip and (parts.hostname or "") in (domain, f"www.{domain}"):
            found.setdefault(domain, []).append(url)
    return {d: u for d, u in found.items() if len(u) >= min_short_urls}


def redirects_elsewhere(url: str, status: int, location: str | None) -> bool:
    if status not in REDIRECTS or not location:
        return False
    target = registered_domain(urljoin(url, location))
    return bool(target) and target != registered_domain(url)


def is_shortener(answers: list[bool | None], *, min_answered: int, min_share: float) -> bool:
    """``answers``: True = redirected elsewhere, False = did not, None = no answer."""
    answered = [a for a in answers if a is not None]
    return len(answered) >= min_answered and sum(answered) / len(answered) >= min_share


def probe(client: HttpClient, url: str, timeout_s: float) -> bool | None:
    try:
        status, location = client.head(url, timeout_s=timeout_s)
    except Exception:  # noqa: BLE001 - a dead or refusing host is "no answer"
        return None
    return redirects_elsewhere(url, status, location)


def learn(
    client: HttpClient, urls, cfg: dict, platforms=frozenset(), known=frozenset()
) -> pd.DataFrame:
    cands = short_link_domains(
        urls,
        max_token_len=cfg["max_token_len"],
        min_short_urls=cfg["min_short_urls"],
        skip=set(platforms) | set(known),
    )
    ranked = sorted(cands, key=lambda d: -len(cands[d]))[: cfg["max_candidates"]]
    log.info("%d candidate domains, probing %d", len(cands), len(ranked))

    def check(domain: str) -> dict:
        sample = sorted(set(cands[domain]))[: cfg["probe_urls"]]
        answers = [probe(client, u, cfg["probe_timeout_s"]) for u in sample]
        return {
            "domain": domain,
            "short_urls": len(cands[domain]),
            "probed": len(sample),
            "answered": sum(a is not None for a in answers),
            "redirected": sum(bool(a) for a in answers),
            "shortener": is_shortener(
                answers, min_answered=cfg["min_answered"], min_share=cfg["min_redirect_share"]
            ),
        }

    with ThreadPoolExecutor(cfg["workers"]) as pool:
        rows = list(pool.map(check, ranked))
    return pd.DataFrame(
        rows, columns=["domain", "short_urls", "probed", "answered", "redirected", "shortener"]
    )


def feed_urls(index_path: Path, extra_files: list[str]) -> list[str]:
    urls: list[str] = []
    if index_path.exists():
        urls += pd.read_parquet(index_path, columns=["url"])["url"].astype(str).tolist()
    for f in extra_files:
        urls += [ln.strip() for ln in resolve(f).read_text(encoding="utf-8").splitlines()]
    return [u for u in urls if u.lower().startswith("http")]


def run() -> int:
    from features.lists import load_lists

    ccfg = load_config("collector")
    cfg = ccfg["shorteners"]
    client = HttpClient.from_config(ccfg["http"], resolve(ccfg["paths"]["http_cache_dir"]))
    lists = load_lists()
    urls = feed_urls(resolve(ccfg["paths"]["index_path"]), cfg["extra_url_files"])
    table = learn(client, urls, cfg, platforms=lists.platforms, known=lists.shorteners)
    out_table, out_list = resolve(cfg["out_table"]), resolve(cfg["out_list"])
    for path in (out_table, out_list):
        path.parent.mkdir(parents=True, exist_ok=True)
    table.sort_values("short_urls", ascending=False).to_csv(out_table, index=False)
    found = sorted(table.loc[table["shortener"], "domain"]) if len(table) else []
    out_list.write_text(
        "# Learned by `python -m collector learn-shorteners` (HEAD, redirects not followed)\n"
        + "".join(f"{d}\n" for d in found),
        encoding="utf-8",
    )
    log.info("%d of %d probed domains are shorteners -> %s", len(found), len(table), out_list)
    return 0
