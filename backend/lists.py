"""Hashed blocklist and allowlist builder, plus the key functions the extension mirrors.

The extension downloads short hash prefixes, never plain domains or URLs. ``list_url_key`` and
``list_domain_key`` are written as small pure functions over plain string operations so that
the JavaScript port can reproduce them exactly (``tests/fixtures/list_key_parity.json`` is
checked by both sides). Only the public-suffix lookup uses a library here (tldextract's
bundled ICANN list, the same one the feature engine and the JS port already mirror).

Blocklist: phishing URLs from the training feeds plus the blocklist-only feeds. A URL on a
shared-hosting platform (``configs/platforms.yaml``), in an open-hosting zone (below) or on an
allowlist candidate is listed by its full-URL hash, because blocking ``github.io`` would block
every site there and blocking ``github.com`` for one bad download would block the site; any
other URL is listed by its registrable domain hash. Allowlist: Tranco top N (rank only cuts the
list, it is never a feature) minus platforms, whole-domain open-hosting zones and blocklisted
domains. The extension lets an exact full-URL hit override the allowlist.

Open hosting (learned from the phishing URLs, not hand-written): a phishing host below an
allowlist candidate (``x.swedencentral.cloudapp.azure.com`` under ``azure.com``,
``drive.google.com`` under ``google.com``) shows that someone other than the owner can publish
there. The *zone* is the child of the registrable domain that contains the host
(``cloudapp.azure.com``, ``drive.google.com``). When phishing appears under many different
children, each with few URLs (one tenant per subdomain, as on ``weebly.com``), the whole
registrable domain is the zone. A URL inside a zone is treated like a platform URL: the
allowlist does not apply and the blocklist lists it by full URL, so a tenant's phishing page
neither passes as the trusted brand nor blocks the brand's own pages (``www.google.com`` stays
allowlisted). The zones are listed in plain text in the allowlist document (``open_hosting``);
they are public hosting names, not user data. Besides the feeds, a long phishing history
(``lists.open_hosting.evidence_urls``) feeds the learner, because the corpus drops domains
shared by several phishing sources and the live feeds cover only days.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import string
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq

from phishdrift.domains import split_host

log = logging.getLogger(__name__)

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_STRIP = " \t\n\r\f\v"
_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
_IPV4_RE = re.compile(rf"^{_OCTET}(?:\.{_OCTET}){{3}}$")


def _split(url: str) -> tuple[str, str, str]:
    """``(host, port_suffix, rest)`` of ``url`` after the shared normalisation steps.

    1. strip surrounding whitespace (only space, tab, newline, carriage return, form feed and
    vertical tab); 2. drop the fragment (from the first ``#``);
    3. drop the scheme (``^[a-zA-Z][a-zA-Z0-9+.\\-]*://``); 4. the authority runs up to the first
    ``/`` or ``?`` (``rest`` is everything from there on); 5. drop userinfo (everything up to
    the last ``@`` in the authority); 6. lowercase ASCII letters of the authority only (other
    characters are untouched so Python and JavaScript agree); 7. split host and port suffix:
    a host starting with ``[`` ends at the first ``]``, any other host ends at the first ``:``;
    the port suffix (``:8080``) keeps its colon; 8. strip trailing dots from the host, then one
    leading ``www.``.
    """
    s = url.strip(_STRIP)
    s = s.split("#", 1)[0]
    s = _SCHEME_RE.sub("", s, count=1)
    cut = len(s)
    for ch in ("/", "?"):
        i = s.find(ch)
        if i != -1:
            cut = min(cut, i)
    authority, rest = s[:cut], s[cut:]
    authority = authority[authority.rfind("@") + 1 :].translate(_LOWER)
    if authority.startswith("["):
        end = authority.find("]")
        host, port = (authority, "") if end == -1 else (authority[: end + 1], authority[end + 1 :])
    else:
        colon = authority.find(":")
        host, port = (authority, "") if colon == -1 else (authority[:colon], authority[colon:])
    host = host.rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return host, port, rest


def list_url_key(url: str) -> str:
    """Full-URL list key: ``host[:port]`` + path + query, nothing else.

    Steps are those of ``_split``; then the path (the part of ``rest`` before the first ``?``)
    loses its trailing ``/`` characters and the query is kept verbatim. Scheme, userinfo,
    fragment, host case, trailing dots on the host and one leading ``www.`` never affect the key.
    ``https://User@WWW.Example.com:8443/a/b/?q=1#top`` -> ``example.com:8443/a/b?q=1``.
    """
    host, port, rest = _split(url)
    path, sep, query = rest.partition("?")
    return host + port + path.rstrip("/") + sep + query


def list_domain_key(url: str) -> str:
    """Registrable-domain list key (public-suffix-only, ICANN suffixes, lowercase).

    The host is normalised as in ``_split`` (no userinfo, port, trailing dots or leading
    ``www.``). An IPv4 literal (four dotted decimal octets, no leading zeros) is returned as is;
    a bracketed IPv6 literal is returned without brackets. Otherwise the result is
    ``<domain label>.<public suffix>``, or the host itself when it has no known public suffix
    or is itself a public suffix.
    """
    host, _, _ = _split(url)
    if _IPV4_RE.match(host):
        return host
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    _, label, suffix = split_host(host)
    return f"{label}.{suffix}" if label and suffix else host


def list_hash(key: str, prefix_bytes: int) -> str:
    """Hex of the first ``prefix_bytes`` bytes of sha256(key as UTF-8)."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[: 2 * prefix_bytes]


# --- inputs -----------------------------------------------------------------------------


def _read_urls(path: Path, phishing_only: bool) -> list[str]:
    names = set(pq.read_schema(path).names)
    cols = [c for c in ("url", "label", "threat") if c in names]
    if "url" not in cols:
        return []
    df = pd.read_parquet(path, columns=cols)
    if phishing_only:
        mask = pd.Series(False, index=df.index)
        if "label" in df:
            mask |= df["label"] == 1
        if "threat" in df:
            mask |= df["threat"] == "phishing"
        df = df[mask]
    return [u for u in df["url"].dropna().astype(str) if u.strip()]


def parse_url_lines(text: str) -> list[str]:
    """One URL per line; blank lines and ``#`` comments skipped (Phishing.Database lists)."""
    return [s for s in (ln.strip() for ln in text.splitlines()) if s and not s.startswith("#")]


def read_phishing_file(path: Path) -> list[str]:
    """Phishing URLs from a parquet or CSV file with a ``url`` column (and ``label``/``threat``
    when present, keeping label 1 or phishing rows only), or a ``.txt`` file of one URL per line."""
    path = Path(path)
    if path.suffix == ".parquet":
        return _read_urls(path, phishing_only=True)
    if path.suffix == ".txt":
        return parse_url_lines(path.read_text(encoding="utf-8", errors="replace"))
    df = pd.read_csv(path)
    if "label" in df:
        df = df[df["label"] == 1]
    return [u for u in df["url"].dropna().astype(str) if u.strip()]


def collect_blocklist_urls(raw_dir: Path, blocklist_dir: Path) -> list[str]:
    """Distinct phishing URLs: training feeds (label 1 or phishing) + every blocklist feed."""
    urls: set[str] = set()
    for path in sorted(Path(raw_dir).glob("*/*.parquet")):
        urls.update(_read_urls(path, phishing_only=True))
    for path in sorted(Path(blocklist_dir).glob("*/*.parquet")):
        urls.update(_read_urls(path, phishing_only=False))
    return sorted(urls)


def read_tranco_file(path: Path, top_n: int) -> list[str]:
    """First ``top_n`` entries of a Tranco file: ``domain`` or ``rank,domain`` per line."""
    out: list[str] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line.split(",")[-1].strip())
        if len(out) >= top_n:
            break
    return out


def tranco_from_package(cache_dir: Path, top_n: int) -> list[str]:
    from tranco import Tranco  # the package downloads the list on first use

    Path(cache_dir).mkdir(parents=True, exist_ok=True)
    return Tranco(cache_dir=str(cache_dir)).list().top(top_n)


# --- build ------------------------------------------------------------------------------


def url_host(url: str) -> str:
    """Host of ``url`` as the list keys see it (``_split``: lowercase, no port, one ``www.``
    dropped)."""
    return _split(url)[0]


def in_zone(host: str, zones: set[str] | frozenset[str]) -> bool:
    """True when ``host`` is a zone or lies below one (plain suffix match on labels)."""
    if host in zones:
        return True
    i = host.find(".")
    while i != -1:
        if host[i + 1 :] in zones:
            return True
        i = host.find(".", i + 1)
    return False


def open_hosting_zones(
    phishing_urls: Iterable[str],
    candidates: set[str],
    min_tenant_children: int,
    min_children_per_url: float,
) -> set[str]:
    """Zones (see the module docstring) learned from phishing hosts below candidate domains."""
    children: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for url in phishing_urls:
        domain = list_domain_key(url)
        if domain not in candidates:
            continue
        host = url_host(url)
        if host == domain or not host.endswith("." + domain):
            continue
        child = host[: -len(domain) - 1].rsplit(".", 1)[-1]
        children[domain][child] += 1
    zones: set[str] = set()
    for domain, counts in children.items():
        n_urls = sum(counts.values())
        if len(counts) >= min_tenant_children and len(counts) / n_urls >= min_children_per_url:
            zones.add(domain)
        else:
            zones.update(f"{child}.{domain}" for child in counts)
    return zones


def build_lists(
    blocklist_urls: Iterable[str],
    allow_candidates: Iterable[str],
    platforms: frozenset[str],
    prefix_bytes: int,
    built_at: datetime | None = None,
    extra_phishing_urls: Iterable[str] = (),
    min_tenant_children: int = 3,
    min_children_per_url: float = 0.5,
) -> dict[str, dict]:
    """Return ``{"manifest", "blocklist", "allowlist"}`` documents (all sorted, deterministic
    except ``built_at``). ``extra_phishing_urls`` (for example the corpus's phishing URLs) only
    help find open-hosting domains; they are not blocklisted."""
    blocklist_urls = list(blocklist_urls)
    cand_domains = {d for d in map(list_domain_key, allow_candidates) if d}
    zones = open_hosting_zones(
        [*blocklist_urls, *extra_phishing_urls],
        cand_domains - platforms,
        min_tenant_children,
        min_children_per_url,
    )
    block_domains: set[str] = set()
    block_urls: set[str] = set()
    plain_block_domains: set[str] = set()
    for url in blocklist_urls:
        domain = list_domain_key(url)
        if not domain:
            continue
        # platforms, open-hosting zones and allowlist candidates are listed by full URL: blocking
        # the domain would block every tenant (github.io) or the big site itself (github.com
        # serving one bad download); any other domain is listed by its registrable domain
        if domain in platforms or domain in cand_domains or in_zone(url_host(url), zones):
            block_urls.add(list_hash(list_url_key(url), prefix_bytes))
        else:
            plain_block_domains.add(domain)
            block_domains.add(list_hash(domain, prefix_bytes))
    allow: set[str] = set()
    for domain in cand_domains:
        if domain not in platforms and domain not in zones and domain not in plain_block_domains:
            allow.add(list_hash(domain, prefix_bytes))
    doms, urls, allowed = sorted(block_domains), sorted(block_urls), sorted(allow)
    opened = sorted(zones)
    digest = hashlib.sha256(
        json.dumps([prefix_bytes, doms, urls, allowed, opened], separators=(",", ":")).encode()
    ).hexdigest()
    version = digest[:12]
    built = (built_at or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds")
    return {
        "manifest": {
            "version": version,
            "built_at": built,
            "prefix_bytes": prefix_bytes,
            "counts": {
                "blocklist_domains": len(doms),
                "blocklist_urls": len(urls),
                "allowlist_domains": len(allowed),
                "open_hosting_domains": len(opened),
            },
        },
        "blocklist": {
            "version": version,
            "prefix_bytes": prefix_bytes,
            "domains": doms,
            "urls": urls,
        },
        "allowlist": {
            "version": version,
            "prefix_bytes": prefix_bytes,
            "domains": allowed,
            "open_hosting": opened,
        },
    }


def write_lists(docs: dict[str, dict], out_dir: Path) -> dict[str, Path]:
    """Write ``manifest.json``, ``blocklist.json`` and ``allowlist.json`` atomically (the
    manifest last, so a reader that sees a new manifest finds the matching lists)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}
    for name in ("blocklist", "allowlist", "manifest"):
        path = out_dir / f"{name}.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(docs[name], separators=(",", ":")), encoding="utf-8")
        os.replace(tmp, path)
        paths[name] = path
    return paths
