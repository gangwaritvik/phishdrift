"""Hashed blocklist and allowlist builder, plus the key functions the extension mirrors.

The extension downloads short hash prefixes, never plain domains or URLs. ``list_url_key`` and
``list_domain_key`` are written as small pure functions over plain string operations so that
the JavaScript port can reproduce them exactly (``tests/fixtures/list_key_parity.json`` is
checked by both sides). Only the public-suffix lookup uses a library here (tldextract's
bundled ICANN list, the same one the feature engine and the JS port already mirror).

Blocklist: phishing URLs from the training feeds plus the blocklist-only feeds. A URL on a
shared-hosting platform (``configs/platforms.yaml``) is listed by its full-URL hash, because
blocking ``github.io`` would block every site there; any other URL is listed by its registrable
domain hash. Allowlist: Tranco top N (rank only cuts the list, it is never a feature) minus
platforms minus blocklisted domains.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import string
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


def build_lists(
    blocklist_urls: Iterable[str],
    allow_candidates: Iterable[str],
    platforms: frozenset[str],
    prefix_bytes: int,
    built_at: datetime | None = None,
) -> dict[str, dict]:
    """Return ``{"manifest", "blocklist", "allowlist"}`` documents (all sorted, deterministic
    except ``built_at``)."""
    block_domains: set[str] = set()
    block_urls: set[str] = set()
    plain_block_domains: set[str] = set()
    for url in blocklist_urls:
        domain = list_domain_key(url)
        if not domain:
            continue
        if domain in platforms:
            block_urls.add(list_hash(list_url_key(url), prefix_bytes))
        else:
            plain_block_domains.add(domain)
            block_domains.add(list_hash(domain, prefix_bytes))
    allow: set[str] = set()
    for cand in allow_candidates:
        domain = list_domain_key(cand)
        if domain and domain not in platforms and domain not in plain_block_domains:
            allow.add(list_hash(domain, prefix_bytes))
    doms, urls, allowed = sorted(block_domains), sorted(block_urls), sorted(allow)
    digest = hashlib.sha256(
        json.dumps([prefix_bytes, doms, urls, allowed], separators=(",", ":")).encode()
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
            },
        },
        "blocklist": {
            "version": version,
            "prefix_bytes": prefix_bytes,
            "domains": doms,
            "urls": urls,
        },
        "allowlist": {"version": version, "prefix_bytes": prefix_bytes, "domains": allowed},
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
