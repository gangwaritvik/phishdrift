"""URL normalization and registered-domain (eTLD+1) extraction.

Uses tldextract's bundled Public Suffix List snapshot, so results are reproducible and
need no network. Private suffixes (github.io, blogspot.com, ...) are honoured: each site
on a free host is its own registered domain, so ``a.github.io`` and ``b.github.io`` can
land in different splits but two pages of ``a.github.io`` never can.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit

import tldextract

_EXTRACT = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _ensure_scheme(url: str) -> str:
    url = url.strip()
    if "://" not in url.split("?", 1)[0]:
        url = "http://" + url
    return url


def normalize_url(url: str) -> str:
    """Canonical form used for exact dedup.

    Lowercases scheme and host, drops default ports, fragments and a bare trailing ``/``,
    adds ``http://`` when the scheme is missing. Path and query case are kept, since
    they are significant on most servers.
    """
    parts = urlsplit(_ensure_scheme(url))
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").rstrip(".")
    netloc = f"[{host}]" if ":" in host else host
    if parts.username or parts.password:
        userinfo = parts.username or ""
        if parts.password:
            userinfo += ":" + parts.password
        netloc = f"{userinfo}@{netloc}"
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is not None and port != _DEFAULT_PORTS.get(scheme):
        netloc += f":{port}"
    path = parts.path if parts.path not in ("", "/") else ""
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def hostname(url: str) -> str:
    """Lowercased host without port or trailing dot ('' when unparsable)."""
    try:
        return (urlsplit(_ensure_scheme(url)).hostname or "").rstrip(".")
    except ValueError:
        return ""


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


@lru_cache(maxsize=500_000)
def registered_domain(url: str) -> str:
    """eTLD+1 of a URL, e.g. ``https://login.secure.paypal.co.uk/x`` -> ``paypal.co.uk``.

    IP hosts return the IP itself. Hosts with no known public suffix (``localhost``,
    internal names) return the host. Returns '' if the URL has no host.
    """
    host = hostname(url)
    if not host:
        return ""
    if _is_ip(host):
        return host.strip("[]")
    ext = _EXTRACT(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host
