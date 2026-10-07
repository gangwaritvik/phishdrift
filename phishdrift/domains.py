"""URL canonicalization, registrable-domain extraction and URL depth.

Uses tldextract's bundled Public Suffix List snapshot, so results are reproducible and
need no network.

Two registrable-domain definitions (prior report §9):
- U1, the default everywhere: public-suffix-only (ICANN suffixes). ``a.web.app`` and
  ``b.web.app`` both map to ``web.app``, so a hosting platform is one group.
- U2, optional: PSL private suffixes honoured, so ``a.web.app`` and ``b.web.app`` differ.
  Used only for sensitivity checks.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit

import tldextract

_EXTRACT_U1 = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=False
)
_EXTRACT_U2 = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True
)
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _ensure_scheme(url: str) -> str:
    url = url.strip()
    if "://" not in url.split("?", 1)[0]:
        url = "http://" + url
    return url


def _netloc(host: str, parts) -> str:
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
    if port is not None and port != _DEFAULT_PORTS.get(parts.scheme.lower()):
        netloc += f":{port}"
    return netloc


def normalize_url(url: str) -> str:
    """Canonical form that keeps the scheme (used for the collector's first-seen index).

    Lowercases scheme and host, drops default ports, fragments and a bare trailing ``/``,
    adds ``http://`` when the scheme is missing. Path and query case are kept.
    """
    parts = urlsplit(_ensure_scheme(url))
    host = (parts.hostname or "").rstrip(".")
    path = parts.path if parts.path not in ("", "/") else ""
    return urlunsplit((parts.scheme.lower(), _netloc(host, parts), path, parts.query, ""))


def url_key(url: str) -> str:
    """Cross-source dedup key: like ``normalize_url`` but without the scheme and a leading
    ``www.``, because sources record those inconsistently (PhishStorm often has no scheme,
    PhiUSIIL legit always has ``https://www.``)."""
    parts = urlsplit(_ensure_scheme(url))
    host = (parts.hostname or "").rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    path = parts.path.rstrip("/")
    key = _netloc(host, parts) + path
    return f"{key}?{parts.query}" if parts.query else key


def hostname(url: str) -> str:
    """Lowercased host without port or trailing dot ('' when unparsable)."""
    try:
        return (urlsplit(_ensure_scheme(url)).hostname or "").rstrip(".")
    except ValueError:
        return ""


def url_depth(url: str) -> int:
    """Number of non-empty ``/``-separated path segments; query and fragment excluded
    (same definition as the prior report §13.7)."""
    try:
        path = urlsplit(_ensure_scheme(url)).path
    except ValueError:
        return 0
    return sum(1 for seg in path.split("/") if seg)


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _registrable(url: str, extractor: tldextract.TLDExtract) -> str:
    host = hostname(url)
    if not host:
        return ""
    if _is_ip(host):
        return host.strip("[]")
    ext = extractor(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host


@lru_cache(maxsize=500_000)
def registered_domain(url: str) -> str:
    """U1 registrable domain (public-suffix-only), e.g.
    ``https://login.secure.paypal.co.uk/x`` -> ``paypal.co.uk``,
    ``https://a.web.app`` -> ``web.app``.

    IP hosts return the IP. Hosts with no known public suffix (``localhost``) return the
    host. Returns '' if the URL has no host.
    """
    return _registrable(url, _EXTRACT_U1)


@lru_cache(maxsize=500_000)
def registered_domain_private(url: str) -> str:
    """U2 registrable domain (PSL private suffixes honoured):
    ``https://a.web.app`` -> ``a.web.app``."""
    return _registrable(url, _EXTRACT_U2)


def normalize_to_registrable(url: str) -> str:
    """Representation check (report R4): ``https://www.<registrable domain>``."""
    return f"https://www.{registered_domain(url)}"
