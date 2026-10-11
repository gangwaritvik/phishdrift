"""Split a URL into the parts the tier A features use.

Plain string operations only (no urllib), so the JavaScript port can do the same steps. The
URL is canonicalised first so formatting cannot reveal the source: the scheme is dropped, the
host is lowercased, a leading ``www.`` and the trailing ``/`` are dropped, the fragment is
dropped. A hosting-platform domain is replaced by ``PLATFORM_TOKEN`` (platform-identity masking).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from features.lists import PLATFORM_TOKEN
from phishdrift.domains import split_host

_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
_WORD = re.compile(r"[^a-z0-9]+")


@dataclass(frozen=True)
class Parts:
    canon: str
    host: str
    port: str
    userinfo: str
    path: str
    query: str
    subdomain: str
    label: str  # registrable domain label, e.g. "paypal" in paypal.co.uk
    suffix: str  # public suffix, e.g. "co.uk"
    is_ip: bool
    is_platform: bool

    @property
    def domain(self) -> str:
        return f"{self.label}.{self.suffix}" if self.suffix else self.label


def words(text: str) -> list[str]:
    return [w for w in _WORD.split(text.lower()) if w]


def is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def parse(url: str, platforms: frozenset[str]) -> Parts | None:
    """Canonical parts of ``url``; None when there is no host."""
    s = url.strip().split("#", 1)[0]
    s = s[_SCHEME.match(s).end() :] if _SCHEME.match(s) else s
    cut = min((i for i in (s.find("/"), s.find("?")) if i >= 0), default=len(s))
    authority, rest = s[:cut], s[cut:]
    userinfo = ""
    if "@" in authority:
        userinfo, authority = authority.rsplit("@", 1)
    port = ""
    if authority.startswith("["):
        end = authority.find("]")
        host = authority[: end + 1] if end >= 0 else authority
        tail = authority[end + 1 :] if end >= 0 else ""
        port = tail[1:] if tail.startswith(":") and tail[1:].isdigit() else ""
    elif ":" in authority and authority.rsplit(":", 1)[1].isdigit():
        host, port = authority.rsplit(":", 1)
    else:
        host = authority
    host = host.lower().rstrip(".")
    if not any(ch.isalnum() for ch in host):
        return None
    if host.startswith("www."):
        host = host[4:]
    if rest.startswith("?"):
        path, query = "", rest[1:]
    else:
        path, _, query = rest.partition("?")
    path = path.rstrip("/")

    is_ip = is_ip_host(host)
    subdomain, label, suffix = ("", host, "") if is_ip else split_host(host)
    is_platform = False
    if not is_ip and suffix and f"{label}.{suffix}" in platforms:
        is_platform = True
        host = f"{subdomain}.{PLATFORM_TOKEN}" if subdomain else PLATFORM_TOKEN
        subdomain, label, suffix = split_host(host)
    canon = (f"{userinfo}@" if userinfo else "") + host + (f":{port}" if port else "")
    canon += path + (f"?{query}" if query else "")
    return Parts(
        canon, host, port, userinfo, path, query, subdomain, label, suffix, is_ip, is_platform
    )
