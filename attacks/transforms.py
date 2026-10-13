"""The six URL evasion families.

``homoglyph``     look-alike letters in the domain name (ASCII digits, or Unicode via punycode)
``subdomain``     login/brand-looking labels stacked in front of the real host
``brand``         a well-known brand name added to the path and query
``padding``       long random path segments, junk query parameters, percent-encoded letters
``shortener``     the URL replaced by a link on a public URL shortener
``tld``           another top-level domain, and a hyphenated domain label

All take the URL, a ``random.Random`` and the ``Lists`` (brands, shorteners) and return the
new URL or ``None``.
"""

from __future__ import annotations

import hashlib
import random
import string
from urllib.parse import quote, urlsplit

from features.lists import Lists
from phishdrift.domains import split_host

FAMILIES = ("homoglyph", "subdomain", "brand", "padding", "shortener", "tld")

ASCII_SWAPS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5"}
UNICODE_SWAPS = {
    "a": "а",  # Cyrillic a
    "e": "е",  # Cyrillic e
    "o": "о",  # Cyrillic o
    "p": "р",  # Cyrillic er
    "c": "с",  # Cyrillic es
    "i": "і",  # Cyrillic i
}
LURE_LABELS = ("secure", "login", "account", "verify", "update", "signin", "support", "service")
SWAP_TLDS = ("com", "net", "org", "info", "xyz", "top", "site", "online", "co", "app")
ALNUM = string.ascii_lowercase + string.digits


def _rng(url: str, family: str, seed: int) -> random.Random:
    digest = hashlib.sha256(f"{seed}|{family}|{url}".encode()).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _brands(lists: Lists) -> list[str]:
    return [b for b in lists.brands if 4 <= len(b) <= 14 and b.isalpha()]


def _build(scheme: str, host: str, port: int | None, path: str, query: str) -> str:
    netloc = host if port is None else f"{host}:{port}"
    return f"{scheme}://{netloc}{path}" + (f"?{query}" if query else "")


def _parts(url: str):
    s = urlsplit(url if "://" in url else f"http://{url}")
    host = (s.hostname or "").lower()
    if not host or s.scheme not in ("http", "https"):
        return None
    try:
        port = s.port
    except ValueError:
        port = None
    return s.scheme, host, port, s.path, s.query


def homoglyph(url: str, rng: random.Random, lists: Lists) -> str | None:
    p = _parts(url)
    if p is None:
        return None
    scheme, host, port, path, query = p
    sub, label, suffix = split_host(host)
    if not suffix or not label.isascii() or f"{label}.{suffix}" in lists.platforms:
        return None
    use_unicode = rng.random() < 0.5
    table = UNICODE_SWAPS if use_unicode else ASCII_SWAPS
    spots = [i for i, ch in enumerate(label) if ch in table]
    if not spots:
        return None
    chosen = rng.sample(spots, k=min(len(spots), rng.choice((1, 1, 2))))
    chars = list(label)
    for i in chosen:
        chars[i] = table[chars[i]]
    new_label = "".join(chars)
    try:
        enc = new_label.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    new_host = ".".join(x for x in (sub, enc, suffix) if x)
    return _build(scheme, new_host, port, path, query)


def subdomain(url: str, rng: random.Random, lists: Lists) -> str | None:
    p = _parts(url)
    brands = _brands(lists)
    if p is None or not brands:
        return None
    scheme, host, port, path, query = p
    lure = rng.sample(LURE_LABELS, k=rng.choice((1, 2)))
    brand = rng.choice(brands)
    stuffed = [*lure, brand, rng.choice(("com", "net", "org"))]
    return _build(scheme, ".".join([*stuffed, host]), port, path, query)


def brand(url: str, rng: random.Random, lists: Lists) -> str | None:
    p = _parts(url)
    brands = _brands(lists)
    if p is None or not brands:
        return None
    scheme, host, port, path, query = p
    name = rng.choice(brands)
    word = rng.choice(("signin", "login", "verify", "account", "secure"))
    new_path = f"/{name}/{word}" + (path if path != "/" else "")
    new_query = (query + "&" if query else "") + f"brand={name}"
    return _build(scheme, host, port, new_path, new_query)


def padding(url: str, rng: random.Random, lists: Lists) -> str | None:
    p = _parts(url)
    if p is None:
        return None
    scheme, host, port, path, query = p
    segments = ["".join(rng.choices(ALNUM, k=rng.randint(8, 24))) for _ in range(rng.randint(3, 6))]
    base = path.rstrip("/")
    encoded = "".join(f"%{ord(c):02x}" if c.isalpha() and rng.random() < 0.3 else c for c in base)
    new_path = encoded + "/" + "/".join(segments)
    junk = "&".join(
        f"{''.join(rng.choices(ALNUM, k=rng.randint(3, 6)))}="
        f"{''.join(rng.choices(ALNUM, k=rng.randint(10, 30)))}"
        for _ in range(rng.randint(2, 5))
    )
    new_query = (query + "&" if query else "") + junk
    return _build(scheme, host, port, quote(new_path, safe="/%"), new_query)


def shortener(url: str, rng: random.Random, lists: Lists) -> str | None:
    p = _parts(url)
    hosts = sorted(h for h in lists.shorteners if "." in h)
    if p is None or not hosts:
        return None
    code = "".join(rng.choices(string.ascii_letters + string.digits, k=rng.randint(6, 8)))
    return f"https://{rng.choice(hosts)}/{code}"


def tld(url: str, rng: random.Random, lists: Lists) -> str | None:
    p = _parts(url)
    if p is None:
        return None
    scheme, host, port, path, query = p
    sub, label, suffix = split_host(host)
    if not suffix or not label.isascii() or f"{label}.{suffix}" in lists.platforms:
        return None
    new_suffix = rng.choice([t for t in SWAP_TLDS if t != suffix])
    if rng.random() < 0.5 and len(label) >= 4:
        cut = rng.randint(2, len(label) - 2)
        label = f"{label[:cut]}-{label[cut:]}"
    else:
        label = f"{label}-{rng.choice(('secure', 'login', 'online', 'portal'))}"
    new_host = ".".join(x for x in (sub, label, new_suffix) if x)
    return _build(scheme, new_host, port, path, query)


_TRANSFORMS = {
    "homoglyph": homoglyph,
    "subdomain": subdomain,
    "brand": brand,
    "padding": padding,
    "shortener": shortener,
    "tld": tld,
}


def apply_family(family: str, url: str, lists: Lists, seed: int = 0) -> str | None:
    """The ``family`` evasion of ``url`` (deterministic in ``seed``), or ``None``."""
    return _TRANSFORMS[family](url, _rng(url, family, seed), lists)
