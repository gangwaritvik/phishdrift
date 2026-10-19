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

import base64
import hashlib
import json
import logging
import os
import re
import string
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq

from phishdrift.domains import _EXTRACT_U2, split_host

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


def _tenant_like(counts: dict[str, int], min_children: int, min_per_url: float) -> bool:
    return len(counts) >= min_children and len(counts) / sum(counts.values()) >= min_per_url


def _segments(rest: str, n: int) -> list[str]:
    """First ``n`` non-empty path segments of ``rest`` (query dropped), ASCII-lowercased."""
    path = rest.partition("?")[0].translate(_LOWER)
    return [seg for seg in path.split("/") if seg][:n]


def _path_tenants(paths: Iterable[list[str]], min_children: int) -> tuple[set[str], dict[str, int]]:
    """Generic first segments and tenant counts for the phishing paths of one host.

    A first segment is *generic* when at least ``min_children`` different second segments follow
    it (``ipfs.io/ipfs/<cid>``, ``sites.google.com/view/<site>``); its tenants are then the first
    two segments. Otherwise the tenant is the first segment (``telegra.ph/<page>``). Learned from
    the data, so no path is hand-written. At most one generic level is followed, so a long open
    redirect (``google.com/amp/s/<host>``) never makes a big site's own path a tenant."""
    paths = [p for p in paths if p]
    nexts: dict[str, set[str]] = defaultdict(set)
    for p in paths:
        if len(p) > 1:
            nexts[p[0]].add(p[1])
    generic = {seg for seg, seen in nexts.items() if len(seen) >= min_children}
    counts: dict[str, int] = defaultdict(int)
    for p in paths:
        tenant = "/".join(p[:2]) if p[0] in generic and len(p) > 1 else p[0]
        counts[tenant] += 1
    return generic, counts


def path_tenant_prefix(rest: str, generic: set[str] | frozenset[str]) -> str:
    """Tenant path prefix (``/x`` or ``/view/x``) of ``rest`` under a path-tenant host, or ''."""
    segs = _segments(rest, 2)
    if not segs:
        return ""
    return "/" + ("/".join(segs) if segs[0] in generic and len(segs) > 1 else segs[0])


def private_tenant(host: str) -> str:
    """The tenant site of ``host`` on a platform with a PSL private suffix (``x.web.app``,
    ``b.github.io`` for ``a.b.github.io``), or '' when the host is not a tenant (``web.app``,
    ``s3.amazonaws.com`` and ``weebly.com`` hosts give '')."""
    ext = _EXTRACT_U2(host)
    if not (ext.domain and ext.suffix):
        return ""
    tenant = f"{ext.domain}.{ext.suffix}"
    _, label, suffix = split_host(host)
    return "" if tenant == f"{label}.{suffix}" else tenant


def sub_tenant(host: str, domain: str) -> str:
    """The tenant site a subdomain ``host`` of registrable ``domain`` belongs to: the PSL
    private-suffix tenant when there is one (``x.blob.core.windows.net``), else the child of the
    domain (``x.weebly.com`` for ``a.x.weebly.com``)."""
    tenant = private_tenant(host)
    if tenant:
        return tenant
    return host[: -len(domain) - 1].rsplit(".", 1)[-1] + "." + domain


@dataclass
class ZoneModel:
    """What the learner found. ``zones`` maps a zone to how it was learned: ``child`` (phishing
    at or below one child of a big site, ``drive.google.com``), ``sub`` (whole domain, one tenant
    per subdomain, ``weebly.com``) or ``path`` (whole domain, tenants are paths, ``telegra.ph``).
    ``path_hosts`` maps every host whose phishing paths look like one tenant each (enough
    distinct tenants, few URLs per tenant) to its generic first segments. ``tenant_domains``
    holds the registrable domains whose phishing subdomains look like one tenant each
    (``sub_tenant``): only there may the blocklist list a whole tenant host."""

    zones: dict[str, str] = field(default_factory=dict)
    path_hosts: dict[str, frozenset[str]] = field(default_factory=dict)
    tenant_domains: set[str] = field(default_factory=set)


def learn_zones(
    phishing_urls: Iterable[str],
    candidates: set[str],
    min_tenant_children: int,
    min_children_per_url: float,
    min_children_whole: int | None = None,
    shared: set[str] | frozenset[str] = frozenset(),
) -> ZoneModel:
    """Learn open-hosting zones (see the module docstring) below ``candidates`` and path-tenant
    hosts below ``candidates`` and ``shared`` (hosting platforms).

    Tenants are subdomains (``x.weebly.com``) or, for phishing on the bare domain, paths
    (``telegra.ph/x``, ``ipfs.io/ipfs/<cid>``; see ``_path_tenants``). A path cannot be a zone,
    so path tenants only ever open the whole domain. ``min_children_whole`` distinct subdomain
    children open the whole domain whatever their URL counts (busy tenants, as on
    ``mybluehost.me``)."""
    children: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    tenants: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    host_paths: dict[str, list[list[str]]] = defaultdict(list)
    host_domain: dict[str, str] = {}
    for url in phishing_urls:
        domain = list_domain_key(url)
        if domain not in candidates and domain not in shared:
            continue
        host, _, rest = _split(url)
        host_paths[host].append(_segments(rest, 2))
        host_domain[host] = domain
        if host != domain and host.endswith("." + domain):
            tenants[domain][sub_tenant(host, domain)] += 1
            if domain in candidates:
                children[domain][host[: -len(domain) - 1].rsplit(".", 1)[-1]] += 1
    model = ZoneModel()
    for domain, counts in tenants.items():
        if _tenant_like(counts, min_tenant_children, min_children_per_url) or bool(
            min_children_whole and len(counts) >= min_children_whole
        ):
            model.tenant_domains.add(domain)
    path_like: dict[str, bool] = {}
    for host, paths in host_paths.items():
        generic, counts = _path_tenants(paths, min_tenant_children)
        if _tenant_like(counts, min_tenant_children, min_children_per_url):
            model.path_hosts[host] = frozenset(generic)
            path_like[host] = True
    for domain in candidates & (children.keys() | {host_domain[h] for h in host_paths}):
        counts = children.get(domain, {})
        if _tenant_like(counts, min_tenant_children, min_children_per_url) or bool(
            min_children_whole and len(counts) >= min_children_whole
        ):
            model.zones[domain] = "sub"
        elif path_like.get(domain):
            model.zones[domain] = "path"
        else:
            for child in counts:
                model.zones.setdefault(f"{child}.{domain}", "child")
    return model


def open_hosting_zones(
    phishing_urls: Iterable[str],
    candidates: set[str],
    min_tenant_children: int,
    min_children_per_url: float,
    min_children_whole: int | None = None,
) -> set[str]:
    """Zone names only (``learn_zones``)."""
    return set(
        learn_zones(
            phishing_urls, candidates, min_tenant_children, min_children_per_url, min_children_whole
        ).zones
    )


def list_url_expressions(url: str) -> list[str]:
    """Every key under which a blocklist URL entry can match ``url`` (the extension hashes each
    one and looks it up), in the spirit of Safe Browsing's host-suffix / path-prefix expressions.

    Hosts: the host with its port, then up to four parent suffixes of at least two labels.
    Paths for each host: none, the first one, two and three non-empty path segments, the whole
    path without trailing ``/``, and the whole path with the query (this last one on the full
    host is ``list_url_key``). The builder decides which of these keys an entry is listed under
    (``block_url_keys``), so a lookup never blocks more than the builder chose to."""
    host, port, rest = _split(url)
    path, sep, query = rest.partition("?")
    path = path.rstrip("/")
    segs = [seg for seg in path.split("/") if seg]
    paths = ["", *("/" + "/".join(segs[:n]) for n in range(1, min(len(segs), 3) + 1)), path]
    if sep:
        paths.append(path + "?" + query)
    hosts = [host + port]
    labels = host.split(".")
    for i in range(1, len(labels) - 1):
        if len(hosts) == 5:
            break
        hosts.append(".".join(labels[i:]))
    out: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        for p in paths:
            key = h + p
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


def _specific(path: str, min_len: int) -> bool:
    """True when a path segment is long enough to name one object (a form or file id)."""
    return any(len(seg) >= min_len for seg in path.split("/"))


def block_url_keys(
    url: str,
    model: ZoneModel,
    protected: set[str] | frozenset[str] = frozenset(),
    specific_segment_len: int = 16,
) -> list[str]:
    """Keys a blocklisted URL on a shared host is listed under (each one is also produced by
    ``list_url_expressions`` for the URLs it should match):

    - the exact URL (``list_url_key``), always;
    - the tenant: the tenant host on a domain whose phishing is one tenant per subdomain
      (``x.web.app``, ``x.weebly.com``; ``ZoneModel.tenant_domains``), or the host plus the
      tenant path on a path-tenant host (``telegra.ph/x``, ``sites.google.com/view/x``);
    - the URL without its query, on a tenant or when a path segment names one object, so a
      per-victim token in the query does not dodge the list.

    No key is ever a ``protected`` host (allowlist candidates and hosting platforms themselves)."""
    host, port, rest = _split(url)
    path, sep, _ = rest.partition("?")
    path = path.rstrip("/")
    domain = list_domain_key(url)
    keys = [list_url_key(url)]
    tenant = ""
    if host != domain and domain in model.tenant_domains and host.endswith("." + domain):
        tenant = sub_tenant(host, domain)
        if tenant in model.path_hosts or tenant in protected:
            tenant = ""  # a shared host (storage.googleapis.com) is never blocked as a whole
    if not tenant and host in model.path_hosts:
        prefix = path_tenant_prefix(path, model.path_hosts[host])
        if prefix:
            segs = [seg for seg in path.split("/") if seg]
            tenant = host + port + "/" + "/".join(segs[: prefix.count("/")])
    if tenant:
        keys.append(tenant)
    if sep and (tenant or _specific(path, specific_segment_len)):
        keys.append(host + port + path)
    return [k for k in dict.fromkeys(keys) if k not in protected]


def _canonical(doc: dict) -> bytes:
    """Exact bytes of a list file: compact JSON, non-ASCII kept as UTF-8, so the extension can
    rebuild the same bytes with ``JSON.stringify`` after a delta and check the hash."""
    return json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def build_lists(
    blocklist_urls: Iterable[str],
    allow_candidates: Iterable[str],
    platforms: frozenset[str],
    prefix_bytes: int,
    built_at: datetime | None = None,
    extra_phishing_urls: Iterable[str] = (),
    min_tenant_children: int = 3,
    min_children_per_url: float = 0.5,
    min_children_whole: int | None = None,
    shorteners: frozenset[str] = frozenset(),
    allow_prefix_bytes: int | None = None,
    sentinel_top_n: int = 1000,
    specific_segment_len: int = 16,
) -> dict[str, dict]:
    """Return ``{"manifest", "blocklist", "allowlist"}`` documents (all sorted, deterministic
    except ``built_at``). ``extra_phishing_urls`` (for example the corpus's phishing URLs) only
    help find open-hosting domains; they are not blocklisted. Shorteners are never allowlisted:
    a short link says nothing about where it leads (the extension judges the target instead).

    ``prefix_bytes`` sizes the blocklist hashes and ``allow_prefix_bytes`` (default: the same)
    the allowlist hashes: a short allowlist prefix lets an attacker register a domain whose hash
    collides with a trusted one. ``allow_candidates`` are in rank order; the hashes of the first
    ``sentinel_top_n`` allowlisted ones are listed in ``allowlist.top`` so the extension can
    refuse a synced list that would block or drop the most visited sites."""
    allow_bytes = allow_prefix_bytes or prefix_bytes
    blocklist_urls = list(blocklist_urls)
    ranked = list(dict.fromkeys(d for d in map(list_domain_key, allow_candidates) if d))
    ranked = [d for d in ranked if d not in shorteners]
    cand_domains = set(ranked)
    model = learn_zones(
        [*blocklist_urls, *extra_phishing_urls],
        cand_domains - platforms,
        min_tenant_children,
        min_children_per_url,
        min_children_whole,
        shared=platforms,
    )
    zones = set(model.zones)
    protected = cand_domains | platforms | zones
    block_domains: set[str] = set()
    block_urls: set[str] = set()
    plain_block_domains: set[str] = set()
    for url in blocklist_urls:
        domain = list_domain_key(url)
        if not domain:
            continue
        # platforms, open-hosting zones and allowlist candidates are listed by URL keys: blocking
        # the domain would block every tenant (github.io) or the big site itself (github.com
        # serving one bad download); any other domain is listed by its registrable domain
        if domain in platforms or domain in cand_domains or in_zone(url_host(url), zones):
            for key in block_url_keys(url, model, protected, specific_segment_len):
                block_urls.add(list_hash(key, prefix_bytes))
        else:
            plain_block_domains.add(domain)
            block_domains.add(list_hash(domain, prefix_bytes))
    allowed_ranked = [
        d for d in ranked if d not in platforms and d not in zones and d not in plain_block_domains
    ]
    allow = {list_hash(d, allow_bytes) for d in allowed_ranked}
    top = [list_hash(d, allow_bytes) for d in allowed_ranked[:sentinel_top_n]]
    doms, urls, allowed = sorted(block_domains), sorted(block_urls), sorted(allow)
    opened = sorted(zones)
    digest = hashlib.sha256(
        json.dumps(
            [prefix_bytes, allow_bytes, doms, urls, allowed, opened, top], separators=(",", ":")
        ).encode()
    ).hexdigest()
    version = digest[:12]
    built = (built_at or datetime.now(UTC)).astimezone(UTC).isoformat(timespec="seconds")
    blocklist = {"version": version, "prefix_bytes": prefix_bytes, "domains": doms, "urls": urls}
    allowlist = {
        "version": version,
        "prefix_bytes": allow_bytes,
        "domains": allowed,
        "open_hosting": opened,
        "top": top,
    }
    manifest = {
        "version": version,
        "built_at": built,
        "prefix_bytes": prefix_bytes,
        "allow_prefix_bytes": allow_bytes,
        "counts": {
            "blocklist_domains": len(doms),
            "blocklist_urls": len(urls),
            "allowlist_domains": len(allowed),
            "open_hosting_domains": len(opened),
            "allowlist_top": len(top),
        },
        "sha256": {
            "blocklist": hashlib.sha256(_canonical(blocklist)).hexdigest(),
            "allowlist": hashlib.sha256(_canonical(allowlist)).hexdigest(),
        },
    }
    return {"manifest": manifest, "blocklist": blocklist, "allowlist": allowlist}


def sign_body(body: bytes, private_key_pem: bytes) -> str:
    """Base64 raw ``r || s`` ECDSA P-256 / SHA-256 signature of ``body`` (the form WebCrypto's
    ``verify`` takes)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    key = serialization.load_pem_private_key(private_key_pem, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise ValueError("the list signing key must be an ECDSA P-256 private key")
    r, s_ = decode_dss_signature(key.sign(body, ec.ECDSA(hashes.SHA256())))
    return base64.b64encode(r.to_bytes(32, "big") + s_.to_bytes(32, "big")).decode("ascii")


def verify_body(body: bytes, signature: str, public_spki_b64: str) -> bool:
    """Check a ``sign_body`` signature against a base64 DER SubjectPublicKeyInfo key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    try:
        raw = base64.b64decode(signature, validate=True)
        key = serialization.load_der_public_key(base64.b64decode(public_spki_b64))
    except (ValueError, TypeError):
        return False
    if len(raw) != 64 or not isinstance(key, ec.EllipticCurvePublicKey):
        return False
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    try:
        key.verify(der, body, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def public_key_module(public: dict | None) -> str:
    """The extension's ``lists_pubkey.js``: the list-signing public key (or null: unsigned)."""
    body = json.dumps(public, indent=1) if public else "null"
    return (
        "// Public key that signs the synced lists and remote config (backend/lists.py).\n"
        "// Written by `python -m backend make-signing-key`;\n"
        "// null means signatures are not checked.\n"
        f"export const LIST_PUBKEY = {body};\n"
    )


def make_signing_key(private_path: Path, public_paths: Iterable[Path]) -> dict:
    """Create an ECDSA P-256 key pair: the private key (PEM, mode 0600) stays with the backend;
    the public key (``{"alg", "spki"}``) is written as ``lists_pubkey.js`` modules for the
    extension (source and any built copy). Refuses to overwrite an existing private key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    private_path = Path(private_path)
    if private_path.exists():
        raise FileExistsError(f"{private_path} exists; delete it first to rotate the key")
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    private_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(pem)
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public = {"alg": "ECDSA-P256-SHA256", "spki": base64.b64encode(spki).decode("ascii")}
    for path in public_paths:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(public_key_module(public), encoding="utf-8")
    return public


def signed_manifest(manifest: dict, private_key_pem: bytes | None) -> dict:
    """``manifest`` plus ``signature`` over its canonical bytes (without the signature field)."""
    body = {k: v for k, v in manifest.items() if k != "signature"}
    if private_key_pem is None:
        return body
    return {**body, "signature": sign_body(_canonical(body), private_key_pem)}


def write_lists(
    docs: dict[str, dict],
    out_dir: Path,
    private_key_pem: bytes | None = None,
    history_keep: int = 48,
) -> dict[str, Path]:
    """Write ``manifest.json``, ``blocklist.json`` and ``allowlist.json`` atomically (the
    manifest last, so a reader that sees a new manifest finds the matching lists). The manifest
    is signed when a key is given. The lists are also kept in ``history/<version>.json`` (the
    newest ``history_keep`` builds) so ``list_delta`` can serve small hourly updates."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    hist = out_dir / "history"
    hist.mkdir(exist_ok=True)
    version = docs["manifest"]["version"]
    snap = hist / f"{version}.json"
    tmp = snap.with_suffix(".json.tmp")
    tmp.write_bytes(_canonical({"blocklist": docs["blocklist"], "allowlist": docs["allowlist"]}))
    os.replace(tmp, snap)
    os.utime(snap)
    for old in sorted(hist.glob("*.json"), key=lambda p: p.stat().st_mtime)[:-history_keep]:
        old.unlink(missing_ok=True)
    out = {**docs, "manifest": signed_manifest(docs["manifest"], private_key_pem)}
    paths: dict[str, Path] = {}
    for name in ("blocklist", "allowlist", "manifest"):
        path = out_dir / f"{name}.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_bytes(_canonical(out[name]))
        os.replace(tmp, path)
        paths[name] = path
    return paths


_VERSION_RE = re.compile(r"^[0-9a-f]{12}$")
_DELTA_SETS = {"blocklist": ("domains", "urls"), "allowlist": ("domains", "open_hosting")}


def list_delta(out_dir: Path, from_version: str) -> dict | None:
    """Changes from the build ``from_version`` to the current one, or None when that build is
    not in the history (or the hash sizes changed): the client then downloads the full lists.

    ``{"from", "to", "blocklist": {"version", "prefix_bytes", "domains": {"add", "del"},
    "urls": {...}}, "allowlist": {"version", "prefix_bytes", "domains": {...},
    "open_hosting": {...}, "top": [...]}}``. ``top`` is sent whole (it is ordered). The client
    applies it, rebuilds each list file and checks its sha256 against the signed manifest."""
    out_dir = Path(out_dir)
    if not _VERSION_RE.match(from_version):
        return None
    old_path = out_dir / "history" / f"{from_version}.json"
    if not old_path.exists():
        return None
    old = json.loads(old_path.read_text(encoding="utf-8"))
    new = {n: json.loads((out_dir / f"{n}.json").read_text(encoding="utf-8")) for n in _DELTA_SETS}
    delta: dict = {"from": from_version, "to": new["blocklist"]["version"]}
    for name, fields in _DELTA_SETS.items():
        if old[name]["prefix_bytes"] != new[name]["prefix_bytes"]:
            return None
        part: dict = {"version": new[name]["version"], "prefix_bytes": new[name]["prefix_bytes"]}
        for f in fields:
            a, b = set(old[name][f]), set(new[name][f])
            part[f] = {"add": sorted(b - a), "del": sorted(a - b)}
        if name == "allowlist":
            part["top"] = new[name]["top"]
        delta[name] = part
    return delta
