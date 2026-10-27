"""Tier C: registration (RDAP), DNS and TLS features of a live-feed host at first-seen time.

``compute_c(host_rec, domain_rec, lists) -> dict[str, float]`` turns the raw facts that
``collector/domain_capture.py`` recorded into features. Every name is declared in
``features/registry.py`` (``NAMES_C``).

Rules
-----
- Facts are only ever the ones captured when the host first appeared in a feed; nothing is looked
  up here. Every age is measured from the host record's ``captured_at``.
- Missing is NaN, never 0: no domain record, an RDAP error other than "not found", a DNS query
  that errored for that record type, a TLS handshake that never got a certificate.
- RDAP: a domain can have several records (a failed lookup is retried on a later run);
  ``pick_domain_record`` takes the latest one with RDAP data, else the latest one.
- Certificate fields exist only when the handshake verified (the collector reads the
  certificate only then), so every ``cert_*`` value is NaN for an unverified or failed handshake.
- Liveness facts are not features: a host that stopped resolving is mostly a taken-down
  phishing page. ``host_flags`` returns them for filtering.
- A record answered with sinkhole addresses (``0.0.0.0``) by a filtering resolver on the
  collector PC is that filter's blocklist verdict, not a fact about the host
  (``collector.domain_capture.filtered_dns``). Its DNS and TLS values are all NaN, it counts as
  not resolving, and the experiment drops it.
- No popularity and no blocklist information is used.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from datetime import UTC, datetime

from collector.domain_capture import filtered_dns
from features.lists import Lists
from features.registry import NAMES_C, REGISTRY_C
from phishdrift.domains import split_host

NAN = float("nan")
SECONDS_PER_DAY = 86_400.0

# Issuers of free, automated (ACME-style) certificates, matched as lowercase substrings of the
# issuer organisation or common name.
FREE_ISSUERS = (
    "let's encrypt",
    "zerossl",
    "buypass",
    "cpanel",
    "google trust services",
    "cloudflare",
)
# TLS handshake errors that mean the name was never looked up, not that the server failed.
TLS_LOOKUP_ERRORS = frozenset({"gaierror"})
HOLD_STATUSES = ("clienthold", "serverhold")
CLOUDFLARE_NS = ".ns.cloudflare.com"

_GROUP = {
    g: tuple(f.name for f in REGISTRY_C if f.group == g) for g in ("registration", "dns", "tls")
}


# --- helpers ---------------------------------------------------------------------------


def parse_time(value: object) -> datetime | None:
    """UTC datetime from an ISO-8601 string (RDAP, certificate or capture time); None if absent
    or unreadable. A time without a zone is taken as UTC."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        t = datetime.fromisoformat(text)
    except ValueError:
        return None
    return t.replace(tzinfo=UTC) if t.tzinfo is None else t.astimezone(UTC)


def _days(later: datetime | None, earlier: datetime | None) -> float:
    if later is None or earlier is None:
        return NAN
    return (later - earlier).total_seconds() / SECONDS_PER_DAY


def _flag(value: object) -> float:
    return NAN if value is None else float(bool(value))


def pick_domain_record(records: Iterable[dict]) -> dict | None:
    """The latest record with RDAP data, else the latest record (None if there are none)."""
    recs = sorted(records, key=lambda r: str(r.get("captured_at") or ""))
    good = [r for r in recs if r.get("rdap")]
    if good:
        return good[-1]
    return recs[-1] if recs else None


def is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(str(host).strip("[]"))
    except ValueError:
        return False
    return True


def registrable(host: str) -> tuple[str, str]:
    """(domain label, registrable domain) of a host under the public-suffix-only definition."""
    _, label, suffix = split_host(host.lower().rstrip("."))
    return label, f"{label}.{suffix}" if suffix else label


def host_flags(host_rec: dict, lists: Lists) -> dict[str, object]:
    """Bookkeeping columns used to filter rows; never model features. ``resolves`` is True only
    for a real (non-sinkhole) address; a filtered record never resolves."""
    dns = host_rec.get("dns")
    filtered = filtered_dns(host_rec)
    resolves = dns.get("resolves") if dns else None
    return {
        "is_hosting_platform": bool(str(host_rec.get("domain") or "").lower() in lists.platforms),
        "is_ip": is_ip_host(str(host_rec.get("host") or "")),
        "resolves": False if filtered else None if resolves is None else bool(resolves),
        "filtered": filtered,
    }


# --- groups ----------------------------------------------------------------------------


def registration_group(domain_rec: dict | None, now: datetime | None) -> dict[str, float]:
    rdap = (domain_rec or {}).get("rdap")
    error = (domain_rec or {}).get("rdap_error")
    found = 1.0 if rdap else 0.0 if error == "not_found" else NAN
    if not rdap:
        return dict.fromkeys(_GROUP["registration"], NAN) | {"rdap_found": found}
    registered, expires = parse_time(rdap.get("registered")), parse_time(rdap.get("expires"))
    status = [str(s).lower().replace(" ", "") for s in rdap.get("status") or []]
    return {
        "domain_age_days": _days(now, registered),
        "days_to_expiry": _days(expires, now),
        "registration_length_days": _days(expires, registered),
        "days_since_rdap_change": _days(now, parse_time(rdap.get("last_changed"))),
        "rdap_found": found,
        "whois_redacted": _flag(rdap.get("redacted")),
        "rdap_status_count": float(len(status)),
        "rdap_client_hold": float(any(h in s for s in status for h in HOLD_STATUSES)),
    }


def dns_group(dns: dict | None, own_domain: str) -> dict[str, float]:
    if not dns:
        return dict.fromkeys(_GROUP["dns"], NAN)
    failed = {str(e).split(":", 1)[0].upper() for e in dns.get("errors") or []}

    def count(key: str, rdtype: str) -> float:
        return NAN if rdtype in failed else float(len(dns.get(key) or []))

    n_ns = count("ns", "NS")
    ns = [str(n).lower().rstrip(".") for n in dns.get("ns") or []]
    mx = NAN if "MX" in failed or dns.get("mx_count") is None else float(dns["mx_count"])
    txt_ok = "TXT" not in failed
    min_ttl = dns.get("min_ttl")
    has_ns = bool(n_ns == n_ns and n_ns > 0)  # n_ns == n_ns: not NaN
    return {
        "n_a": count("a", "A"),
        "n_aaaa": count("aaaa", "AAAA"),
        "has_cname": NAN if "CNAME" in failed else float(bool(dns.get("cname"))),
        "mx_count": mx,
        "has_mx": NAN if mx != mx else float(mx > 0),
        "has_spf": _flag(dns.get("spf")) if txt_ok else NAN,
        "has_dmarc": _flag(dns.get("dmarc")) if txt_ok else NAN,
        "n_ns": n_ns,
        "ns_in_own_domain": (
            float(any(registrable(n)[1] == own_domain for n in ns)) if has_ns else NAN
        ),
        "ns_cloudflare": float(any(n.endswith(CLOUDFLARE_NS) for n in ns)) if has_ns else NAN,
        "min_ttl_s": NAN if min_ttl is None else float(min_ttl),
    }


def _san_name(san: str) -> str:
    s = str(san).lower().rstrip(".")
    return s[2:] if s.startswith("*.") else s


def brand_in_sans(sans: Iterable[str], brands: Iterable[str]) -> bool:
    """A brand appears inside a label of a SAN whose registrable domain is not the brand's own
    (the brand's own = the SAN's registrable-domain label equals the brand)."""
    brands = tuple(brands)
    for san in sans:
        name = _san_name(san)
        if not name or is_ip_host(name):
            continue
        own_label, _ = registrable(name)
        labels = [x for x in name.split(".") if x]
        for b in brands:
            if b != own_label and any(b in x for x in labels):
                return True
    return False


def cn_matches(cn: str, host: str) -> bool:
    """Certificate common name covers ``host`` (exact, or a wildcard for one label)."""
    cn, host = str(cn).lower().rstrip("."), str(host).lower().rstrip(".")
    if cn == host:
        return True
    if cn.startswith("*."):
        head, _, rest = host.partition(".")
        return bool(head) and rest == cn[2:]
    return False


def tls_group(tls: dict | None, host: str, now: datetime | None, lists: Lists) -> dict[str, float]:
    out = dict.fromkeys(_GROUP["tls"], NAN)
    if not tls or (not tls.get("ok") and tls.get("error") in TLS_LOOKUP_ERRORS):
        return out
    out["tls_ok"] = _flag(tls.get("ok"))
    if not tls.get("ok"):
        return out
    out["tls_verified"] = _flag(tls.get("verified"))
    has_cert = any(tls.get(k) for k in ("issuer_o", "issuer_cn", "not_before", "subject_cn"))
    if not tls.get("verified") or not has_cert:
        return out
    issuer = f"{tls.get('issuer_o') or ''} {tls.get('issuer_cn') or ''}".lower()
    start, end = parse_time(tls.get("not_before")), parse_time(tls.get("not_after"))
    sans = list(tls.get("sans") or [])
    subject = tls.get("subject_cn")
    out |= {
        "cert_free_issuer": float(any(i in issuer for i in FREE_ISSUERS))
        if issuer.strip()
        else NAN,
        "cert_validity_days": _days(end, start),
        "cert_age_days": _days(now, start),
        "cert_days_left": _days(end, now),
        "cert_san_count": NAN if tls.get("san_count") is None else float(tls["san_count"]),
        "cert_wildcard": float(any(str(s).startswith("*.") for s in [*sans, subject or ""])),
        "cert_cn_matches_host": float(cn_matches(subject, host)) if subject else NAN,
        "brand_in_cert_sans": float(brand_in_sans(sans, lists.brands)),
    }
    return out


def compute_c(host_rec: dict, domain_rec: dict | None, lists: Lists) -> dict[str, float]:
    """Every tier C feature of one host record (with its registrable domain's record)."""
    now = parse_time(host_rec.get("captured_at"))
    host = str(host_rec.get("probe_host") or host_rec.get("host") or "").lower()
    own = str(host_rec.get("domain") or registrable(host)[1]).lower()
    filtered = filtered_dns(host_rec)  # the PC's resolver answered, not the host's DNS
    values = (
        registration_group(domain_rec, now)
        | dns_group(None if filtered else host_rec.get("dns"), own)
        | tls_group(None if filtered else host_rec.get("tls"), host, now, lists)
    )
    return {n: float(values[n]) for n in NAMES_C}
