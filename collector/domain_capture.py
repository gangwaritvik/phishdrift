"""First-seen domain capture for tier C (live-feed URLs only).

When a host first appears in a live feed (or in the live Tranco crawl), record raw facts
about it once, at that moment: RDAP registration data for its registrable domain, DNS
records for the host and its domain, and the TLS certificate the host presents (handshake
only, no page fetch). Facts are never computed later for old URLs, because a domain's age,
DNS and certificate today say nothing about the day it was reported.

Records go to ``domain_info_dir/YYYY-MM-DD.jsonl``, one JSON object per line:
  {"kind": "domain", "domain", "captured_at", "rdap": {...} | null, "rdap_error"}
  {"kind": "host", "host", "domain", "label", "first_seen", "captured_at", "dns", "tls"}
Feature code (tier C) turns these into features later; nothing here is a model feature.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import ssl
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path

import requests

from phishdrift.domains import hostname, registered_domain
from phishdrift.http import HttpClient

log = logging.getLogger(__name__)

# (name, rdtype) -> [(value, ttl)]; [] when the name has no such record or does not exist.
DnsQuery = Callable[[str, str], list[tuple[str, int]]]


# --- RDAP ------------------------------------------------------------------------------


def _vcard_value(vcard: list, field: str) -> str | None:
    for entry in vcard[1] if len(vcard) > 1 else []:
        if entry and entry[0] == field:
            return str(entry[3]) if len(entry) > 3 else None
    return None


def parse_rdap(obj: dict) -> dict:
    """The registration facts tier C needs from an RDAP domain response."""
    events = {e.get("eventAction"): e.get("eventDate") for e in obj.get("events") or []}
    registrar = None
    for ent in obj.get("entities") or []:
        if "registrar" in (ent.get("roles") or []):
            registrar = _vcard_value(ent.get("vcardArray") or [], "fn") or ent.get("handle")
    text = json.dumps(obj).lower()
    return {
        "registered": events.get("registration"),
        "expires": events.get("expiration"),
        "last_changed": events.get("last changed"),
        "registrar": registrar,
        "status": obj.get("status") or [],
        "nameservers": sorted(
            (ns.get("ldhName") or "").lower() for ns in obj.get("nameservers") or []
        ),
        "redacted": bool(obj.get("redacted"))
        or "redacted for privacy" in text
        or "privacy" in (registrar or "").lower(),
    }


def fetch_rdap(
    client: HttpClient, domain: str, url_template: str
) -> tuple[dict | None, str | None]:
    """(parsed RDAP, None) or (None, error). rdap.org redirects to the registry's server."""
    try:
        body = client.get(
            url_template.format(domain=domain), headers={"Accept": "application/rdap+json"}
        )
        return parse_rdap(json.loads(body)), None
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        return None, "not_found" if status == 404 else f"http_{status}"
    except (requests.RequestException, ValueError) as exc:
        return None, type(exc).__name__


# --- DNS -------------------------------------------------------------------------------


def dnspython_query(timeout_s: float) -> DnsQuery:
    import dns.exception
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout_s

    def query(name: str, rdtype: str) -> list[tuple[str, int]]:
        try:
            ans = resolver.resolve(name, rdtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.Timeout:
            raise TimeoutError(f"DNS {rdtype} {name}") from None
        return [(r.to_text(), ans.rrset.ttl) for r in ans]

    return query


def dns_facts(host: str, domain: str, query: DnsQuery) -> dict:
    """Records for the host (A, AAAA, CNAME) and its registrable domain (NS, MX, SPF, DMARC)."""
    out: dict = {"errors": []}

    def q(name: str, rdtype: str) -> list[tuple[str, int]]:
        try:
            return query(name, rdtype)
        except Exception as exc:  # noqa: BLE001 - record and continue with other records
            out["errors"].append(f"{rdtype}:{type(exc).__name__}")
            return []

    a, aaaa, cname = q(host, "A"), q(host, "AAAA"), q(host, "CNAME")
    ns, mx, txt = q(domain, "NS"), q(domain, "MX"), q(domain, "TXT")
    dmarc = q(f"_dmarc.{domain}", "TXT")
    ttls = [t for recs in (a, aaaa, cname, ns, mx) for _, t in recs]
    out.update(
        {
            "a": sorted(v for v, _ in a),
            "aaaa": sorted(v for v, _ in aaaa),
            "cname": [v.rstrip(".") for v, _ in cname],
            "ns": sorted(v.rstrip(".").lower() for v, _ in ns),
            "mx_count": len(mx),
            "spf": any("v=spf1" in v.lower() for v, _ in txt),
            "dmarc": any("v=dmarc1" in v.lower() for v, _ in dmarc),
            "min_ttl": min(ttls) if ttls else None,
            "resolves": bool(a or aaaa),
        }
    )
    return out


# --- TLS -------------------------------------------------------------------------------


def _cert_time(value: str | None) -> str | None:
    if not value:
        return None
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), UTC).isoformat()


def _name_field(name: tuple, key: str) -> str | None:
    for rdn in name or ():
        for k, v in rdn:
            if k == key:
                return v
    return None


def parse_cert(cert: dict) -> dict:
    """Fields of ``ssl.SSLSocket.getpeercert()`` that tier C needs."""
    sans = [v for k, v in cert.get("subjectAltName") or () if k == "DNS"]
    return {
        "issuer_o": _name_field(cert.get("issuer"), "organizationName"),
        "issuer_cn": _name_field(cert.get("issuer"), "commonName"),
        "subject_cn": _name_field(cert.get("subject"), "commonName"),
        "not_before": _cert_time(cert.get("notBefore")),
        "not_after": _cert_time(cert.get("notAfter")),
        "san_count": len(sans),
        "sans": sans[:50],
    }


def tls_facts(host: str, timeout_s: float) -> dict:
    """Handshake with ``host:443`` and read its certificate. A certificate that fails
    verification is itself a fact (``verified: false`` with the reason)."""
    ctx = ssl.create_default_context()
    try:
        with (
            socket.create_connection((host, 443), timeout=timeout_s) as sock,
            ctx.wrap_socket(sock, server_hostname=host) as tls,
        ):
            cert = tls.getpeercert()
            return {"ok": True, "verified": True, "version": tls.version(), **parse_cert(cert)}
    except ssl.SSLCertVerificationError as exc:
        return {"ok": True, "verified": False, "error": exc.verify_message or str(exc)}
    except (OSError, ssl.SSLError) as exc:
        return {"ok": False, "verified": False, "error": type(exc).__name__}


# --- store and run ---------------------------------------------------------------------


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def load_captured(info_dir: Path) -> tuple[set[str], set[str]]:
    """(hosts, domains) already captured."""
    hosts, domains = set(), set()
    for path in sorted(Path(info_dir).glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("kind") == "host":
                hosts.add(rec["host"])
            elif rec.get("kind") == "domain":
                domains.add(rec["domain"])
    return hosts, domains


def append_records(records: list[dict], info_dir: Path, day: str) -> Path:
    path = Path(info_dir) / f"{day}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, default=str) + "\n")
    return path


def capture(
    targets: Iterable[dict],
    client: HttpClient,
    cfg: dict,
    info_dir: Path,
    now: datetime,
    query: DnsQuery | None = None,
    tls: Callable[[str, float], dict] = tls_facts,
) -> dict[str, int]:
    """Capture facts for new hosts. ``targets``: dicts with url, label, first_seen, in
    priority order (feed phishing first, since phishing hosts die fast). At most
    ``max_domains_per_run`` hosts per run; the rest wait for the next run."""
    hosts_done, domains_done = load_captured(info_dir)
    query = query or dnspython_query(cfg["dns_timeout_s"])
    records: list[dict] = []
    n_hosts = n_domains = 0
    for t in targets:
        if n_hosts >= cfg["max_domains_per_run"]:
            break
        host, domain = hostname(t["url"]), registered_domain(t["url"])
        if not host or not domain or host in hosts_done:
            continue
        hosts_done.add(host)
        stamp = datetime.now(UTC).isoformat()
        is_ip = _is_ip(host)
        if domain not in domains_done:
            domains_done.add(domain)
            rdap, err = (None, "ip_host") if is_ip else fetch_rdap(client, domain, cfg["rdap_url"])
            records.append(
                {
                    "kind": "domain",
                    "domain": domain,
                    "captured_at": stamp,
                    "rdap": rdap,
                    "rdap_error": err,
                }
            )
            n_domains += 1
        records.append(
            {
                "kind": "host",
                "host": host,
                "domain": domain,
                "label": int(t["label"]),
                "first_seen": str(t.get("first_seen")),
                "captured_at": stamp,
                "dns": None if is_ip else dns_facts(host, domain, query),
                "tls": tls(host, cfg["tls_timeout_s"]) if cfg.get("tls", True) else None,
            }
        )
        n_hosts += 1
    if records:
        append_records(records, info_dir, now.date().isoformat())
    log.info("domain capture: %d hosts, %d registrable domains", n_hosts, n_domains)
    return {"hosts": n_hosts, "domains": n_domains}
