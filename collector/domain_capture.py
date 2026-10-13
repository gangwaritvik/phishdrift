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

import inspect
import ipaddress
import json
import logging
import os
import socket
import ssl
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path

import requests

from collector.benign import run_parallel
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


# Type numbers in DNS-over-HTTPS JSON answers.
RDTYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
# Answers a filtering resolver gives for a blocked name. They are the filter's verdict (a
# blocklist), not facts about the host, so they never count as resolving.
SINKHOLE_ADDRESSES = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1"})


def doh_query(
    urls: list[str], timeout_s: float, session: requests.Session | None = None
) -> DnsQuery:
    """DNS over HTTPS (JSON API) against public resolvers that do not filter. The machine's
    own resolver may be a protective DNS service: on 2026-10-12 the collector PC got 0.0.0.0
    for most phishing hosts, which hid their real records and broke the TLS handshake. Each
    URL is tried in turn (e.g. dns.google, then cloudflare-dns.com)."""
    session = session or requests.Session()

    def query(name: str, rdtype: str) -> list[tuple[str, int]]:
        error: Exception | None = None
        for url in urls:
            try:
                resp = session.get(
                    url,
                    params={"name": name, "type": rdtype},
                    headers={"Accept": "application/dns-json"},
                    timeout=timeout_s,
                )
                resp.raise_for_status()
                body = resp.json()
            except (requests.RequestException, ValueError) as exc:
                error = exc
                continue
            if body.get("Status") not in (0, 3):  # NOERROR, NXDOMAIN; others are failures
                error = RuntimeError(f"DNS status {body.get('Status')}")
                continue
            want = RDTYPES[rdtype]
            return [
                (
                    str(a.get("data", "")).strip('"')
                    if rdtype == "TXT"
                    else str(a.get("data", "")),
                    int(a.get("TTL", 0)),
                )
                for a in body.get("Answer") or []
                if a.get("type") == want
            ]
        raise TimeoutError(f"DoH {rdtype} {name}: {error}")

    return query


def make_query(cfg: dict) -> DnsQuery:
    """The capture resolver from config: ``dns_resolver: doh`` (default when ``doh_urls`` is
    set) or ``system`` (dnspython with the machine's resolver)."""
    if cfg.get("dns_resolver", "doh" if cfg.get("doh_urls") else "system") == "doh":
        return doh_query(cfg["doh_urls"], cfg["dns_timeout_s"])
    return dnspython_query(cfg["dns_timeout_s"])


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
    addresses = [v for v, _ in a + aaaa]
    real = [v for v in addresses if v not in SINKHOLE_ADDRESSES]
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
            "resolves": bool(real),
            "sinkhole": bool(addresses) and not real,
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


def tls_facts(host: str, timeout_s: float, address: str | None = None) -> dict:
    """Handshake with ``host:443`` and read its certificate. A certificate that fails
    verification is itself a fact (``verified: false`` with the reason). ``address``: connect
    to this IP (from our own DNS answer) instead of asking the machine's resolver, still
    sending ``host`` as the server name."""
    ctx = ssl.create_default_context()
    try:
        with (
            socket.create_connection((address or host, 443), timeout=timeout_s) as sock,
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


def filtered_dns(rec: dict) -> bool:
    """True when a host record's addresses are all sinkhole answers from a filtering resolver
    (records written before the ``sinkhole`` key existed are checked from their addresses)."""
    dns = rec.get("dns") or {}
    if "sinkhole" in dns:
        return bool(dns["sinkhole"])
    addresses = list(dns.get("a") or []) + list(dns.get("aaaa") or [])
    return bool(addresses) and all(a in SINKHOLE_ADDRESSES for a in addresses)


def dns_failed(rec: dict) -> bool:
    """True when both address lookups failed (resolver unreachable), so nothing is known."""
    errors = (rec.get("dns") or {}).get("errors") or []
    return any(e.startswith("A:") for e in errors) and any(e.startswith("AAAA:") for e in errors)


FINAL_RDAP_ERRORS = frozenset({"not_found", "ip_host"})  # answers, not failures: never retried


def load_state(info_dir: Path) -> tuple[set[str], set[str], dict[str, int]]:
    """(hosts captured, domains with a final RDAP answer, failed RDAP lookups per domain).
    A lookup that failed (rate limit, timeout, server error) is retried on a later run."""
    hosts, domains = set(), set()
    failures: dict[str, int] = {}
    for path in sorted(Path(info_dir).glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:  # a line cut off by a stopped run: that host is captured again
                log.warning("%s: skipping an unreadable line", path.name)
                continue
            if rec.get("kind") == "host":
                if not filtered_dns(rec) and not dns_failed(rec):  # else captured again later
                    hosts.add(rec["host"])
            elif rec.get("kind") == "domain":
                d = rec["domain"]
                if rec.get("rdap") is not None or rec.get("rdap_error") in FINAL_RDAP_ERRORS:
                    domains.add(d)
                else:
                    failures[d] = failures.get(d, 0) + 1
    return hosts, domains, failures


def load_captured(info_dir: Path) -> tuple[set[str], set[str]]:
    """(hosts, domains) already captured (domains: with a final RDAP answer)."""
    hosts, domains, _ = load_state(info_dir)
    return hosts, domains


def append_records(records: list[dict], info_dir: Path, day: str) -> Path:
    """Append ``records`` as JSON lines with one write call, so a stopped run leaves at most
    one cut-off last line (which ``load_captured`` skips). A cut-off line without a trailing
    newline is terminated first, so it cannot swallow the first new record."""
    path = Path(info_dir) / f"{day}.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(rec, default=str) + "\n" for rec in records)
    if path.exists() and path.stat().st_size > 0:
        with path.open("rb") as rd:
            rd.seek(-1, os.SEEK_END)
            if rd.read(1) != b"\n":
                text = "\n" + text
    with path.open("ab") as fh:
        fh.write(text.encode("utf-8"))
        fh.flush()
        os.fsync(fh.fileno())
    return path


def plan_jobs(
    targets: Iterable[dict],
    hosts_done: set[str],
    domains_done: set[str],
    failures: dict[str, int],
    max_hosts: int,
    rdap_retries: int,
) -> list[dict]:
    """Work for one run, in target order: new hosts (with an RDAP lookup for the first host of
    each domain without a final answer) up to ``max_hosts``, plus RDAP-only retries for domains
    whose earlier lookups failed fewer than ``rdap_retries`` times."""
    jobs: list[dict] = []
    hosts, domains = set(hosts_done), set(domains_done)
    n_hosts = 0
    for t in targets:
        host, domain = hostname(t["url"]), registered_domain(t["url"])
        if not host or not domain:
            continue
        if host not in hosts:
            if n_hosts >= max_hosts:
                continue
            hosts.add(host)
            n_hosts += 1
            jobs.append(
                {"host": host, "domain": domain, "target": t, "rdap": domain not in domains}
            )
            domains.add(domain)
        elif domain not in domains and failures.get(domain, 0) < rdap_retries:
            domains.add(domain)
            jobs.append({"host": host, "domain": domain, "target": None, "rdap": True})
    return jobs


def capture_job(
    job: dict, client: HttpClient, cfg: dict, query: DnsQuery, tls: Callable[..., dict]
) -> list[dict]:
    """Records for one job: the domain's RDAP record (when asked) and the host's DNS/TLS record."""
    host, domain, t = job["host"], job["domain"], job["target"]
    stamp = datetime.now(UTC).isoformat()
    is_ip = _is_ip(host)
    records = []
    if job["rdap"]:
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
    if t is not None:
        dns = None if is_ip else dns_facts(host, domain, query)
        address = host.strip("[]") if is_ip else _first_real_address(dns)
        records.append(
            {
                "kind": "host",
                "host": host,
                "domain": domain,
                "label": int(t["label"]),
                "first_seen": str(t.get("first_seen")),
                "captured_at": stamp,
                "dns": dns,
                "tls": tls(host, cfg["tls_timeout_s"], address) if cfg.get("tls", True) else None,
            }
        )
    return records


def _first_real_address(dns: dict) -> str | None:
    for value in list(dns.get("a") or []) + list(dns.get("aaaa") or []):
        if value not in SINKHOLE_ADDRESSES:
            return value
    return None


def _run_jobs(
    jobs: list[dict], work: Callable[[dict], list[dict] | None], workers: int, hard_limit_s: float
):
    """Yield each job's records as it finishes. With ``workers`` > 1 the jobs run on daemon
    threads and a job still running after ``hard_limit_s`` is abandoned (yields None), so one
    stuck lookup cannot hold the run, and its lock, for hours (seen on 2026-10-12: a run
    stopped logging after 350 hosts and kept the lock until the task limit)."""
    if workers <= 1:
        for job in jobs:
            yield work(job)
        return

    def guarded(job: dict) -> list[dict] | None:
        try:
            return work(job)
        except Exception as exc:  # noqa: BLE001 - one bad host must not stop the run
            log.warning("domain capture: %s failed: %s", job["host"], exc)
            return None

    for job, recs in run_parallel(jobs, guarded, workers, hard_limit_s):
        if recs is None and job is not None:
            log.debug("domain capture: %s gave no records (timed out or failed)", job["host"])
        yield recs


def capture(
    targets: Iterable[dict],
    client: HttpClient,
    cfg: dict,
    info_dir: Path,
    now: datetime,
    query: DnsQuery | None = None,
    tls: Callable[..., dict] = tls_facts,
) -> dict[str, int]:
    """Capture facts for new hosts. ``targets``: dicts with url, label, first_seen, in
    priority order (feed phishing first, since phishing hosts die fast). At most
    ``max_domains_per_run`` hosts per run; the rest wait for the next run. ``workers`` hosts
    are captured at once (default 1; each RDAP server still gets the politeness delay).

    Safe to stop at any time: finished hosts are appended every ``checkpoint_every`` hosts
    (and when the loop ends or is interrupted), and no new host is started once
    ``time_budget_s`` seconds have passed. Both keys are optional (no checkpoints / no budget)."""
    hosts_done, domains_done, failures = load_state(info_dir)
    query = query or make_query(cfg)
    if len(inspect.signature(tls).parameters) < 3:  # a (host, timeout) callable
        two_args = tls

        def tls(host: str, timeout_s: float, address: str | None = None) -> dict:
            return two_args(host, timeout_s)

    checkpoint_every = cfg.get("checkpoint_every")
    budget_s = cfg.get("time_budget_s")
    started = time.monotonic()
    day = now.date().isoformat()
    jobs = plan_jobs(
        targets,
        hosts_done,
        domains_done,
        failures,
        cfg["max_domains_per_run"],
        cfg.get("rdap_retries", 2),
    )
    over_budget = False

    def work(job: dict) -> list[dict] | None:
        nonlocal over_budget
        if budget_s is not None and time.monotonic() - started > budget_s:
            over_budget = True
            return None
        return capture_job(job, client, cfg, query, tls)

    records: list[dict] = []
    n_hosts = n_domains = 0
    try:
        workers, hard_limit_s = int(cfg.get("workers", 1)), cfg.get("job_deadline_s", 300)
        for recs in _run_jobs(jobs, work, workers, hard_limit_s):
            if recs is None:
                continue
            records += recs
            n_domains += sum(r["kind"] == "domain" for r in recs)
            new_hosts = sum(r["kind"] == "host" for r in recs)
            n_hosts += new_hosts
            if checkpoint_every and new_hosts and n_hosts % checkpoint_every == 0:
                append_records(records, info_dir, day)
                records = []
                log.info("domain capture: %d of %d hosts so far", n_hosts, len(jobs))
    finally:  # also on Ctrl+C: keep every host that finished
        if records:
            append_records(records, info_dir, day)
    if over_budget:
        log.warning("domain capture: time budget of %ss used up; the rest waits", budget_s)
    log.info("domain capture: %d hosts, %d registrable domains", n_hosts, n_domains)
    return {"hosts": n_hosts, "domains": n_domains}
