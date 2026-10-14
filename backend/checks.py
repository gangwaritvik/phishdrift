"""Domain checks for the backend: raw lookups -> facts -> placeholder signals and risk.

PLACEHOLDER RULES. ``evaluate`` turns facts into signals with hand-set thresholds from
``configs/backend.yaml``. It is NOT a trained tier C model (the tier C model is on the cut
list in docs/PROJECT_SPEC.md) and nothing here has been validated against labelled data. The
output is a hint for the combiner and the popup, never evidence on its own.

Lookups reuse ``collector/domain_capture.py`` (RDAP, DNS, TLS handshake). Only a bare domain
is looked up; the backend never receives a URL or page content. To avoid being used to probe
internal hosts, a TLS handshake is made only when every address the name resolves to is
globally routable.
"""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

from backend.settings import Settings
from collector.domain_capture import (
    DnsQuery,
    dns_facts,
    fetch_rdap,
    make_query,
    tls_facts,
)
from phishdrift.domains import registered_domain
from phishdrift.http import HttpClient

log = logging.getLogger(__name__)

Checker = Callable[[str], dict[str, Any]]

FACT_KEYS = (
    "age_days",
    "registered",
    "resolves",
    "has_mx",
    "has_spf",
    "has_dmarc",
    "tls_ok",
    "tls_verified",
    "cert_age_days",
    "cert_free_issuer",
    "san_count",
)


def empty_facts() -> dict[str, Any]:
    return dict.fromkeys(FACT_KEYS)


def _days_since(iso: str | None, now: datetime) -> int | None:
    if not iso:
        return None
    try:
        when = datetime.fromisoformat(iso)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0, (now - when).days)


def _record_fact(dns: dict, present: bool, rdtype: str) -> bool | None:
    """A missing record only counts as absent when that lookup did not fail."""
    if present:
        return True
    failed = any(e.startswith(f"{rdtype}:") for e in dns.get("errors", []))
    return None if failed else False


def facts_from_raw(
    rdap: dict | None,
    rdap_error: str | None,
    dns: dict | None,
    tls: dict | None,
    now: datetime,
    free_issuers: list[str],
) -> dict[str, Any]:
    """Map the collector's raw RDAP / DNS / TLS records to the API's ``facts`` object."""
    facts = empty_facts()
    if rdap is not None:
        facts["registered"] = True
        facts["age_days"] = _days_since(rdap.get("registered"), now)
    elif rdap_error == "not_found":
        facts["registered"] = False
    if dns is not None:
        resolves = _record_fact(dns, bool(dns.get("resolves")), "A")
        if resolves is False:
            resolves = _record_fact(dns, False, "AAAA")
        facts["resolves"] = resolves
        facts["has_mx"] = _record_fact(dns, dns.get("mx_count", 0) > 0, "MX")
        facts["has_spf"] = _record_fact(dns, bool(dns.get("spf")), "TXT")
        facts["has_dmarc"] = _record_fact(dns, bool(dns.get("dmarc")), "TXT")
    if tls is not None:
        facts["tls_ok"] = bool(tls.get("ok"))
        if tls.get("ok"):
            facts["tls_verified"] = bool(tls.get("verified"))
            facts["cert_age_days"] = _days_since(tls.get("not_before"), now)
            issuer = f"{tls.get('issuer_o') or ''} {tls.get('issuer_cn') or ''}".lower()
            if issuer.strip():
                facts["cert_free_issuer"] = any(name in issuer for name in free_issuers)
            if tls.get("san_count") is not None:
                facts["san_count"] = int(tls["san_count"])
    return facts


# --- placeholder rules ------------------------------------------------------------------


# Severity each signal has unless ``rules.severity`` in configs/backend.yaml overrides it.
DEFAULT_SEVERITY = {
    "domain_very_young": "high",
    "domain_young": "warn",
    "domain_unregistered": "warn",
    "not_resolving": "warn",
    "no_tls": "info",
    "no_tls_young_domain": "warn",
    "tls_unverified": "warn",
    "free_cert_very_young_domain": "high",
}


def _signal(sid: str, text: str, severity: str | None = None) -> dict[str, str]:
    return {"id": sid, "text": text, "severity": severity or DEFAULT_SEVERITY[sid]}


def evaluate(facts: dict[str, Any], rules: dict) -> tuple[list[dict[str, str]], str]:
    """Signals from thresholds, then a risk level from their counts. Each signal's severity can
    be set in ``rules.severity`` (chosen from ``reports/domain_rules.md``)."""
    very_young, young = rules["very_young_domain_days"], rules["young_domain_days"]
    age = facts.get("age_days")
    out: list[dict[str, str]] = []
    if age is not None and age < very_young:
        out.append(
            _signal("domain_very_young", f"This domain was registered only {age} day(s) ago.")
        )
    elif age is not None and age < young:
        out.append(_signal("domain_young", f"This domain was registered only {age} days ago."))
    if facts.get("registered") is False:
        out.append(
            _signal("domain_unregistered", "No registration record was found for this domain.")
        )
    if facts.get("resolves") is False:
        out.append(_signal("not_resolving", "This domain does not resolve in DNS."))
    if facts.get("tls_ok") is False:
        out.append(_signal("no_tls", "The site does not offer a secure (HTTPS) connection."))
        if age is not None and age < young:
            out.append(
                _signal(
                    "no_tls_young_domain",
                    "A new domain without HTTPS is unusual for a real service.",
                )
            )
    if facts.get("tls_verified") is False:
        out.append(
            _signal("tls_unverified", "The site's security certificate could not be verified.")
        )
    if facts.get("cert_free_issuer") and age is not None and age < very_young:
        out.append(
            _signal(
                "free_cert_very_young_domain",
                "A brand-new domain with a free certificate is a common phishing pattern.",
            )
        )
    override = rules.get("severity") or {}
    for sig in out:
        sig["severity"] = override.get(sig["id"], sig["severity"])
    return out, risk_level(out, rules["risk"])


def risk_level(signals: list[dict[str, str]], risk_cfg: dict) -> str:
    warns = sum(1 for s in signals if s["severity"] == "warn")
    if any(s["severity"] == "high" for s in signals) or warns >= risk_cfg["high_warn_count"]:
        return "high"
    if warns >= risk_cfg["elevated_warn_count"]:
        return "elevated"
    return "low"


# --- live lookups -----------------------------------------------------------------------


class _CachedRdapClient:
    """Gives ``fetch_rdap`` the on-disk cache and a polite interval without changing it."""

    def __init__(self, client: HttpClient, ttl_s: float, min_interval_s: float) -> None:
        self._client, self._ttl_s, self._min_interval_s = client, ttl_s, min_interval_s

    def get(self, url: str, **kwargs: Any) -> bytes:
        return self._client.get(
            url, cache_ttl_s=self._ttl_s, min_interval_s=self._min_interval_s, **kwargs
        )


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _all_global(addresses: list[str]) -> bool:
    try:
        return bool(addresses) and all(ipaddress.ip_address(a).is_global for a in addresses)
    except ValueError:
        return False


class LiveChecker:
    """``domain -> facts`` using RDAP, DNS and a TLS handshake (all with timeouts)."""

    def __init__(
        self,
        settings: Settings,
        client: HttpClient | None = None,
        query: DnsQuery | None = None,
        tls: Callable[[str, float], dict] = tls_facts,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.settings = settings
        lookup, cap = settings.cfg["lookup"], settings.capture_cfg
        http = client or HttpClient.from_config(settings.http_cfg, settings.http_cache_dir)
        self._rdap_client = _CachedRdapClient(
            http, lookup["rdap_cache_ttl_s"], lookup["rdap_min_interval_s"]
        )
        self._query = query or make_query(cap)  # same resolver as the collector
        self._tls = tls
        self._now = now
        self._pool = ThreadPoolExecutor(max_workers=lookup["workers"], thread_name_prefix="rdap")

    def _rdap(self, domain: str) -> tuple[dict | None, str | None]:
        if _is_ip(domain):
            return None, "ip_host"
        try:
            return fetch_rdap(
                self._rdap_client,  # type: ignore[arg-type]  # duck-typed: only .get is used
                registered_domain(domain),
                self.settings.capture_cfg["rdap_url"],
            )
        except Exception as exc:  # noqa: BLE001 - keep the DNS/TLS facts when RDAP breaks
            return None, type(exc).__name__

    def _resolver_works(self) -> bool:
        """Control lookup of a name that always exists (``lookup.dns_control_host``)."""
        try:
            return bool(self._query(self.settings.cfg["lookup"]["dns_control_host"], "A"))
        except Exception:  # noqa: BLE001
            return False

    def _dns_tls(self, host: str) -> tuple[dict | None, dict | None]:
        cap = self.settings.capture_cfg
        if _is_ip(host):
            dns, addresses = None, [host]
        else:
            dns = dns_facts(host, registered_domain(host), self._query)
            addresses = dns["a"] + dns["aaaa"]
            if not addresses and not self._resolver_works():
                return None, None  # a broken resolver must not look like "does not resolve"
        tls = None
        if cap.get("tls", True) and _all_global(addresses):
            if self._tls is tls_facts:  # connect to our own answer, not the machine's resolver
                tls = tls_facts(host, cap["tls_timeout_s"], addresses[0])
            else:
                tls = self._tls(host, cap["tls_timeout_s"])
        return dns, tls

    def __call__(self, domain: str) -> dict[str, Any]:
        rdap_future = self._pool.submit(self._rdap, domain)
        dns, tls = self._dns_tls(domain)
        rdap, rdap_error = rdap_future.result()
        return facts_from_raw(
            rdap, rdap_error, dns, tls, self._now(), self.settings.cfg["rules"]["free_issuers"]
        )
