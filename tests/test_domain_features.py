"""Tier C features (registration, DNS, TLS) and the host-level table builder."""

import json
import math

import pandas as pd
import pytest

from features import build_c
from features.dictionary import render
from features.domain_features import (
    brand_in_sans,
    cn_matches,
    compute_c,
    host_flags,
    parse_time,
    pick_domain_record,
)
from features.lists import Lists
from features.registry import GROUPS_C, NAMES_C, REGISTRY_C

LISTS = Lists.build(platforms=["web.app"], brands=["paypal", "dhl"])
NOW = "2026-10-12T12:00:00+00:00"


def host(**kw) -> dict:
    rec = {
        "kind": "host",
        "host": "login.example.com",
        "domain": "example.com",
        "label": 1,
        "first_seen": "2026-10-12 10:00:00+00:00",
        "captured_at": NOW,
        "dns": {
            "errors": [],
            "a": ["192.0.2.1", "192.0.2.2"],
            "aaaa": [],
            "cname": ["x.cdn.net"],
            "ns": ["ns1.example.com", "ns2.example.com"],
            "mx_count": 2,
            "spf": True,
            "dmarc": False,
            "min_ttl": 300,
            "resolves": True,
        },
        "tls": {
            "ok": True,
            "verified": True,
            "version": "TLSv1.3",
            "issuer_o": "Let's Encrypt",
            "issuer_cn": "R11",
            "subject_cn": "*.example.com",
            "not_before": "2026-10-02T12:00:00+00:00",
            "not_after": "2026-12-31T12:00:00+00:00",
            "san_count": 2,
            "sans": ["*.example.com", "example.com"],
        },
    }
    rec.update(kw)
    return rec


def domain(rdap=None, error=None, at=NOW) -> dict:
    return {
        "kind": "domain",
        "domain": "example.com",
        "captured_at": at,
        "rdap": rdap,
        "rdap_error": error,
    }


RDAP = {
    "registered": "2026-10-02T12:00:00Z",
    "expires": "2027-10-02T12:00:00Z",
    "last_changed": "2026-10-11T12:00:00.000Z",
    "registrar": "Some Registrar",
    "status": ["client transfer prohibited", "client hold"],
    "nameservers": [],
    "redacted": True,
}


def test_registry_and_dictionary():
    assert GROUPS_C == ("registration", "dns", "tls")
    assert all(f.tier == "C" and not f.in_browser for f in REGISTRY_C)
    assert all(f.availability == "live-feed hosts at first-seen" for f in REGISTRY_C)
    assert set(compute_c(host(), None, LISTS)) == set(NAMES_C)
    assert "## Tier C: domain, DNS and TLS features" in render()


def test_registration_group():
    v = compute_c(host(), domain(RDAP), LISTS)
    assert v["domain_age_days"] == pytest.approx(10.0)
    assert v["days_to_expiry"] == pytest.approx(355.0)
    assert v["registration_length_days"] == pytest.approx(365.0)
    assert v["days_since_rdap_change"] == pytest.approx(1.0)
    assert (v["rdap_found"], v["whois_redacted"]) == (1.0, 1.0)
    assert (v["rdap_status_count"], v["rdap_client_hold"]) == (2.0, 1.0)


def test_registration_missing_is_nan():
    not_found = compute_c(host(), domain(None, "not_found"), LISTS)
    assert not_found["rdap_found"] == 0.0 and math.isnan(not_found["domain_age_days"])
    for rec in (domain(None, "http_429"), None):
        v = compute_c(host(), rec, LISTS)
        assert all(math.isnan(v[f.name]) for f in REGISTRY_C if f.group == "registration")


def test_latest_good_rdap_rule():
    early = domain(RDAP, at="2026-10-10T00:00:00+00:00")
    late_fail = domain(None, "Timeout", at="2026-10-12T00:00:00+00:00")
    assert pick_domain_record([late_fail, early]) is early
    newer = domain(RDAP | {"redacted": False}, at="2026-10-11T00:00:00+00:00")
    assert pick_domain_record([early, newer, late_fail]) is newer
    assert pick_domain_record([late_fail]) is late_fail
    assert pick_domain_record([]) is None


def test_dns_group():
    v = compute_c(host(), None, LISTS)
    assert (v["n_a"], v["n_aaaa"], v["has_cname"]) == (2.0, 0.0, 1.0)
    assert (v["mx_count"], v["has_mx"], v["has_spf"], v["has_dmarc"]) == (2.0, 1.0, 1.0, 0.0)
    assert (v["n_ns"], v["ns_in_own_domain"], v["ns_cloudflare"]) == (2.0, 1.0, 0.0)
    assert v["min_ttl_s"] == 300.0
    dns = host()["dns"] | {"ns": ["ada.ns.cloudflare.com"], "errors": ["MX:TimeoutError"]}
    v = compute_c(host(dns=dns), None, LISTS)
    assert (v["ns_in_own_domain"], v["ns_cloudflare"]) == (0.0, 1.0)
    assert math.isnan(v["mx_count"]) and math.isnan(v["has_mx"]) and v["n_a"] == 2.0
    v = compute_c(host(dns=host()["dns"] | {"ns": []}), None, LISTS)
    assert v["n_ns"] == 0.0 and math.isnan(v["ns_in_own_domain"])


def test_filtered_record_gives_no_dns_or_tls_values():
    dns = host()["dns"] | {"a": ["0.0.0.0"], "aaaa": ["::"], "min_ttl": 60}
    rec = host(dns=dns, tls={"ok": False, "verified": False, "error": "gaierror"})
    v = compute_c(rec, domain(RDAP), LISTS)
    assert all(math.isnan(v[f.name]) for f in REGISTRY_C if f.group in ("dns", "tls"))
    assert v["domain_age_days"] == pytest.approx(10.0)  # registration is not from the resolver
    flags = host_flags(rec, LISTS)
    assert flags["filtered"] and flags["resolves"] is False
    new_style = host(dns=host()["dns"] | {"sinkhole": True, "resolves": False})
    assert host_flags(new_style, LISTS)["filtered"]


def test_tls_group():
    v = compute_c(host(), None, LISTS)
    assert (v["tls_ok"], v["tls_verified"], v["cert_free_issuer"]) == (1.0, 1.0, 1.0)
    assert v["cert_validity_days"] == pytest.approx(90.0)
    assert v["cert_age_days"] == pytest.approx(10.0)
    assert v["cert_days_left"] == pytest.approx(80.0)
    assert (v["cert_san_count"], v["cert_wildcard"], v["cert_cn_matches_host"]) == (2.0, 1.0, 1.0)
    assert v["brand_in_cert_sans"] == 0.0
    paid = host()["tls"] | {"issuer_o": "DigiCert Inc", "issuer_cn": "DigiCert G2"}
    assert compute_c(host(tls=paid), None, LISTS)["cert_free_issuer"] == 0.0


def test_tls_failures_are_nan_not_zero():
    failed = compute_c(
        host(tls={"ok": False, "verified": False, "error": "TimeoutError"}), None, LISTS
    )
    assert failed["tls_ok"] == 0.0 and math.isnan(failed["tls_verified"])
    unverified = compute_c(
        host(tls={"ok": True, "verified": False, "error": "self-signed"}), None, LISTS
    )
    assert unverified["tls_verified"] == 0.0 and math.isnan(unverified["cert_age_days"])
    lookup = compute_c(host(tls={"ok": False, "verified": False, "error": "gaierror"}), None, LISTS)
    assert math.isnan(lookup["tls_ok"])
    assert all(
        math.isnan(v)
        for k, v in compute_c(host(tls=None), None, LISTS).items()
        if k.startswith(("tls_", "cert_", "brand_"))
    )


def test_brand_and_cn_helpers():
    assert brand_in_sans(["paypal-secure.com"], LISTS.brands)
    assert brand_in_sans(["*.paypal.login-check.net"], LISTS.brands)
    assert not brand_in_sans(["www.paypal.com", "paypal.co.uk"], LISTS.brands)  # its own domain
    assert not brand_in_sans(["dhl.com"], LISTS.brands)  # 3 letters: not in the brand set
    assert cn_matches("*.example.com", "a.example.com")
    assert not cn_matches("*.example.com", "a.b.example.com")
    assert not cn_matches("*.example.com", "example.com")
    assert parse_time("2026-10-02T12:00:00.5Z").tzinfo is not None
    assert parse_time("not a date") is None and parse_time(None) is None


def test_platform_and_ip_flags():
    assert host_flags(host(host="a.web.app", domain="web.app"), LISTS)["is_hosting_platform"]
    ip = host(host="192.0.2.7", domain="192.0.2.7", dns=None)
    flags = host_flags(ip, LISTS)
    assert flags["is_ip"] and flags["resolves"] is None and not flags["filtered"]
    v = compute_c(ip, domain(None, "ip_host"), LISTS)
    assert math.isnan(v["rdap_found"]) and math.isnan(v["n_a"])


def test_build_reads_latest_host_record_and_skips_cut_lines(tmp_path, monkeypatch):
    filtered = host(captured_at="2026-10-11T00:00:00+00:00", dns=host()["dns"] | {"a": ["0.0.0.0"]})
    good = host()
    benign = host(host="www.old.org", domain="old.org", label=0)
    lines = [json.dumps(r) for r in (filtered, domain(RDAP), benign)]
    (tmp_path / "2026-10-11.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (tmp_path / "2026-10-12.jsonl").write_text(
        json.dumps(good) + '\n{"kind": "ho', encoding="utf-8"
    )
    monkeypatch.setattr(build_c, "load_lists", lambda: LISTS)
    out, counts = build_c.build_c(tmp_path, tmp_path / "features_c.parquet")
    df = pd.read_parquet(out).set_index("host")
    assert len(df) == 2 and not df.loc["login.example.com", "filtered"]
    assert df.loc["login.example.com", "n_a"] == 2.0
    assert df.loc["login.example.com", "domain_age_days"] == pytest.approx(10.0)
    assert math.isnan(df.loc["www.old.org", "domain_age_days"])  # no domain record
    assert df[list(NAMES_C)].dtypes.eq("float32").all()
    assert counts.loc["1", "hosts"] == 1 and counts.loc["0", "domains"] == 1
    assert counts["filtered_by_pc_resolver"].sum() == 0
