"""Brand and look-alike rules (features/brand_rules.py) and the brand map builder."""

from __future__ import annotations

import json
import math

import pytest

from features.brand_domains import build_map, confusables_map, families_from_misp
from features.brand_parity import FIXTURE, URLS, fixture_rules, page_cases, page_html
from features.brand_rules import (
    catcher_score,
    load_config,
    page_claims,
    punycode_decode,
    within_one,
)
from features.html_features import analyze
from features.js_export import FIXTURE_LISTS


@pytest.fixture(scope="module")
def rules():
    return fixture_rules()


def rule_of(rules, url):
    hits = rules.address_signals(url)
    return hits[0]["rule"] if hits else None


def test_punycode_decode():
    assert punycode_decode("pple-43d") == "аpple"  # Cyrillic а
    assert punycode_decode("80ak6aa92e") == "аррӏе"
    assert punycode_decode("zz!") is None


def test_within_one():
    assert within_one("paypai", "paypal")  # substitution
    assert within_one("pyapal", "paypal")  # transposition
    assert within_one("paypa", "paypal") and within_one("payppal", "paypal")
    assert not within_one("paypal", "paypal")
    assert not within_one("pypl", "paypal")


def test_skeleton(rules):
    assert rules.skeleton("аpple") == "apple"
    assert rules.skeleton("micr0soft") == "microsoft"
    assert rules.skeleton("rnicrosoft") == "microsoft"
    assert rules.skeleton("vvellsfargo") == "wellsfargo"


@pytest.mark.parametrize(
    ("url", "rule"),
    [
        ("https://xn--pple-43d.com/login", "homograph"),
        ("https://paypa1.com", "homograph"),
        ("https://micr0soft.com", "homograph"),
        ("https://paypal.com-secure.xyz/login", "embedded"),
        ("https://login.microsoftonline.com.attacker.top/", "embedded"),
        ("https://paypai.com", "edit1"),
        ("https://onlinesbi-kyc.co.in", "combo"),
        ("https://paypal-login.web.app/", "combo"),
        ("https://hdfcbankkyc.in", "combo"),
    ],
)
def test_address_rules_fire(rules, url, rule):
    assert rule_of(rules, url) == rule


@pytest.mark.parametrize(
    "url",
    [
        "https://www.paypal.com",
        "https://paypal.de",  # brand label on another suffix is its own
        "https://login.microsoftonline.com/common",  # in Microsoft's family
        "https://outlook.live.com/mail",
        "https://www.sbi.co.in",
        "https://applebees.com",  # remainder is not a lure word
        "https://amazonaws.com",
        "https://stream.com",  # edit1 needs the same first letter
        "https://192.168.1.1/login",
        "https://evil.io/paypal.com/login",  # a path is not an embedded host
        "not a url",
        "",
    ],
)
def test_address_rules_silent(rules, url):
    assert rules.address_signals(url) == []


def test_hyphenated_own_name(rules):
    # a hyphen-stripped label that is a brand is the brand's own site (deutsche-bank.de)
    assert fixture_rules().address_signals("https://hdfc-bank.com") == []


def _facts(url, title, meta="", form="", footer=""):
    facts: dict = {}
    analyze(url, page_html(title, meta, form, footer), lists=FIXTURE_LISTS, facts=facts,
            fact_brands=frozenset(fixture_rules().brands))  # fmt: skip
    return facts


PASSWORD = '<form><input type="password" name="p"></form>'


def test_page_signal(rules):
    f = _facts("https://evil.top/o", "Sign in to your PayPal account", form=PASSWORD)
    assert rules.page_signal("https://evil.top/o", f)["brand"] == "paypal"
    own = _facts(
        "https://login.microsoftonline.com/", "Sign in to your Microsoft account", form=PASSWORD
    )
    assert rules.page_signal("https://login.microsoftonline.com/", own) is None
    nocred = _facts("https://evil.top/n", "Sign in to your PayPal account")
    assert rules.page_signal("https://evil.top/n", nocred) is None
    # a site that names itself vetoes a brand in the title; "powered by Google" is not the owner
    shop = _facts(
        "https://shop.example.com/l", "Example Shop",
        '<meta property="og:site_name" content="Example Shop">', PASSWORD, "© Example Shop, powered by Google",  # noqa: E501
    )  # fmt: skip
    assert page_claims(shop) == [] and rules.page_signal("https://shop.example.com/l", shop) is None
    news = _facts("https://news.example/a", "Apple unveils new phone", form=PASSWORD)
    assert rules.page_signal("https://news.example/a", news) is None  # no login word in the title


def test_page_facts_do_not_change_features():
    html = page_html("Log in to your PayPal account", "", PASSWORD, "© PayPal")
    plain, s1 = analyze("https://evil.top/x", html, lists=FIXTURE_LISTS)
    facts: dict = {}
    with_facts, s2 = analyze(
        "https://evil.top/x",
        html,
        lists=FIXTURE_LISTS,
        facts=facts,
        fact_brands=frozenset({"paypal"}),
    )
    assert s1 == s2 and facts["password_fields"] == 1
    assert plain.keys() == with_facts.keys()
    for k in plain:
        a, b = plain[k], with_facts[k]
        assert (math.isnan(a) and math.isnan(b)) or a == b, k


def test_catcher_score(rules):
    cfg = load_config()["catcher"]
    plain = catcher_score("https://example.com", rules, cfg)
    lured = catcher_score("https://paypal-secure-login-verify.example.top", rules, cfg)
    assert lured > plain + 50


def test_build_map_families():
    fams = families_from_misp(
        {"microsoft": ["microsoft.com", "microsoftonline.com", "live.com", "*.office.com"]}
    )
    m = build_map(["microsoft", "office", "nike"], fams, platforms=frozenset({"live.com"}))
    assert m["microsoft"] == ["microsoft.com", "microsoftonline.com", "office.com"]
    assert "nike" not in m
    big = [({"google"}, {f"x{i}.com" for i in range(600)} | {"google.com", "google.de"})]
    assert build_map(["google"], big, max_family=500) == {"google": ["google.com", "google.de"]}


def test_confusables_map():
    table = {
        "a": [{"c": "а", "n": "CYRILLIC"}],
        "о": [{"c": "o", "n": "LATIN"}, {"c": "0", "n": "DIGIT"}],
    }
    m = confusables_map(table)
    assert m == {"а": "a", "о": "o"}


def test_parity_fixture_current(rules):
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    assert [c["url"] for c in data["cases"]] == URLS
    for case in data["cases"]:
        assert rules.address_signals(case["url"]) == case["signals"], case["url"]
    for got, want in zip(page_cases(rules), data["pages"], strict=True):
        assert got["signal"] == want["signal"], got["url"]
