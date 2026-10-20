"""Browser payload and Python-JS parity fixture for the brand and look-alike rules.

python -m features export-rules   # js/data/brand_rules.json from configs/lists + brand_rules.yaml
python -m features parity         # also writes tests/fixtures/brand_rules_parity.json

The fixture uses a small fixed brand list and domain map (not the scraped ones) with the real
confusables table, so it does not change when the lists are rebuilt.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from features.brand_rules import (
    BrandRules,
    catcher_score,
    load_config,
    load_rules,
    read_confusables,
    rules_payload,
)
from features.fit import Fitted
from features.html_features import analyze
from features.js_export import FIXTURE_LISTS, JS_DATA, lists_payload
from features.lists import ROOT

FIXTURE = ROOT / "tests" / "fixtures" / "brand_rules_parity.json"

FIXTURE_BRANDS = [
    "paypal", "apple", "microsoft", "outlook", "office365", "google", "amazon", "netflix",
    "onlinesbi", "hdfcbank", "icicibank", "chase", "wellsfargo", "facebook", "instagram",
    "whatsapp", "coinbase", "binance", "metamask", "dropbox", "docusign", "linkedin", "adobe",
    "steam", "airtel", "paytm", "phonepe", "flipkart", "irctc", "dhl", "fedex", "visa",
]  # fmt: skip
FIXTURE_DOMAINS = {
    "microsoft": ["microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com",
                  "office365.com", "linkedin.com", "1drv.ms"],
    "outlook": ["microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com"],
    "office365": ["microsoft.com", "microsoftonline.com", "office.com", "office365.com"],
    "linkedin": ["linkedin.com", "microsoft.com"],
    "google": ["google.com", "google.co.in", "youtube.com", "gmail.com", "blogger.com"],
    "paypal": ["paypal.com", "paypal.me", "paypalobjects.com"],
    "apple": ["apple.com", "icloud.com"],
    "onlinesbi": ["onlinesbi.sbi", "sbi.co.in"],
    "facebook": ["facebook.com", "fb.com", "messenger.com"],
}  # fmt: skip
FIXTURE_LURES = [
    "account", "confirm", "kyc", "login", "otp", "password", "recover", "secure", "security",
    "signin", "update", "verify", "verification", "unlock", "webscr",
]  # fmt: skip

URLS = [
    # homographs and punycode
    "https://xn--pple-43d.com/login", "https://xn--80ak6aa92e.com", "http://xn--paypl-7ve.com/",
    "https://xn--micrsoft-qbh.com", "https://xn--gogle-0nd.com/signin", "https://xn--e1awd7f.com",
    "https://paypa1.com", "https://paypal1.com", "https://rnicrosoft.com/", "https://micr0soft.com",
    "https://g00gle.com", "https://app1e.com", "https://amaz0n.co.in", "https://netf1ix.com",
    "https://faceb00k.com/login", "https://c0inbase.com", "https://vvellsfargo.com",
    "https://xn--bnance-bwa.com", "https://xn--", "https://xn--zz.com", "https://xn--a-ecp.com",
    "https://аpple.com/", "https://pаypal.com", "https://ｐaypal.com", "https://ⓟaypal.com",
    # edit distance 1
    "https://paypai.com", "https://paypa.com", "https://payppal.com", "https://pyapal.com",
    "https://amazom.com", "https://amazn.com", "https://netflx.com", "https://facebok.com",
    "https://instagran.com", "https://whatsap.com", "https://linkedln.com", "https://dropbx.com",
    "https://coinbsae.com", "https://onlinesb1.co.in", "https://hdfcbnak.com", "https://steam.com",
    "https://stream.com", "https://chase.com", "https://chasse.com", "https://adobe.com",
    "https://abode.com", "https://applee.com", "https://googel.com", "https://micosoft.com",
    # embedded real domains
    "https://paypal.com-secure.xyz/login", "https://paypal-com.evil.net/x", "http://www.paypal.com.evil.ru",
    "https://login.microsoftonline.com.attacker.top/", "https://apple.com.verify-id.info",
    "https://secure-google-com.web.app", "https://sbi.co.in.kyc-update.in", "https://amazon.co.uk.order.cc",
    "https://www-paypal-com.translate.goog/", "https://facebook.com.au.example.org",
    "https://mail.google.com", "https://accounts.google.co.in/signin", "https://paypal.com.au",
    "https://netflix.com.br", "https://my.chase.com.secure.co", "https://a.b.c.d.paypal.com.x.y.z.top",
    # combos
    "https://onlinesbi-kyc.co.in", "https://paypalsecure.com", "https://paypal-secure-login.com",
    "https://amazon-verify-account.top", "https://appleid-verify.com", "https://applebees.com",
    "https://amazonaws.com", "https://netflix-update.net", "https://securepaypal.net",
    "https://hdfcbank-kyc.in", "https://hdfcbankkyc.in", "https://metamask-wallet.io",
    "https://metamasklogin.io", "https://coinbase-pro.com", "https://binance-support.com",
    "https://whatsapp-web.net", "https://chase-online.com", "https://chaseonline.com",
    "https://flipkart-offer.in", "https://irctc-login.co.in", "https://paytm-kyc.in",
    "https://paypal-login.web.app/", "https://netflix-update.github.io", "https://amazon.github.io",
    "https://paypal-security.pages.dev/x", "https://dropbox-login.blogspot.com",
    # legitimate and neutral
    "https://www.paypal.com", "https://paypal.de", "https://login.microsoftonline.com/common",
    "https://outlook.live.com/mail", "https://web.whatsapp.com", "https://www.google.com/search?q=x",
    "https://onlinesbi.sbi", "https://www.sbi.co.in", "https://hdfcbank.com", "https://modern.com",
    "https://example.com", "https://www.bbc.co.uk/news", "https://github.com/login",
    "https://en.wikipedia.org/wiki/PayPal", "https://news.ycombinator.com", "https://docs.python.org/3/",
    "https://www.irctc.co.in/nget/train-search", "https://paytm.com", "https://shop.example.in/cart",
    "https://my-bank.co.in/login", "https://secure.login.example.org", "https://192.168.1.1/login",
    "http://[2001:db8::1]/paypal", "https://localhost/", "not a url", "", "https://",
    "https://xn--80aswg.xn--p1ai/", "https://москва.рф", "https://bücher.de", "https://straße.de",
    "https://paypal", "https://paypal.com.", "HTTPS://PAYPAL.COM-SECURE.XYZ", "https://user@paypal.com.evil.io",
    "https://evil.io/paypal.com/login", "https://evil.io/?u=https://paypal.com",
    "https://appleid.apple.com/sign-in", "https://icloud.com", "https://apple-icloud.com",
    "https://ıcloud.com", "https://faceboook.com", "https://instagram.com.login.co",
    "https://docusign-review.net", "https://adobe-sign.com", "https://dhl-tracking.info",
    "https://fedex-delivery.top", "https://visa-secure.com", "https://airtel-kyc.in",
    "https://phonepe-reward.in", "https://flipkart.com", "https://flipcart.com", "https://fl1pkart.com",
]  # fmt: skip

PAGE = """<html><head><title>{title}</title>{meta}</head><body>
<h1>{h1}</h1><p>{body}</p>{form}<footer>{footer}</footer></body></html>"""
FILLER = "Welcome to our service. Read the help pages and the terms before you continue. " * 4
PASSWORD_FORM = '<form action="/s"><input name="u"><input type="password" name="p"></form>'
OTP_FORM = '<form><input name="otp" placeholder="Enter OTP"></form>'
CARD_FORM = '<form><input name="cardnumber"><input name="cvv"></form>'

PAGES = [
    ("https://paypal-login.web.app/", "Log in to your PayPal account", "", PASSWORD_FORM, ""),
    ("https://www.paypal.com/signin", "Log in to your PayPal account", "", PASSWORD_FORM, ""),
    ("https://paypal.de/signin", "PayPal Login", "", PASSWORD_FORM, ""),
    ("https://login.microsoftonline.com/", "Sign in to your Microsoft account", "", PASSWORD_FORM, ""),  # noqa: E501
    ("https://outlook.live.com/", "Outlook", "", PASSWORD_FORM, "© Microsoft 2026"),
    ("https://evil.top/o365", "Sign in to your account", '<meta property="og:site_name" content="Microsoft Office 365">', PASSWORD_FORM, ""),  # noqa: E501
    ("https://evil.top/sbi", "Login", "", OTP_FORM, "Copyright © 2026 OnlineSBI, State Bank of India"),  # noqa: E501
    ("https://evil.top/news", "Apple unveils new phone", "", "", "© 2026 Daily News"),
    ("https://shop.example.com/login", "Sign in", "", PASSWORD_FORM, "Sign in with Google or Facebook"),  # noqa: E501
    ("https://shop.example.com/pay", "Checkout - Amazon Pay", "", CARD_FORM, ""),
    ("https://shop.example.com/login2", "Example Shop", '<meta property="og:site_name" content="Example Shop">', PASSWORD_FORM, "© Example Shop, powered by Google Cloud"),  # noqa: E501
    ("http://10.0.0.5/netflix", "Netflix", "", PASSWORD_FORM, ""),
    ("https://hdfcbank.com/netbanking", "HDFC Bank NetBanking", "", PASSWORD_FORM, "© HDFC Bank"),
    ("https://hdfc-netbank.in/", "HDFCBank NetBanking Login", "", PASSWORD_FORM, ""),
    ("https://accounts.google.com/", "Sign in - Google Accounts", "", PASSWORD_FORM, ""),
    ("https://sites.google.com/view/x", "Microsoft Outlook Web Access", "", PASSWORD_FORM, ""),
    ("https://evil.top/short", "Netflix", "", PASSWORD_FORM, "x"),
    ("https://evil.top/nocred", "Netflix", "", "", "© Netflix"),
]  # fmt: skip


def fixture_rules() -> BrandRules:
    return BrandRules.build(
        skeleton_map=read_confusables(),
        brand_domains=FIXTURE_DOMAINS,
        brands=FIXTURE_BRANDS,
        lures=FIXTURE_LURES,
        min_edit_len=6,
        min_combo_len=5,
        platforms=FIXTURE_LISTS.platforms,
    )


def page_html(title: str, meta: str, form: str, footer: str, short: bool = False) -> str:
    body = "" if short else FILLER
    return PAGE.format(title=title, meta=meta, h1=title, body=body, form=form, footer=footer)


def page_cases(rules: BrandRules) -> list[dict]:
    out = []
    for url, title, meta, form, footer in PAGES:
        html = page_html(title, meta, form, footer, short=footer == "x")
        facts: dict = {}
        _, status = analyze(
            url, html, lists=FIXTURE_LISTS, facts=facts, fact_brands=frozenset(rules.brands)
        )
        out.append(
            {"url": url, "html": html, "status": status, "facts": facts,
             "signal": rules.page_signal(url, facts)}
        )  # fmt: skip
    return out


def _num(x: float) -> float | None:
    return None if math.isnan(x) else x


def write_parity() -> Path:
    rules = fixture_rules()
    cfg = load_config()
    payload = rules_payload(rules, cfg)
    cases = [
        {"url": u, "signals": rules.address_signals(u), "catcher": _num(catcher_score(u, rules, cfg["catcher"], FIXTURE_LISTS.suspicious_tlds))}  # noqa: E501
        for u in URLS
    ]  # fmt: skip
    data = {
        "note": "Written by `python -m features parity` (features/brand_parity.py). Do not edit.",
        "rules": payload,
        "lists": lists_payload(FIXTURE_LISTS, Fitted()),
        "cases": cases,
        "pages": page_cases(rules),
    }
    FIXTURE.write_text(
        json.dumps(data, ensure_ascii=False, indent=0, sort_keys=True) + "\n", "utf-8"
    )
    return FIXTURE


def export_rules() -> Path:
    out = JS_DATA / "brand_rules.json"
    payload = rules_payload(load_rules(), load_config())
    out.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return out
