"""Data files for the JavaScript port of the tier A features (``js/``).

python -m features export-js   # js/data/psl_icann.json and js/data/lists.json
python -m features parity      # tests/fixtures/url_parity.json (expected values from Python)

``psl_icann.json`` holds the ICANN public-suffix rules of the installed ``tldextract`` snapshot
(the same rules ``phishdrift.domains.split_host`` uses). Rules with non-ASCII labels are also
written in their punycode form, so the browser needs no IDNA decoder: tldextract decodes
``xn--`` labels before matching, and matching the encoded form gives the same result.

The parity fixture uses small fixed lists (not the scraped ones) and fixed fitted numbers, so
it changes only when a feature definition changes. Both test suites check it: pytest that it
equals what Python computes now, the JS suite that JavaScript computes the same values.
"""

from __future__ import annotations

import itertools
import json
import math
import random
from pathlib import Path

import idna

from features.extract import extract
from features.fit import Fitted, load_fitted
from features.lists import ROOT, Lists, load_lists
from features.registry import NAMES
from phishdrift.domains import _EXTRACT_U1

JS_DATA = ROOT / "js" / "data"
PARITY_FILE = ROOT / "tests" / "fixtures" / "url_parity.json"


def _puny(rule: str) -> str | None:
    out = []
    for label in rule.split("."):
        prefix = "!" if label.startswith("!") else ""
        bare = label[len(prefix) :]
        if bare == "*" or bare.isascii():
            out.append(label)
            continue
        try:
            out.append(prefix + idna.encode(bare).decode("ascii"))
        except idna.IDNAError:
            return None
    return ".".join(out)


def psl_rules() -> list[str]:
    rules = list(_EXTRACT_U1._get_tld_extractor().public_tlds)
    aliases = {a for r in rules if not r.isascii() and (a := _puny(r)) and a != r}
    return sorted(set(rules) | aliases)


def lists_payload(lists: Lists, fitted: Fitted) -> dict:
    return {
        "platforms": sorted(lists.platforms),
        "brands": list(lists.brands),
        "keywords": list(lists.keywords),
        "shorteners": sorted(lists.shorteners),
        "suspicious_tlds": sorted(lists.suspicious_tlds),
        "redirect_params": sorted(lists.redirect_params),
        "fitted": {
            "bigram_logprob": fitted.bigram_logprob,
            "bigram_floor": fitted.bigram_floor,
            "tld_risk": fitted.tld_risk,
            "tld_default": fitted.tld_default,
        },
    }


def export_js(lists: Lists | None = None, fitted: Fitted | None = None) -> list[Path]:
    JS_DATA.mkdir(parents=True, exist_ok=True)
    psl = JS_DATA / "psl_icann.json"
    psl.write_text(json.dumps(psl_rules(), ensure_ascii=False, indent=0), encoding="utf-8")
    payload = lists_payload(lists or load_lists(), fitted or load_fitted())
    out = JS_DATA / "lists.json"
    out.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True), encoding="utf-8")
    return [psl, out]


# --- parity fixture --------------------------------------------------------------------

FIXTURE_LISTS = Lists.build(
    platforms=["github.io", "web.app", "blogspot.com", "pages.dev", "bit.ly"],
    brands=["paypal", "amazon", "hdfcbank", "netflix", "microsoft", "apple", "icici", "sbi"],
    keywords=["login", "verify", "secure", "account", "update", "signin", "bank", "kyc", "upi"],
    shorteners=["bit.ly", "tinyurl.com", "t.co"],
    suspicious_tlds=["xyz", "top", "tk", "zip"],
    redirect_params=["url", "next", "redirect", "goto"],
)
FIXTURE_FITTED = Fitted(
    bigram_logprob={"pa": -3.1, "ay": -4.2, "yp": -5.0, "al": -3.3, "go": -3.7, "oo": -4.4},
    bigram_floor=-9.5,
    tld_risk={"com": 0.21, "xyz": 0.93, "co.uk": 0.08, "in": 0.35, "рф": 0.5},
    tld_default=0.3,
)

HANDWRITTEN = [
    "https://www.example.com/",
    "http://example.com",
    "example.com/path/to/page.html",
    "HTTPS://WWW.EXAMPLE.COM/Index.PHP?ID=5",
    "https://user:pass@example.com:8080/a?b=c#frag",
    "http://192.168.0.1/login.php",
    "http://0x7f000001/admin",
    "http://3232235777/",
    "http://0300.0250.0000.0001/x",
    "http://[2001:db8::1]:8443/path",
    "http://[::ffff:192.0.2.1]/",
    "https://xn--pypal-4ve.com/signin",
    "https://xn--80ak6aa92e.com/",
    "https://пример.рф/вход",
    "https://test.xn--p1ai/login",
    "https://paypa1.com/verify/account",
    "https://paypal-secure-login.xyz/update",
    "https://secure-paypal.com/",
    "https://my-paypal-help.top/kyc",
    "https://rnicrosoft.com/login",
    "https://arnazon.co.uk/orders",
    "https://amaz0n.in/account?next=https://amazon.in",
    "https://hdfcbank.com/",
    "https://hdfcbank.netbanking-verify.com/upi",
    "https://login.microsoftonline.com.evil.tk/common/oauth2",
    "https://www.icici.example.org/",
    "https://appleid.apple.com.verify-id.xyz/",
    "https://netflix.com/browse",
    "https://n3tflix-billing.com/update-payment",
    "https://some-user.github.io/project/index.html",
    "https://github.io/",
    "https://my-app.web.app/login",
    "https://foo.bar.blogspot.com/2024/01/post.html",
    "https://bit.ly/3xYzAbC",
    "https://tinyurl.com/abc123",
    "https://t.co/xyz",
    "https://example.com/redirect?url=http%3A%2F%2Fevil.com",
    "https://example.com/r?goto=https%253A%252F%252Fevil.com",
    "https://example.com/contact?email=john.doe@example.org",
    "https://example.com/a//b///c",
    "https://example.com/http/www/com",
    "https://www.www.example.com/",
    "https://a.b.c.d.e.example.com/",
    "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com/",
    "https://example.com/%7Euser/%41%42%43",
    "https://example.com/path;param?x=1&y=2&z=3&&",
    "https://example.com/?",
    "https://example.com/#onlyfragment",
    "https://example.co.uk/shop",
    "https://foo.ck/",
    "https://www.ck/",
    "https://a.foo.kawasaki.jp/",
    "https://city.kawasaki.jp/",
    "http://localhost:3000/",
    "http://intranet/",
    "https://example.com.",
    "https://example.com:443/",
    "https://example.com:80/",
    "https://example.com:abc/",
    "https://ex_ample.com/",
    "https://xn--e1afmkfd.xn--p1ai/",
    "https://bücher.de/katalog",
    "https://example.com/über/straße",
    "https://example.com/😀/emoji",
    "https://example.com/download.exe",
    "https://example.com/file.tar.gz",
    "https://example.com/script.cgi?cmd=1",
    "https://example.com/page.shtml",
    "https://example.com/a.verylongext",
    "https://example.zip/",
    "https://sub.example.zip/doc.zip",
    "https://1-2-3.example.com/",
    "https://a1b2c3d4.com/",
    "https://bcdfghjklmnpqrstvwxz.com/",
    "https://xn--.com/",
    "http://-.com/",
    "http:///nohost",
    "",
    "   https://example.com/space   ",
    "https://example.com/a b c",
    "https://example.com/~tilde+plus*star$dollar|pipe,comma",
    "https://example.com/@at",
    "mailto:someone@example.com",
    "ftp://files.example.com/pub",
    "javascript:alert(1)",
    "https://WWW.PayPal.COM/US/",
    "https://www.paypal.com.secure-login.example/",
    "https://paypal.com-account-verify.info/",
    "https://www-paypal.com/",
    "https://apple.com-icloud.support/",
    "https://sbi.co.in/",
    "https://onlinesbi.sbi/",
    "https://icici-bank-kyc-update.in/kyc",
    "https://login.example.com/signin/verify/account/update",
]


def _generated(n: int, seed: int = 7) -> list[str]:
    rng = random.Random(seed)
    schemes = ["http://", "https://", ""]
    subs = ["", "www.", "login.", "secure.account.", "m.", "a1.", "xn--80aswg.", "cdn-01."]
    labels = ["example", "paypal", "paypa1", "my-bank", "shop24", "news", "gooogle", "x7k2qz"]
    suffixes = ["com", "co.uk", "xyz", "in", "org", "github.io", "web.app", "top", "de"]
    paths = ["", "/", "/index.html", "/login", "/a/b/c/d/e", "/wp-admin/x.php", "/%20space"]
    queries = ["", "?id=1", "?next=/home", "?url=http://x.com", "?a=1&b=2&c=", "?q=%7E%41"]
    out = []
    combos = list(itertools.product(schemes, subs, labels, suffixes, paths, queries))
    for scheme, sub, label, suffix, path, query in combos:
        if rng.random() < n / len(combos):  # keep about n of them
            out.append(f"{scheme}{sub}{label}.{suffix}{path}{query}")
    return out


def parity_cases() -> list[str]:
    return HANDWRITTEN + _generated(160)


def _clean(v: float) -> float | None:
    return None if math.isnan(v) else v


def parity_fixture() -> dict:
    cases = []
    for url in parity_cases():
        feats = extract(url, lists=FIXTURE_LISTS, fitted=FIXTURE_FITTED)
        cases.append({"url": url, "values": [_clean(feats[k]) for k in NAMES]})
    return {
        "note": "Generated by `python -m features parity`. Do not edit by hand.",
        "names": list(NAMES),
        "lists": lists_payload(FIXTURE_LISTS, FIXTURE_FITTED),
        "cases": cases,
    }


def write_parity(path: Path = PARITY_FILE) -> Path:
    """One case per line, so a changed feature shows up as a readable diff."""
    data = parity_fixture()

    def dump(x) -> str:
        return json.dumps(x, ensure_ascii=False, sort_keys=True)

    lines = ["{"]
    lines += [f' "{k}": {dump(data[k])},' for k in ("note", "names", "lists")]
    lines.append(' "cases": [')
    lines.append(",\n".join(f"  {dump(c)}" for c in data["cases"]))
    lines += [" ]", "}", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
    return path
