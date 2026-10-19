"""Write ``tests/fixtures/list_key_parity.json`` from the Python key functions.

    python -m backend.make_fixture

The JavaScript extension checks the same file, so its ``listUrlKey`` / ``listDomainKey`` /
hash must reproduce every case exactly. Regenerate only when the key definitions change on
purpose, and then update the JS port.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from backend.lists import list_domain_key, list_hash, list_url_expressions, list_url_key
from phishdrift.config import load_config

FIXTURE = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "list_key_parity.json"

URLS = [
    # schemes, www, trailing slash
    "http://example.com",
    "https://example.com/",
    "https://www.example.com/",
    "HTTPS://WWW.EXAMPLE.COM/Path",
    "ftp://files.example.org/pub/",
    "example.com",
    "www.example.com/login",
    "//example.com/x",
    "  https://example.com/a/b/  ",
    "https://www.www.example.com/",
    "https://www2.example.com/",
    "https://wwwexample.com/",
    # paths, queries, fragments
    "https://example.com/a/b/c",
    "https://example.com/a/b/c///",
    "https://example.com/a//b",
    "https://example.com/?q=1",
    "https://example.com?q=1",
    "https://example.com/path/?q=a/b/",
    "https://example.com/path/?q=1&r=2#frag",
    "https://example.com/path#frag?q=1",
    "https://example.com/#",
    "https://example.com/a%20b/C%2Fd",
    "https://example.com/Path/CaseKept?Key=Value",
    "https://example.com/a b/c",
    "https://example.com/?",
    "https://example.com//",
    # userinfo, ports
    "https://user@example.com/",
    "https://user:pass@example.com:8443/x/",
    "https://a@b@example.com/",
    "http://example.com:80/",
    "http://example.com:8080/index.html",
    "https://EXAMPLE.com:443",
    "https://example.com:/x",
    "https://example.com/redirect?to=http://evil.com@good.com/",
    "https://example.com/@user/profile",
    # host case, trailing dots
    "https://Login.Example.COM/Signin",
    "https://example.com./",
    "https://example.com.../a",
    "https://www.example.com.:8080/a/",
    # subdomains
    "https://login.secure.example.com/verify",
    "https://a.b.c.d.example.com/",
    "http://paypal.com.account-verify.example.net/login",
    "https://secure-paypal.com-login.example.xyz/",
    # multi-part and unusual suffixes
    "https://www.example.co.uk/",
    "https://login.secure.paypal.co.uk/x",
    "https://shop.example.com.au/cart",
    "https://example.co.jp/",
    "https://sub.example.com.br/a",
    "https://example.gov.in/services/",
    "https://www.example.ac.in",
    "https://foo.example.ck/",
    "https://www.ck/",
    "https://co.uk/",
    "https://localhost/",
    "http://localhost:3000/app",
    "http://intranet/home",
    # platform hosts
    "https://foo.github.io/",
    "https://foo.github.io/repo/page.html",
    "https://www.bar.web.app/login",
    "https://x.pages.dev/?a=1",
    "https://my-site.blogspot.com/2024/01/post.html",
    "https://abc.firebaseapp.com/",
    "https://github.io/",
    # punycode and IDN
    "https://xn--80ak6aa92e.com/",
    "https://www.xn--bcher-kva.example/page",
    "https://xn--e1afmkfd.xn--p1ai/",
    "https://пример.рф/path",
    "https://Bücher.example/Path",
    "https://münchen.de/",
    "https://BÜCHER.example/Path",
    # IP hosts
    "http://192.168.0.1/login",
    "http://192.168.0.1:8080/a/",
    "https://8.8.8.8/",
    "http://255.255.255.255/x",
    "http://256.1.1.1/x",
    "http://01.2.3.4/x",
    "http://1.2.3/x",
    "http://user@10.0.0.1/",
    "http://[2001:db8::1]/",
    "http://[2001:DB8::1]:8080/path/",
    "https://[::1]/",
    "http://0x7f.0.0.1/",
    "http://2130706433/",
    # odd inputs
    "",
    "   ",
    "https://",
    "https:///path",
    "javascript:alert(1)",
    "mailto:someone@example.com",
    "data:text/html,hello",
    "http://example.com\\@evil.com/",
    "HTTP://EXAMPLE.COM/A?B=C#D",
    "http://a.b/",
    "https://very-long-subdomain-name-with-many-hyphens.sub.example.org/some/long/path/index.php?id=12345&session=abcdef",
    "https://example.com/" + "a" * 120,
    # blocklist expressions: tenants, query tokens, deep hosts, ports, double slashes
    "https://x.web.app/login?token=abc123",
    "https://telegra.ph/Secure-Login-10-15",
    "https://sites.google.com/view/paypal-help/home?authuser=0",
    "https://a.b.c.d.e.f.example.co.uk/1/2/3/4/5?x=1",
    "http://host.example.com:8080/a//b/?q",
    "https://docs.google.com/forms/d/e/1FAIpQLSdXyZ0123456789abcdef/viewform?usp=sf_link",
    "https://192.168.0.1/admin/login.php?a=b",
    "https://xn--pple-43d.com/signin/",
]


def build() -> dict:
    prefix_bytes = load_config("backend")["lists"]["prefix_bytes"]
    cases = []
    for url in URLS:
        url_key, domain_key = list_url_key(url), list_domain_key(url)
        cases.append(
            {
                "url": url,
                "url_key": url_key,
                "domain_key": domain_key,
                "url_hash": list_hash(url_key, prefix_bytes),
                "domain_hash": list_hash(domain_key, prefix_bytes),
                "expressions": list_url_expressions(url),
            }
        )
    return {
        "note": "Generated by `python -m backend.make_fixture`. Do not edit by hand.",
        "prefix_bytes": prefix_bytes,
        "cases": cases,
    }


SYNC_FIXTURE = FIXTURE.with_name("list_sync_fixture.json")


def build_sync() -> dict:
    """Two signed list builds, the delta between them and a signed remote config, for the
    extension's sync tests (``extension/test/listsync.test.js``). Uses a throwaway key made here;
    the signatures differ on every run, so the Python test checks them instead of the bytes."""
    import tempfile

    from backend.lists import (
        _canonical,
        build_lists,
        list_delta,
        make_signing_key,
        sign_body,
        write_lists,
    )

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        public = make_signing_key(tmp / "key.pem", [])
        pem = (tmp / "key.pem").read_bytes()
        cands = [f"site{i}.com" for i in range(300)] + ["google.com", "weebly.com"]
        feed1 = [
            "http://evil1.test/x",
            "https://a.weebly.com/x",
            "https://b.weebly.com/y",
            "https://c.weebly.com/z",
            "https://x.web.app/login?t=1",
        ]
        feed2 = [*feed1[1:], "http://evil2.test/y", "https://site5.com/hacked/page"]
        kw = dict(allow_prefix_bytes=16, sentinel_top_n=50)
        old = build_lists(feed1, cands, frozenset({"web.app"}), 8, **kw)
        new = build_lists(feed2, cands, frozenset({"web.app"}), 8, **kw)
        write_lists(old, tmp / "lists", pem)
        write_lists(new, tmp / "lists", pem)
        manifest = json.loads((tmp / "lists" / "manifest.json").read_text())
        delta = list_delta(tmp / "lists", old["manifest"]["version"])
        config = {
            "list_sync_minutes": 60,
            "never_warn": ["example.org"],
            "notes": "test",
            "thresholds": {
                "address": {"dangerous": 0.99, "suspicious": 0.9},
                "page": {"dangerous": None, "suspicious": None},
            },
            "version": 2,
        }
        body = json.dumps(config, sort_keys=True, separators=(",", ":"))
        config["sha256"] = hashlib.sha256(body.encode()).hexdigest()
        served = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        # served as the backend does: sorted body, then the signature appended last
        config = {**json.loads(served), "signature": sign_body(served, pem)}
    return {
        "note": "Generated by `python -m backend.make_fixture`. Do not edit by hand.",
        "pubkey": public,
        "old": {
            "version": old["manifest"]["version"],
            "blocklist": old["blocklist"],
            "allowlist": old["allowlist"],
        },
        "manifest": manifest,
        "blocklist_text": _canonical(new["blocklist"]).decode("utf-8"),
        "allowlist_text": _canonical(new["allowlist"]).decode("utf-8"),
        "delta": delta,
        "config": config,
    }


def main() -> None:
    FIXTURE.parent.mkdir(parents=True, exist_ok=True)
    FIXTURE.write_text(json.dumps(build(), ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(f"wrote {FIXTURE}")
    SYNC_FIXTURE.write_text(json.dumps(build_sync(), ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {SYNC_FIXTURE}")


if __name__ == "__main__":
    main()
