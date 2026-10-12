"""Tier B scripts group."""

import random
import string

import pytest

from tests.html_helpers import feats, isnan, page


def script(code: str, attrs: str = "") -> str:
    return f"<script{attrs}>{code}</script>"


def test_obfuscation_calls():
    code = (
        "var a = atob('aGk='); var b = unescape('%41'); eval(a); new Function('x');"
        "document.write('x'); document.writeln('y'); String.fromCharCode(65, 66);"
        "var c = String.fromCharCode(1); atob ('x');"
    )
    f = feats(page(script(code)))
    assert f["n_atob"] == 2 and f["n_unescape"] == 1
    assert f["n_eval"] == 2  # eval( and new Function(
    assert f["n_document_write"] == 2
    assert f["n_fromcharcode"] == 2


def test_inline_handlers_count_like_scripts():
    f = feats(page("<body onload=\"eval(atob('eA=='))\">"))
    assert f["n_eval"] == 1 and f["n_atob"] == 1


def test_inline_script_counts_and_ratio():
    html = page(script("var a = 1;") + script("   ") + script("var b = 2;"))
    f = feats(html)
    assert f["n_scripts_inline"] == 2  # the blank script does not count
    assert f["script_chars_ratio"] == pytest.approx(20 / len(html))


def test_external_json_and_template_scripts_are_not_inline_javascript():
    body = (
        '<script src="/a.js">eval(1)</script>'
        '<script type="application/ld+json">{"eval(": "x"}</script>'
        '<script type="text/template">eval(2)</script>'
        '<script type="module">import x from "/m.js";</script>'
        '<script type="text/javascript">var ok = 1;</script>'
    )
    f = feats(page(body))
    assert f["n_scripts_inline"] == 2 and f["n_eval"] == 0
    assert f["n_script_src"] == 1


def test_script_text_is_not_visible_text():
    plain = feats(page())["visible_text_len"]
    assert (
        feats(page(script("a" * 1000) + '<script src="/x.js">hidden words</script>'))[
            "visible_text_len"
        ]
        == plain
    )


def test_entropy_and_escapes():
    quiet = feats(page(script("var a = 1;")))
    assert isnan(quiet["script_entropy"])  # under 100 characters of script
    assert quiet["script_escape_ratio"] == 0
    rng = random.Random(0)
    noise = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(2000))
    plain = "var total = 0; for (var i = 0; i < 10; i++) { total += i; }\n" * 30
    assert (
        feats(page(script(noise)))["script_entropy"] > feats(page(script(plain)))["script_entropy"]
    )
    code = "var s = '" + r"\x41\x42\u0043" + "';" + " " * 100  # 14 of 125 characters are escapes
    assert feats(page(script(code)))["script_escape_ratio"] == pytest.approx(14 / 125)
    assert isnan(feats(page())["script_escape_ratio"])


def test_ajax_and_exfiltration_endpoints():
    code = (
        "fetch('https://api.telegram.org/bot123:ABC/sendMessage?chat_id=1');"
        "var x = new XMLHttpRequest(); $.post('/a'); navigator.sendBeacon('/b');"
        "fetch('https://discord.com/api/webhooks/1/abc'); fetch('https://webhook.site/uuid');"
    )
    f = feats(page(script(code)))
    assert f["n_ajax_calls"] == 6  # three fetch calls, XHR, $.post, sendBeacon
    assert f["n_telegram_endpoints"] == 1
    assert f["n_webhook_endpoints"] == 2
    # A form that posts to a relay counts even though no script is involved.
    form = '<form action="https://formspree.io/f/abc"><input name="q"></form>'
    assert feats(page(form))["n_webhook_endpoints"] == 1
    assert feats(page())["n_telegram_endpoints"] == 0
