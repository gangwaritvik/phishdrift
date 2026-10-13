"""Tier B structure group."""

import pytest

from features import html_features
from tests.html_helpers import FILLER, feats, isnan, page


def test_sizes_and_text_ratio():
    html = page()
    f = feats(html)
    assert f["page_size"] == len(html)
    assert f["n_lines"] == 1 and f["longest_line"] == len(html)
    assert f["visible_text_len"] == len(FILLER.strip())  # whitespace collapsed
    assert f["text_to_code_ratio"] == pytest.approx(len(FILLER.strip()) / len(html))
    multi = feats(html.replace("><", ">\n<"))
    assert multi["n_lines"] == html.count("><") + 1
    assert multi["longest_line"] < len(html)


def test_only_the_first_500k_characters_are_parsed():
    head = page()
    big = head.replace("</body></html>", "") + "<p>x</p>" * 100_000 + "</body></html>"
    f = feats(big)
    assert f["page_size"] == len(big) > html_features.MAX_HTML_CHARS
    assert f["n_tags"] < 100_000 * 2  # the tail was never parsed


def test_tag_count_and_depth():
    f = feats(page("<div><div><div><span>deep</span></div></div></div>"))
    assert f["max_dom_depth"] == 6  # html > body > div > div > div > span
    # optional end tags: sibling paragraphs and list items do not stack up
    flat = feats(page("<ul>" + "<li>item" * 50 + "</ul>" + "<p>para" * 50))
    assert flat["max_dom_depth"] <= 4
    assert f["n_tags"] >= 7


def test_iframes():
    body = (
        '<iframe src="https://a.test/x"></iframe>'
        '<iframe src="https://a.test/y" width="0" height="0"></iframe>'
        '<iframe src="https://a.test/z" style="display: none"></iframe>'
        '<iframe src="https://a.test/w" hidden></iframe>'
        '<iframe src="https://a.test/v" width="600px" height="400"></iframe>'
    )
    f = feats(page(body))
    assert f["n_iframes"] == 5 and f["n_hidden_iframes"] == 3


def test_meta_refresh():
    none = feats(page())
    assert none["has_meta_refresh"] == 0 and isnan(none["meta_refresh_external"])
    ext = feats(page(head='<meta http-equiv="refresh" content="0; url=https://evil.test/a">'))
    assert ext["has_meta_refresh"] == 1 and ext["meta_refresh_external"] == 1
    own = feats(page(head='<meta http-equiv="REFRESH" content="5;URL=\'/next\'">'))
    assert own["has_meta_refresh"] == 1 and own["meta_refresh_external"] == 0
    reload = feats(page(head='<meta http-equiv="refresh" content="30">'))
    assert reload["has_meta_refresh"] == 1 and reload["meta_refresh_external"] == 0


def test_right_click_and_mouse_tricks():
    assert feats(page())["right_click_disabled"] == 0
    attr = feats(page().replace("<body>", '<body oncontextmenu="return false">'))
    assert attr["right_click_disabled"] == 1
    script = feats(
        page("<script>document.addEventListener('contextmenu', e => e.preventDefault());</script>")
    )
    assert script["right_click_disabled"] == 1
    assert feats(page("<script>var contextmenu = 1;</script>"))["right_click_disabled"] == 0
    hover = feats(
        page('<a href="/x" onmouseover="window.status=\'x\'">a</a><b onmouseover="y()">b</b>')
    )
    assert hover["n_onmouseover"] == 2


def test_popups_and_redirects():
    js = (
        "<script>window.open('http://a.test'); window.open ('b');"
        "window.location = 'http://evil.test'; location.href='/x'; if (location.href == 'y') {}"
        "window.location.replace('z'); top.location.assign('w');</script>"
        "<button onclick=\"window.open('p')\">x</button>"
    )
    f = feats(page(js))
    assert f["n_window_open"] == 3  # two in the script, one inline handler
    assert f["n_js_redirects"] == 4  # = twice, replace, assign; the == comparison is not counted


def test_viewport_and_robots():
    f = feats(page(head='<meta name="viewport" content="width=device-width">'))
    assert f["has_viewport_meta"] == 1 and f["robots_noindex"] == 0
    g = feats(page(head='<meta name="robots" content="noindex, nofollow">'))
    assert g["robots_noindex"] == 1 and g["has_viewport_meta"] == 0
    assert feats(page(head='<meta name="robots" content="index,follow">'))["robots_noindex"] == 0
