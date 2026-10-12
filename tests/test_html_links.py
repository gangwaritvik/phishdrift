"""Tier B links group."""

import pytest

from tests.html_helpers import feats, isnan, page


def test_link_kinds_and_ratios():
    body = (
        '<a href="/about">About</a>'
        '<a href="contact.html">Contact</a>'
        '<a href="https://www.example.com/x">Same</a>'
        '<a href="https://shop.example.com/y">Subdomain</a>'
        '<a href="https://other.org/z">Other</a>'
        '<a href="//cdn.third.net/w">Protocol relative</a>'
        '<a href="#">Top</a>'
        '<a href="">Empty</a>'
        '<a href="javascript:void(0)">Script</a>'
        '<a href="mailto:me@example.com">Mail</a>'
        "<a>No href</a>"
    )
    f = feats(page(body))
    assert f["n_links"] == 10  # the anchor without href is not a link
    assert f["link_internal_ratio"] == pytest.approx(0.4)  # 4 of 10
    assert f["link_external_ratio"] == pytest.approx(0.2)
    assert f["link_null_ratio"] == pytest.approx(0.3)  # '#', '' and javascript:
    assert f["n_external_link_domains"] == 2


def test_no_links_gives_nan_ratios_not_zero():
    f = feats(page())
    assert f["n_links"] == 0
    for name in ("link_internal_ratio", "link_external_ratio", "link_null_ratio"):
        assert isnan(f[name])
    assert f["n_external_link_domains"] == 0


def test_anchor_text_that_names_another_domain():
    body = (
        '<a href="https://evil.test/login">www.paypal.com</a>'  # mismatch
        '<a href="https://www.paypal.com/help">https://paypal.com/help</a>'  # same domain
        '<a href="/home">www.paypal.com</a>'  # claims paypal, points at this site: mismatch
        '<a href="https://evil.test/a">Click here</a>'  # text is not a domain
        '<a href="index.html">index.html</a>'  # a file name is not a domain
        '<a href="https://evil.test/b"><b>shop.example.com</b></a>'  # mismatch, text in a child tag
    )
    assert feats(page(body))["n_anchor_text_mismatch"] == 3


def test_link_hosts_and_schemes():
    body = (
        '<a href="http://insecure.org/a">a</a>'
        '<a href="http://192.168.4.4/login">ip</a>'
        '<a href="https://[2001:db8::1]/x">v6</a>'
        '<a href="https://bit.ly/abc">short</a>'
        '<a href="https://www.bit.ly/abc">short www</a>'
        '<a href="https://notbit.ly.example.org/abc">not a shortener</a>'
    )
    f = feats(page(body))
    assert f["n_links_insecure_http"] == 2
    assert f["n_links_ip_host"] == 2
    assert f["n_links_shortener"] == 2


def test_social_links_are_counted_in_the_text_group():
    body = (
        '<a href="https://www.facebook.com/shop">f</a>'
        '<a href="https://twitter.com/shop">t</a>'
        '<a href="https://notfacebook.com/x">n</a>'
    )
    assert feats(page(body))["n_social_links"] == 2


def test_base_href():
    assert feats(page(head='<base href="https://evil.test/">'))["has_base_external"] == 1
    assert feats(page(head='<base href="/app/">'))["has_base_external"] == 0
    assert feats(page())["has_base_external"] == 0


def test_urls_in_meta_script_and_link_tags():
    head = (
        '<meta property="og:url" content="https://www.example.com/">'
        '<meta property="og:image" content="https://img.other.net/a.png">'
        '<meta name="description" content="not a url">'
        '<script src="/a.js"></script>'
        '<link rel="stylesheet" href="https://fonts.other.net/css">'
    )
    # internal: og:url, /a.js; external: og:image, the stylesheet
    assert feats(page(head=head))["meta_script_link_internal_ratio"] == pytest.approx(0.5)
    assert isnan(feats(page())["meta_script_link_internal_ratio"])


def test_platform_pages_compare_masked_domains():
    body = '<a href="https://other.web.app/x">a</a><a href="https://google.com/">g</a>'
    f = feats(page(body), url="https://victim.github.io/")
    assert f["link_internal_ratio"] == pytest.approx(0.5)  # another platform site = same token
    assert f["link_external_ratio"] == pytest.approx(0.5)


def test_malformed_anchors_do_not_break_counting():
    body = (
        '<a href="/a">one <a href="/b">two <a href="https://x.org/">three</a></a></a><a href="/c">'
    )
    f = feats(page(body))
    assert f["n_links"] == 4
