"""Tier B resources group."""

import pytest

from tests.html_helpers import feats, isnan, page


def test_external_ratios_by_resource_type():
    head = (
        '<script src="/local.js"></script>'
        '<script src="https://cdn.other.net/lib.js"></script>'
        '<script src="//cdn.other.net/two.js"></script>'
        '<link rel="stylesheet" href="style.css">'
        '<link rel="stylesheet" href="https://fonts.other.net/f.css">'
    )
    body = (
        '<img src="/logo.png"><img src="https://img.other.net/a.png">'
        '<img src="https://www.example.com/b.png"><img data-src="https://lazy.other.net/c.png">'
    )
    f = feats(page(body, head))
    assert f["n_script_src"] == 3 and f["script_external_ratio"] == pytest.approx(2 / 3)
    assert f["css_external_ratio"] == pytest.approx(0.5)
    assert f["n_img"] == 4 and f["img_external_ratio"] == pytest.approx(0.5)


def test_no_resources_gives_nan():
    f = feats(page())
    assert f["n_script_src"] == 0 and f["n_img"] == 0
    for name in ("script_external_ratio", "css_external_ratio", "img_external_ratio"):
        assert isnan(f[name])
    assert isnan(f["resource_external_ratio"]) and f["n_external_resource_domains"] == 0


def test_data_uri_images_are_counted_but_not_external():
    body = '<img src="data:image/png;base64,AAAA"><img src="DATA:image/gif;base64,BBBB">'
    f = feats(page(body))
    assert f["n_img"] == 2 and f["n_img_data_uri"] == 2
    assert isnan(f["img_external_ratio"])  # nothing with a URL to compare


def test_favicon():
    assert feats(page())["has_favicon"] == 0
    assert isnan(feats(page())["favicon_external"])
    own = feats(page(head='<link rel="icon" href="/favicon.ico">'))
    assert own["has_favicon"] == 1 and own["favicon_external"] == 0
    other = feats(page(head='<link rel="shortcut icon" href="https://brand.example.org/f.ico">'))
    assert other["has_favicon"] == 1 and other["favicon_external"] == 1
    assert feats(page(head='<link rel="apple-touch-icon" href="/a.png">'))["has_favicon"] == 1


def test_all_resources_together():
    head = '<script src="https://a.net/x.js"></script><link rel="stylesheet" href="/s.css">'
    body = (
        '<img src="https://b.net/i.png"><iframe src="https://c.net/f"></iframe>'
        '<video src="/v.mp4"></video><audio src="https://b.net/s.mp3"></audio>'
    )
    f = feats(page(body, head))
    # external: script a.net, img b.net, iframe c.net, audio b.net; internal: css, video
    assert f["resource_external_ratio"] == pytest.approx(4 / 6)
    assert f["n_external_resource_domains"] == 3


def test_platform_hosted_resources_are_masked():
    body = '<img src="https://other.web.app/a.png"><img src="https://img.other.net/a.png">'
    f = feats(page(body), url="https://victim.github.io/")
    assert f["img_external_ratio"] == pytest.approx(0.5)
