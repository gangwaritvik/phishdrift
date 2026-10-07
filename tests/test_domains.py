import pytest

from phishdrift.domains import (
    hostname,
    normalize_to_registrable,
    normalize_url,
    registered_domain,
    registered_domain_private,
    url_depth,
    url_key,
)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://www.google.com/search?q=x", "google.com"),
        ("https://login.secure.paypal.co.uk/x", "paypal.co.uk"),
        ("http://netbanking.hdfcbank.com", "hdfcbank.com"),
        ("https://onlinesbi.sbi.co.in/", "sbi.co.in"),
        ("paytm.com/login", "paytm.com"),  # missing scheme
        ("HTTPS://WWW.Amazon.IN:443/ap/signin", "amazon.in"),
        ("https://paypal.com.secure-verify.xyz/", "secure-verify.xyz"),  # brand in subdomain
        ("https://my-site.github.io/login", "github.io"),  # U1: platform is one group
        ("https://evil.blogspot.com/", "blogspot.com"),
        ("https://a.web.app/x", "web.app"),
        ("http://192.0.2.10/bank/update.php", "192.0.2.10"),
        ("http://[2001:db8::1]:8080/x", "2001:db8::1"),
        ("https://xn--pypal-4ve.com/", "xn--pypal-4ve.com"),  # punycode stays as-is
        ("http://user:pw@evil.com/x", "evil.com"),  # userinfo trick
        ("http://localhost:8000/", "localhost"),
        ("http://", ""),
    ],
)
def test_registered_domain_u1(url, expected):
    assert registered_domain(url) == expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://my-site.github.io/login", "my-site.github.io"),
        ("https://a.web.app/x", "a.web.app"),
        ("https://login.secure.paypal.co.uk/x", "paypal.co.uk"),
    ],
)
def test_registered_domain_u2_honours_private_suffixes(url, expected):
    assert registered_domain_private(url) == expected


def test_sites_on_one_platform_share_the_u1_group():
    assert registered_domain("https://a.github.io/") == registered_domain("https://b.github.io/")
    assert registered_domain_private("https://a.github.io/") != registered_domain_private(
        "https://b.github.io/"
    )


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("HTTP://Example.COM:80/", "http://example.com"),
        ("https://example.com:443/a/B?x=Y#frag", "https://example.com/a/B?x=Y"),
        ("example.com/path", "http://example.com/path"),
        ("https://example.com:8443/", "https://example.com:8443"),
        ("http://[2001:db8::1]/a", "http://[2001:db8::1]/a"),
        ("  https://example.com./x  ", "https://example.com/x"),
    ],
)
def test_normalize_url(url, expected):
    assert normalize_url(url) == expected


def test_url_key_ignores_scheme_www_and_trailing_slash():
    variants = [
        "https://www.Example.com/",
        "http://example.com",
        "example.com/",
        "HTTPS://WWW.EXAMPLE.COM:443#top",
    ]
    assert {url_key(u) for u in variants} == {"example.com"}
    assert url_key("https://example.com/a/?x=1") == "example.com/a?x=1"
    assert url_key("https://example.com/A") != url_key("https://example.com/a")  # path case kept
    assert url_key("https://example.com:8080/") == "example.com:8080"
    assert url_key("https://sub.example.com/") != url_key("https://example.com/")


@pytest.mark.parametrize(
    ("url", "depth"),
    [
        ("https://www.example.com", 0),
        ("https://www.example.com/", 0),
        ("https://www.example.com/?q=1/2/3", 0),  # query excluded
        ("https://www.example.com/#/a/b", 0),  # fragment excluded
        ("https://example.com/a", 1),
        ("https://example.com/a/", 1),
        ("https://example.com//a///b", 2),  # empty segments ignored
        ("example.com/a/b/c/login.php?x=1", 4),
    ],
)
def test_url_depth(url, depth):
    assert url_depth(url) == depth


def test_normalize_to_registrable():
    assert normalize_to_registrable("http://login.paypal.co.uk/a/b?x") == "https://www.paypal.co.uk"


def test_hostname_handles_garbage():
    assert hostname("http://[not-ipv6/") == ""
    assert hostname("HTTPS://Sub.Example.COM.:8443/x") == "sub.example.com"
