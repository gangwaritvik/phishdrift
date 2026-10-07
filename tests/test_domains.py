import pytest

from phishdrift.domains import hostname, normalize_url, registered_domain


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
        ("https://my-site.github.io/login", "my-site.github.io"),  # private suffix
        ("https://evil.blogspot.com/", "evil.blogspot.com"),
        ("http://192.0.2.10/bank/update.php", "192.0.2.10"),
        ("http://[2001:db8::1]:8080/x", "2001:db8::1"),
        ("https://xn--pypal-4ve.com/", "xn--pypal-4ve.com"),  # punycode stays as-is
        ("http://user:pw@evil.com/x", "evil.com"),  # userinfo trick
        ("http://localhost:8000/", "localhost"),
        ("http://", ""),
    ],
)
def test_registered_domain(url, expected):
    assert registered_domain(url) == expected


def test_same_site_pages_share_domain():
    a = registered_domain("https://a.example.co.uk/login")
    b = registered_domain("http://b.c.example.co.uk/other?x=1")
    assert a == b == "example.co.uk"


def test_different_free_hosted_sites_differ():
    assert registered_domain("https://a.github.io/") != registered_domain("https://b.github.io/")


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


def test_hostname_handles_garbage():
    assert hostname("http://[not-ipv6/") == ""
