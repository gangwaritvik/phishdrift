"""Brand-domain mismatch columns: look-alikes are flagged, a brand's own domains are not."""

import math
import random

from attacks.lookalike import STYLES, TEST_ONLY_STYLES, TRAIN_STYLES, make_domain
from features.brand_mismatch import COLUMNS, BrandMismatch, within_one
from features.urlparts import parse

PLATFORMS = frozenset({"github.io"})
BM = BrandMismatch(
    ["paypal", "microsoft", "apple", "amazon"],
    {"paypal": ["paypal.com", "paypal.de"], "apple": ["apple.com"], "microsoft": ["microsoft.com"]},
    {"а": "a"},  # Cyrillic a
)


def sig(url: str) -> dict[str, float]:
    return BM.features(parse(url, PLATFORMS))


def test_digit_swap_is_a_foreign_homograph():
    s = sig("https://paypa1.com/")
    assert s["brand_homograph"] == 1 and s["brand_official"] == 0 and s["brand_other_suffix"] == 0


def test_rn_for_m_and_punycode_are_homographs():
    assert sig("https://rnicrosoft.com/")["brand_homograph"] == 1
    assert sig("https://xn--pple-43d.com/")["brand_homograph"] == 1  # Cyrillic a + "pple"


def test_one_edit_needs_six_letters():
    assert sig("https://paypai.com/")["brand_edit1"] == 1
    assert sig("https://appl.com/")["brand_edit1"] == 0  # "apple" is below the 6-letter minimum


def test_a_brands_own_domains_are_not_look_alikes():
    for url in ("https://www.paypal.com/signin", "https://paypal.de/", "https://apple.com/"):
        s = sig(url)
        assert s["brand_official"] == 1
        assert s["brand_homograph"] == s["brand_edit1"] == s["brand_other_suffix"] == 0


def test_brand_name_on_another_suffix():
    s = sig("https://paypal.net/")
    assert s["brand_other_suffix"] == 1 and s["brand_official"] == 0
    assert sig("https://amazon.xyz/")["brand_other_suffix"] == 0  # no own domains known: unknown


def test_platforms_and_ip_hosts_are_missing_not_zero():
    for url in ("https://paypa1.github.io/", "http://192.168.0.1/login"):
        assert all(math.isnan(v) for v in sig(url).values())
    assert set(sig("https://example.org/")) == set(COLUMNS)


def test_within_one_edit_kinds():
    assert within_one("paypal", "paypai") and within_one("paypal", "payal")
    assert within_one("paypal", "pyapal") and within_one("paypal", "paypall")
    assert not within_one("paypal", "paypal") and not within_one("paypal", "pxypai")


def test_look_alike_styles_are_deterministic_and_split_into_seen_and_unseen():
    assert set(STYLES) == set(TRAIN_STYLES) | set(TEST_ONLY_STYLES)
    assert not set(TRAIN_STYLES) & set(TEST_ONLY_STYLES)
    for style in STYLES:
        a = make_domain(style, "microsoft", random.Random(1), "com")
        assert a == make_domain(style, "microsoft", random.Random(1), "com")
        assert a is None or (a.isascii() and a != "microsoft.com" or style == "suffix")
    assert make_domain("suffix", "paypal", random.Random(1), "com").split(".")[1] != "com"
    assert make_domain("delete", "ebay", random.Random(1)) is None  # too short to stay a name


def test_generated_look_alikes_are_flagged_by_the_columns():
    flagged = 0
    for style in ("digit", "leet", "rnvv", "unicode", "transpose", "delete", "insert"):
        dom = make_domain(style, "microsoft", random.Random(4), "com")
        if dom:
            s = BM.features(parse(f"https://{dom}/", PLATFORMS))
            flagged += s["brand_homograph"] == 1 or s["brand_edit1"] == 1
    assert flagged >= 5
