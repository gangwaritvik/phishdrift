"""Tier B text group."""

import pytest

from tests.html_helpers import feats, isnan, page

SHOP = "https://www.examplebank.com/login"


def test_title_flags():
    assert feats(page(title="Example Bank"))["has_title"] == 1
    assert feats(page(title="Example Bank"))["title_empty"] == 0
    blank = feats(page(title="   "))
    assert blank["has_title"] == 1 and blank["title_empty"] == 1
    none = feats(page(title=None))
    assert none["has_title"] == 0 and isnan(none["title_empty"])  # no element: not applicable
    assert isnan(none["domain_in_title"]) and isnan(none["title_domain_match"])
    assert isnan(none["url_title_match"]) and isnan(none["title_has_credential_word"])


def test_domain_in_title_and_match_score():
    f = feats(page(title="Example Bank | Sign in"), url=SHOP)
    assert f["domain_in_title"] == 1 and f["title_domain_match"] == 1
    assert f["title_has_credential_word"] == 1
    g = feats(page(title="Welcome to our shop"), url=SHOP)
    assert g["domain_in_title"] == 0 and g["title_domain_match"] < 0.5
    assert g["title_has_credential_word"] == 0
    # punctuation and case do not matter: label "examplebank" against "EXAMPLE-BANK"
    assert feats(page(title="EXAMPLE-BANK online"), url=SHOP)["domain_in_title"] == 1


def test_url_title_match():
    f = feats(page(title="Example Bank login"), url=SHOP)
    # words of 3+ letters: example, bank, login; the masked URL has all three
    assert f["url_title_match"] == pytest.approx(1.0)
    g = feats(page(title="Example Garden shop"), url=SHOP)
    assert g["url_title_match"] == pytest.approx(1 / 3)
    assert isnan(feats(page(title="a b"), url=SHOP)["url_title_match"])  # no word of 3+ letters


def test_domain_text_features_are_nan_for_ip_and_platform_hosts():
    for url in ("http://192.168.1.5/login", "https://victim.github.io/login"):
        f = feats(page(title="Victim Login"), url=url)
        assert isnan(f["domain_in_title"]) and isnan(f["title_domain_match"])
        assert isnan(f["domain_in_copyright"])
        assert f["title_has_credential_word"] == 1  # not domain-relative


def test_description_and_copyright():
    f = feats(page("<footer>Copyright 2024 Example Bank. All rights reserved.</footer>"), url=SHOP)
    assert f["has_copyright"] == 1 and f["domain_in_copyright"] == 1
    assert f["has_description"] == 0
    g = feats(page("<footer>© 2024 Some Other Company</footer>"), url=SHOP)
    assert g["has_copyright"] == 1 and g["domain_in_copyright"] == 0
    h = feats(page(), url=SHOP)
    assert h["has_copyright"] == 0 and isnan(h["domain_in_copyright"])
    desc = feats(page(head='<meta name="description" content="Online banking">'))
    assert desc["has_description"] == 1
    assert feats(page(head='<meta name="description" content="  ">'))["has_description"] == 0


def test_word_counts():
    text = (
        "<p>Your bank account number and credit card. Please pay now: payment due, invoice "
        "attached. Bitcoin wallet, seed phrase. URGENT: your account is suspended, action "
        "required immediately. Login with your password and the OTP, or sign in.</p>"
    )
    f = feats(page(text))
    assert f["n_bank_words"] == 4  # bank, account number, credit card, bank account
    assert f["n_pay_words"] == 5  # pay, pay now, payment, invoice, wallet
    assert f["n_crypto_words"] == 3  # bitcoin, wallet, seed phrase
    assert f["n_urgency_words"] == 4  # urgent, suspended, action required, immediately
    assert f["n_credential_words"] == 4  # login, password, otp, sign in
    plain = feats(page())
    assert all(plain[k] == 0 for k in ("n_bank_words", "n_pay_words", "n_crypto_words"))


def test_script_style_and_noscript_text_is_not_counted():
    body = (
        "<script>var bank = 'bank bank bank';</script><style>.bank{}</style>"
        "<noscript>bank bank bank</noscript><title>bank</title>"
    )
    assert feats(page(body, title="Shop"))["n_bank_words"] == 0


def test_brand_mismatch():
    # A PayPal page on an unrelated domain.
    f = feats(page("<p>PayPal PayPal</p>", title="PayPal - Log in"), url="https://evil.test/a")
    assert f["brand_in_title_mismatch"] == 1 and f["n_brands_in_text_mismatch"] == 1
    # The same page on PayPal's own domain, including another country suffix.
    for url in ("https://www.paypal.com/signin", "https://paypal.co.uk/x"):
        g = feats(page("<p>PayPal PayPal</p>", title="PayPal - Log in"), url=url)
        assert g["brand_in_title_mismatch"] == 0 and g["n_brands_in_text_mismatch"] == 0
    # A look-alike label is not the brand.
    h = feats(page(title="PayPal"), url="https://paypal-secure.com/")
    assert h["brand_in_title_mismatch"] == 1
    # One mention in the text is not enough; words written apart still match a joined brand.
    one = feats(page("<p>amazon</p>"), url="https://evil.test/")
    assert one["n_brands_in_text_mismatch"] == 0
    apart = feats(page("<p>Bank of America. Bank of America.</p>"), url="https://evil.test/")
    assert apart["n_brands_in_text_mismatch"] == 1
    assert feats(page(title="Welcome"), url="https://evil.test/")["brand_in_title_mismatch"] == 0


def test_no_brand_list_gives_nan_not_zero():
    from features.lists import Lists

    f = feats(page(title="PayPal"), lists=Lists.build())
    assert isnan(f["brand_in_title_mismatch"]) and isnan(f["n_brands_in_text_mismatch"])
