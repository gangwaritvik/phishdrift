"""URL evasion transforms: deterministic, valid URLs, parent domain kept where it should be."""

import pytest

from attacks import FAMILIES, apply_family
from features.lists import Lists
from phishdrift.domains import split_host

LISTS = Lists.build(
    platforms={"github.io"},
    brands={"paypal", "microsoft", "amazon"},
    shorteners={"bit.ly", "tinyurl.com"},
)
URL = "https://login.shop-example.co.uk/account/verify?id=7"


@pytest.mark.parametrize("family", FAMILIES)
def test_each_family_is_deterministic_and_changes_the_url(family):
    a = apply_family(family, URL, LISTS, seed=3)
    assert a is not None and a != URL and a.startswith(("http://", "https://"))
    assert a == apply_family(family, URL, LISTS, seed=3)


def test_seed_changes_the_choice():
    seen = {apply_family("padding", URL, LISTS, seed=s) for s in range(5)}
    assert len(seen) > 1


def test_homoglyph_changes_the_domain_label_and_stays_a_valid_host():
    out = {apply_family("homoglyph", URL, LISTS, seed=s) for s in range(20)}
    assert all(u and u != URL for u in out)
    assert any("xn--" in u for u in out) and any("xn--" not in u for u in out)
    for u in out:
        host = u.split("/")[2]
        assert host.isascii() and host.endswith(".co.uk")


def test_subdomain_stuffing_keeps_the_real_domain_last():
    out = apply_family("subdomain", URL, LISTS, seed=1)
    host = out.split("/")[2]
    assert host.endswith("login.shop-example.co.uk") and host.count(".") > 4
    assert split_host(host)[1] == "shop-example"


def test_brand_adds_a_known_brand_to_the_path_and_keeps_the_host():
    out = apply_family("brand", URL, LISTS, seed=1)
    assert out.split("/")[2] == "login.shop-example.co.uk"
    assert any(b in out for b in LISTS.brands)


def test_padding_keeps_the_host_and_makes_the_url_longer():
    out = apply_family("padding", URL, LISTS, seed=1)
    assert out.split("/")[2] == "login.shop-example.co.uk" and len(out) > len(URL) + 60


def test_shortener_replaces_the_url_with_a_short_link():
    out = apply_family("shortener", URL, LISTS, seed=1)
    assert out.split("/")[2] in LISTS.shorteners and "shop-example" not in out


def test_tld_swap_changes_the_suffix_and_the_label():
    out = apply_family("tld", URL, LISTS, seed=1)
    sub, label, suffix = split_host(out.split("/")[2])
    assert suffix != "co.uk" and "-" in label and label != "shop-example"


@pytest.mark.parametrize("family", ["homoglyph", "tld"])
def test_domain_families_skip_ip_hosts_and_hosting_platforms(family):
    assert apply_family(family, "http://203.0.113.5/x", LISTS) is None
    assert apply_family(family, "https://someone.github.io/x", LISTS) is None


def test_unparsable_input_is_skipped():
    for family in FAMILIES:
        assert apply_family(family, "ftp://example.com/x", LISTS) is None
        assert apply_family(family, "", LISTS) is None


def test_robustness_report_renders_from_per_split_rows():
    import pandas as pd

    from experiments import robustness
    from phishdrift.config import load_config

    rows = []
    for model, flag in (("base", 0.5), ("adv", 0.8)):
        rows.append(
            {"split": 0, "model": model, "held_out": "tld", "set": "clean_test", "n_urls": 100}
            | {"n_domains": 90, "roc_auc": 0.95, "op_1pct_recall": 0.7, "op_0p1pct_recall": 0.5}
            | {"cal_1pct_recall": 0.7, "cal_1pct_fpr": 0.01, "cal_0p1pct_recall": 0.5}
            | {"cal_0p1pct_fpr": 0.001}
        )  # fmt: skip
        for label in ("clean_phishing", "clean_benign", "long_benign"):
            rows.append(_flag(model, label, flag, False))
        for fam in FAMILIES:
            for kind in ("phishing", "benign"):
                rows.append(_flag(model, f"{fam}:{kind}", flag, fam == "tld"))
    text = robustness.render(pd.DataFrame(rows), load_config("models"))
    assert "tld (held out)" in text and "tld (seen in training)" not in text
    assert "## False alarms on rewritten and long legitimate URLs" in text


def _flag(model, label, flag, held):
    return {
        "split": 0, "model": model, "held_out": "tld", "set": label, "n_urls": 50,
        "n_domains": 50, "flag_suspicious": flag, "flag_dangerous": flag / 2,
        "applied": 1.0, "family_held_out": held,
    }  # fmt: skip
