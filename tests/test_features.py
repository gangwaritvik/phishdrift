"""Tier A URL features: one test per group, plus masking, NaN, registry and dictionary checks."""

import math

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from features import dictionary, fit, scrape
from features.extract import extract
from features.fit import Fitted
from features.lists import PLATFORM_TOKEN, Lists
from features.registry import GROUPS, NAMES, REGISTRY
from features.url_features import edit_distance, normalise_homoglyphs
from features.urlparts import parse


@pytest.fixture
def lists() -> Lists:
    return Lists.build(
        platforms=["github.io", "web.app"],
        brands=["paypal", "amazon", "hdfcbank", "sbi"],  # "sbi" is under 4 characters: dropped
        keywords=["login", "verify", "secure"],
        shorteners=["bit.ly"],
        suspicious_tlds=["xyz"],
        redirect_params=["url", "next"],
    )


def feats(url: str, lists: Lists, fitted: Fitted | None = None) -> dict[str, float]:
    return extract(url, lists=lists, fitted=fitted or Fitted())


def isnan(x: float) -> bool:
    return math.isnan(x)


def test_registry_is_complete_and_unique():
    assert len(NAMES) == len(set(NAMES)) >= 90
    assert set(GROUPS) == {f.group for f in REGISTRY}
    assert all(f.tier == "A" and f.in_browser for f in REGISTRY)


def test_extract_returns_every_registered_feature_in_order(lists):
    out = feats("https://www.example.com/a/b.php?x=1&y=2#frag", lists)
    assert list(out) == list(NAMES)
    assert all(isinstance(v, float) for v in out.values())


def test_length_group(lists):
    f = feats(
        "http://www.Example.com/a/b.php?x=1&y=2#frag", lists
    )  # canonical: example.com/a/b.php?x=1&y=2
    assert (f["url_len"], f["host_len"], f["domain_len"], f["subdomain_len"]) == (27, 11, 11, 0)
    assert (f["path_len"], f["query_len"], f["tld_len"]) == (8, 7, 3)
    assert (f["shortest_word_url"], f["longest_word_url"]) == (1, 7)
    assert f["avg_word_url"] == pytest.approx(19 / 9)
    assert (f["shortest_word_host"], f["longest_word_host"], f["avg_word_host"]) == (3, 7, 5)
    assert f["avg_word_path"] == pytest.approx(5 / 3)
    assert isnan(feats("example.com", lists)["shortest_word_path"])  # no path -> NaN, not 0


def test_counts_group(lists):
    f = feats("http://www.Example.com/a/b.php?x=1&y=2#frag", lists)
    assert (f["n_dot"], f["n_slash"], f["n_qmark"], f["n_and"], f["n_eq"]) == (2, 2, 1, 1, 2)
    assert (f["n_digits"], f["n_letters"], f["path_depth"], f["n_query_params"]) == (2, 17, 2, 2)
    assert (f["host_n_dot"], f["host_n_hyphen"], f["n_subdomain_levels"]) == (1, 0, 0)
    g = feats("a.b.shop.example.co.uk/x/www/com", lists)
    assert g["n_subdomain_levels"] == 3 and g["n_www_tokens"] == 1 and g["n_com_tokens"] == 1
    assert feats("a b.com/x y", lists)["n_space"] == 2


def test_ratios_group(lists):
    f = feats("example.com/a/b.php?x=1&y=2", lists)
    assert f["digit_ratio_url"] == pytest.approx(2 / 27)
    assert f["letter_ratio_url"] == pytest.approx(17 / 27)
    assert f["special_ratio_url"] == pytest.approx(8 / 27)
    assert f["digit_ratio_host"] == 0 and f["letter_ratio_host"] == pytest.approx(10 / 11)


def test_host_form_group(lists):
    ip = feats("http://192.168.0.1:8080/login", lists)
    assert ip["host_is_ip"] == 1 and ip["nonstandard_port"] == 1 and ip["has_port"] == 1
    assert feats("http://0x7f000001/", lists)["host_ip_obfuscated"] == 1
    assert feats("http://2130706433/", lists)["host_ip_obfuscated"] == 1
    assert feats("https://user@evil.com", lists)["has_userinfo"] == 1
    assert feats("https://xn--pypal-4ve.com", lists)["has_punycode"] == 1
    assert feats("https://pаypal.com", lists)["has_non_ascii_host"] == 1  # Cyrillic a
    f = feats("https://secure-https.example.com/http/www//a.com/p.html", lists)
    assert f["https_in_host"] == 1 and f["http_in_path"] == 1 and f["www_in_path"] == 1
    assert (
        f["double_slash_in_path"] == 1 and f["tld_in_path"] == 1 and f["prefix_suffix_hyphen"] == 0
    )
    assert f["path_ext_is_html"] == 1 and f["path_ext_is_script"] == 0
    assert feats("https://w.x.y.z.example.com", lists)["abnormal_subdomain"] == 1
    assert feats("https://a.www.example.com", lists)["www_misplaced_host"] == 1
    assert feats("https://my-bank.com", lists)["prefix_suffix_hyphen"] == 1
    assert feats("https://a.example.com/x?com", lists)["tld_in_subdomain"] == 0


def test_obfuscation_group(lists):
    f = feats("example.com/a%20b%2Fc/zzzz", lists)
    assert f["n_pct_encoded"] == 2 and f["pct_encoded_ratio"] == pytest.approx(6 / 26)
    assert f["longest_repeat_run"] == 4
    assert f["n_non_ascii_url"] == 0
    assert feats("example.com/ü", lists)["n_non_ascii_url"] == 1
    assert 0 < f["char_continuation_rate"] <= 1


def test_randomness_group(lists):
    f = feats("aaaa.com", lists)
    assert f["entropy_domain"] == 0
    assert f["domain_vowel_ratio"] == 1 and f["domain_longest_consonant_run"] == 0
    g = feats("xk7qzp.com", lists)
    assert g["domain_longest_consonant_run"] == 3 and g["domain_digit_switches"] == 2
    assert g["entropy_domain"] > f["entropy_domain"]
    assert isnan(g["bigram_loglik_domain"])  # not fitted
    fitted = Fitted(bigram_logprob={"aa": -1.0}, bigram_floor=-9.0)
    assert feats("aaaa.com", lists, fitted)["bigram_loglik_domain"] == pytest.approx(-1.0)
    assert feats("ab.com", lists, fitted)["bigram_loglik_domain"] == pytest.approx(-9.0)


def test_words_group(lists):
    f = feats("https://login.paypal-support.com/verify/amazon?next=secure", lists)
    assert f["kw_in_host"] == 1 and f["kw_in_path"] == 1 and f["kw_in_query"] == 1
    assert f["n_suspicious_keywords"] == 3
    assert f["brand_in_subdomain"] == 0 and f["brand_in_path"] == 1
    assert f["domain_contains_brand"] == 1 and f["domain_is_brand"] == 0
    assert feats("https://paypal.com", lists)["domain_is_brand"] == 1
    assert feats("https://paypal.com", lists)["domain_contains_brand"] == 0
    assert feats("https://amazon.evil.com", lists)["brand_in_subdomain"] == 1


def test_squatting_group(lists):
    assert feats("paypal.com", lists)["min_brand_edit_distance"] == 0
    assert feats("paypa.com", lists)["min_brand_edit_distance"] == 1
    assert feats("paypall.com", lists)["min_brand_edit_distance"] == 1
    assert feats("pyapal.com", lists)["min_brand_edit_distance"] == 2
    assert feats("google.com", lists)["min_brand_edit_distance"] == 3  # 3 means "3 or more"
    assert feats("paypa1.com", lists)["homoglyph_brand_match"] == 1
    assert feats("paypal.com", lists)["homoglyph_brand_match"] == 0
    assert feats("paypal-secure.com", lists)["combosquat_prefix"] == 1
    assert feats("secure-paypal.com", lists)["combosquat_suffix"] == 1
    assert feats("my-paypal-login.com", lists)["combosquat_middle"] == 1
    assert feats("paypal.com", lists)["combosquat_prefix"] == 0
    assert isnan(feats("http://1.2.3.4/x", lists)["min_brand_edit_distance"])
    assert edit_distance("kitten", "sitting") == 3
    assert normalise_homoglyphs("arnazon") == "amazon"


def test_other_group(lists):
    assert feats("https://bit.ly/abc", lists)["is_shortener"] == 1
    assert feats("https://example.com/?url=http://evil.com", lists)["has_redirect_param"] == 1
    assert feats("https://example.com/?url=http://evil.com", lists)["has_embedded_url"] == 1
    assert feats("https://example.com/?u=http%3A%2F%2Fevil.com", lists)["has_embedded_url"] == 1
    assert feats("https://example.com/a@b.com", lists)["has_embedded_email"] == 1
    assert feats("https://example.xyz", lists)["suspicious_tld"] == 1
    assert feats("https://example.com", lists)["suspicious_tld"] == 0
    assert isnan(feats("https://example.com", lists)["tld_risk"])
    fitted = Fitted(tld_risk={"com": 0.2}, tld_default=0.5)
    assert feats("https://example.com", lists, fitted)["tld_risk"] == 0.2
    assert feats("https://example.org", lists, fitted)["tld_risk"] == 0.5


def test_platform_masking_hides_which_platform(lists):
    a = feats("https://evil.github.io/login", lists)
    b = feats("https://evil.web.app/login", lists)
    assert a == b  # the platform's identity does not reach any feature
    assert a["is_hosting_platform"] == 1 and a["subdomain_len"] == 4
    assert feats("https://evil.example.com/login", lists)["is_hosting_platform"] == 0
    p = parse("https://github.io/x", lists.platforms)
    assert p is not None and p.host == PLATFORM_TOKEN and p.subdomain == ""


def test_canonicalisation_removes_formatting_differences(lists):
    base = feats("example.com/a/b", lists)
    for variant in (
        "https://example.com/a/b/",
        "http://www.example.com/a/b#x",
        "HTTPS://WWW.EXAMPLE.COM/a/b",
    ):
        assert feats(variant, lists) == base


def test_missing_values_are_nan_not_zero(lists):
    for bad in ("", "   ", "http://", "://", None):
        out = extract(bad, lists=lists, fitted=Fitted())
        assert list(out) == list(NAMES) and all(isnan(v) for v in out.values())


def test_dictionary_is_not_stale():
    assert dictionary.DICTIONARY_FILE.read_text(encoding="utf-8") == dictionary.render(), (
        "docs/FEATURE_DICTIONARY.md is stale: run `python -m features dictionary`"
    )


def test_platform_list_comes_from_the_public_suffix_list():
    platforms = set(scrape.platforms_from_psl())
    assert {"github.io", "web.app", "pages.dev", "blogspot.com", "firebaseapp.com"} <= platforms
    assert "com" not in platforms and "co.uk" not in platforms  # ICANN suffixes are not platforms
    shipped = Lists.build(platforms=__import__("features.lists", fromlist=["x"]).read_platforms())
    assert "github.io" in shipped.platforms


def test_fit_uses_given_rows_only(lists):
    urls = ["good.com/a", "good.com/b", "bad.xyz/a", "bad.xyz/b", "bad.xyz/c"]
    data = fit.fit(urls, [0, 0, 1, 1, 1], lists.platforms)
    assert data["tld_risk"]["xyz"] > data["tld_risk"]["com"]
    assert "go" in data["bigram_logprob"]  # benign label only
    assert "ba" not in data["bigram_logprob"]  # phishing domains never enter the bigram model


def test_build_streams_a_processed_part(tmp_path, monkeypatch, lists):
    from features import __main__ as cli

    pool = pa.table({"uid": ["a:0", "a:1"], "url": ["https://paypa1.com/login", "http://x.org"]})
    pq.write_table(pool, tmp_path / "pool.parquet")
    monkeypatch.setattr(cli, "_paths", lambda: (tmp_path, tmp_path / "features_a.parquet"))
    monkeypatch.setattr(cli, "load_lists", lambda: lists)
    out = cli.build("pool")
    df = pd.read_parquet(out)
    assert list(df.columns) == ["uid", *NAMES] and len(df) == 2
    assert df.loc[0, "homoglyph_brand_match"] == 1


def test_build_other_parts_get_their_own_file(tmp_path, monkeypatch, lists):
    from features import __main__ as cli

    held = pa.table({"uid": ["s:0"], "url": ["http://x.org/a"]})
    pq.write_table(held, tmp_path / "heldout_source.parquet")
    monkeypatch.setattr(cli, "_paths", lambda: (tmp_path, tmp_path / "features_a.parquet"))
    monkeypatch.setattr(cli, "load_lists", lambda: lists)
    out = cli.build("heldout_source")
    assert out.name == "features_a_heldout_source.parquet" and len(pd.read_parquet(out)) == 1


def test_wikidata_brands_survive_one_failing_type():
    import json

    from features.scrape import brands_from_wikidata

    class Client:
        def get(self, url, **kwargs):
            if "Q22687" in url:
                raise TimeoutError("504")
            rows = [
                {"label": {"value": "Acme Bank"}, "site": {"value": "https://www.acmebank.com/"}}
            ]
            return json.dumps({"results": {"bindings": rows}}).encode()

    cfg = {
        "wikidata_types": ["Q4830453", "Q22687"],
        "wikidata_query": "{type} {min_sitelinks}",
        "wikidata_min_sitelinks": 40,
    }
    assert "acmebank" in brands_from_wikidata(Client(), cfg)
