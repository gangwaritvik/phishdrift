"""Feature registry: every feature is declared once here.

``docs/FEATURE_DICTIONARY.md`` is generated from this table (``python -m features dictionary``)
and a test fails if the file is stale. Never edit the dictionary by hand.
"""

from __future__ import annotations

from dataclasses import dataclass

PAPERS = {
    "H": "Hannousse and Yahiouche 2021 (87 features)",
    "P": "Prasad and Chandra 2024 (PhiUSIIL)",
    "U": "UCI Phishing Websites (Mohammad et al. 2014)",
    "own": "this project",
}


@dataclass(frozen=True)
class Feature:
    name: str
    group: str
    definition: str
    papers: str = "own"
    tier: str = "A"
    availability: str = "all samples"
    runtime_cost: str = "low"
    in_browser: bool = True


CHARS = {
    "dot": ".",
    "hyphen": "-",
    "underscore": "_",
    "slash": "/",
    "at": "@",
    "qmark": "?",
    "and": "&",
    "eq": "=",
    "percent": "%",
    "tilde": "~",
    "plus": "+",
    "star": "*",
    "colon": ":",
    "comma": ",",
    "semicolon": ";",
    "dollar": "$",
    "pipe": "|",
    "space": " ",
}

CANON = "the canonical URL (no scheme, no leading www., platform domain masked)"


def _rows() -> list[Feature]:
    f: list[Feature] = []

    def add(name: str, group: str, definition: str, papers: str = "own", cost: str = "low"):
        f.append(Feature(name, group, definition, papers, runtime_cost=cost))

    g = "length"
    add("url_len", g, f"Characters in {CANON}.", "H,P,U")
    add("host_len", g, "Characters in the host.", "H,P")
    add("domain_len", g, "Characters in the registrable domain (label + public suffix).", "P")
    add("subdomain_len", g, "Characters in the subdomain part of the host (0 if none).", "own")
    add("path_len", g, "Characters in the path.", "H")
    add("query_len", g, "Characters in the query string.", "H")
    add("tld_len", g, "Characters in the public suffix.", "P")
    for scope, what in (("url", "URL"), ("host", "host"), ("path", "path")):
        add(
            f"shortest_word_{scope}",
            g,
            f"Length of the shortest word in the {what}; NaN if none.",
            "H",
        )
        add(
            f"longest_word_{scope}",
            g,
            f"Length of the longest word in the {what}; NaN if none.",
            "H",
        )
        add(f"avg_word_{scope}", g, f"Mean word length in the {what}; NaN if none.", "H")

    g = "counts"
    for key, ch in CHARS.items():
        shown = "space" if ch == " " else f"`{ch}`"
        add(f"n_{key}", g, f"Number of {shown} characters in the URL.", "H,P,U")
    add("host_n_dot", g, "Number of `.` in the host.", "H")
    add("host_n_hyphen", g, "Number of `-` in the host.", "H")
    add("n_digits", g, "Number of ASCII digits in the URL.", "P")
    add("n_letters", g, "Number of ASCII letters in the URL.", "P")
    add("n_subdomain_levels", g, "Number of labels in the subdomain (0 if none).", "H,P")
    add("path_depth", g, "Non-empty `/`-separated path segments (same as the corpus depth).", "H")
    add("n_query_params", g, "Number of `&`-separated query entries.", "P")
    add("n_www_tokens", g, "Words equal to `www` in the host or path.", "H")
    add("n_com_tokens", g, "Words equal to `com` in the host or path.", "H")

    g = "ratios"
    for scope in ("url", "host"):
        add(f"digit_ratio_{scope}", g, f"Digits divided by length of the {scope}.", "H,P")
        add(f"letter_ratio_{scope}", g, f"Letters divided by length of the {scope}.", "P")
        add(
            f"special_ratio_{scope}",
            g,
            f"Non-alphanumeric characters divided by length of the {scope}.",
            "P",
        )

    g = "host_form"
    add("host_is_ip", g, "Host is an IPv4 or IPv6 address.", "H,P,U")
    add("host_ip_obfuscated", g, "Host is a hex, octal or single-decimal-number IP.", "H")
    add("has_port", g, "A port is written in the URL.", "H")
    add("nonstandard_port", g, "A port other than 80 or 443 is written.", "H,U")
    add("has_userinfo", g, "The URL has `user@` before the host.", "H,U")
    add("has_punycode", g, "The host contains `xn--`.", "H")
    add("has_non_ascii_host", g, "The host contains non-ASCII characters.", "own")
    add("https_in_host", g, "The word `https` appears inside the host.", "H,U")
    add("http_in_path", g, "The word `http` appears inside the path.", "H")
    add("www_in_path", g, "The word `www` appears inside the path.", "H")
    add("www_misplaced_host", g, "A `www` label appears in the host after the first position.", "H")
    add("double_slash_in_path", g, "`//` appears in the path.", "H,U")
    add("tld_in_path", g, "The last label of the public suffix is a word in the path.", "H")
    add(
        "tld_in_subdomain",
        g,
        "The last label of the public suffix is a label in the subdomain.",
        "H",
    )
    add(
        "abnormal_subdomain",
        g,
        "More than 3 subdomain labels, or a label over 25 characters.",
        "own",
    )
    add("prefix_suffix_hyphen", g, "The registrable domain label contains `-`.", "H,U")
    add(
        "path_ext_present",
        g,
        "The last path segment has a file extension of 1 to 5 characters.",
        "H",
    )
    add("path_ext_is_script", g, "Extension is php, asp, aspx, jsp or cgi.", "own")
    add("path_ext_is_html", g, "Extension is html, htm or shtml.", "own")

    g = "obfuscation"
    add("n_pct_encoded", g, "Number of `%XX` escapes.", "H")
    add("pct_encoded_ratio", g, "Characters in escapes divided by URL length.", "H")
    add("longest_repeat_run", g, "Length of the longest run of one repeated character.", "own")
    add(
        "char_continuation_rate",
        g,
        "Longest run of one character class (letters, digits, other) divided by URL length.",
        "P",
    )
    add("n_non_ascii_url", g, "Number of non-ASCII characters in the URL.", "own")

    g = "randomness"
    add("entropy_url", g, "Shannon entropy of the URL characters (bits).", "P")
    add("entropy_domain", g, "Shannon entropy of the registrable domain label (bits).", "H")
    add(
        "bigram_loglik_domain",
        g,
        "Mean log probability of the domain label's character bigrams under a model fitted on training benign domains only; NaN until fitted. Doubles as the random-domain score.",
        "own",
        "low",
    )
    add("domain_longest_consonant_run", g, "Longest run of consonants in the domain label.", "own")
    add(
        "domain_vowel_ratio",
        g,
        "Vowels divided by letters in the domain label; NaN if no letters.",
        "own",
    )
    add(
        "domain_digit_switches",
        g,
        "Letter to digit or digit to letter changes in the domain label.",
        "own",
    )

    g = "words"
    add(
        "n_suspicious_keywords",
        g,
        "Distinct suspicious keywords (login, verify, kyc, upi, ...) found in host, path or query.",
        "H,P",
    )
    add("kw_in_host", g, "Suspicious keywords found in the host (count of distinct keywords).", "H")
    add("kw_in_path", g, "Suspicious keywords found in the path.", "H")
    add("kw_in_query", g, "Suspicious keywords found in the query.", "own")
    add(
        "brand_in_subdomain",
        g,
        "Brand names found in the subdomain (count of distinct brands).",
        "H",
    )
    add("brand_in_path", g, "Brand names found in the path (count of distinct brands).", "H")
    add("domain_is_brand", g, "The registrable domain label equals a brand name.", "own")
    add(
        "domain_contains_brand",
        g,
        "The domain label contains a brand name but is not equal to it.",
        "own",
    )

    g = "squatting"
    add(
        "min_brand_edit_distance",
        g,
        "Smallest edit distance from the domain label to a brand name: 0, 1, 2, or 3 meaning 3 or more.",
        "own",
        "medium",
    )
    add(
        "homoglyph_brand_match",
        g,
        "The label equals a brand name only after look-alike characters are normalised (0 to o, 1 to l, rn to m, ...).",
        "own",
        "medium",
    )
    add(
        "combosquat_prefix",
        g,
        "The label is brand + hyphen + other words (`paypal-secure`).",
        "own",
    )
    add(
        "combosquat_suffix",
        g,
        "The label is other words + hyphen + brand (`secure-paypal`).",
        "own",
    )
    add(
        "combosquat_middle",
        g,
        "A brand is a hyphen-separated word in the middle of the label.",
        "own",
    )

    g = "other"
    add("is_shortener", g, "The registrable domain is a known URL shortener.", "H")
    add(
        "has_redirect_param",
        g,
        "The query has a redirect-style parameter (url, redirect, next, goto, ...).",
        "own",
    )
    add(
        "has_embedded_url",
        g,
        "Another URL (`http://` or its %-encoded form) appears in the path or query.",
        "H",
    )
    add("has_embedded_email", g, "An email address appears in the path or query.", "own")
    add("suspicious_tld", g, "The public suffix is on the abused-TLD list.", "H")
    add(
        "tld_risk",
        g,
        "Smoothed phishing rate of the public suffix in training folds only; NaN until fitted.",
        "own",
    )
    add(
        "is_hosting_platform",
        g,
        "The registrable domain is a shared hosting platform (it was masked before the other features).",
        "own",
    )
    return f


REGISTRY: tuple[Feature, ...] = tuple(_rows())
NAMES: tuple[str, ...] = tuple(f.name for f in REGISTRY)
GROUPS: tuple[str, ...] = tuple(dict.fromkeys(f.group for f in REGISTRY))

assert len(set(NAMES)) == len(NAMES), "duplicate feature name in registry"
