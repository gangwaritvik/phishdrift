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


def _rows_b() -> list[Feature]:
    """Tier B: features of the page HTML (``features/html_features.py``).

    Every value is NaN when the page has no usable HTML (missing, under 200 characters of visible
    text, or an obvious parked / takedown / error page). Ratios are NaN when their denominator is
    zero. "The domain" means the registrable domain after platform-identity masking.
    """
    f: list[Feature] = []

    def add(name: str, group: str, definition: str, papers: str = "own", cost: str = "low"):
        f.append(
            Feature(
                name,
                group,
                definition,
                papers,
                tier="B",
                availability="samples with HTML",
                runtime_cost=cost,
                in_browser=True,
            )
        )

    g = "forms"
    add("n_forms", g, "Number of `<form>` elements.", "H,P")
    add("n_password_fields", g, "Number of `<input type=password>` elements.", "P,U")
    add("n_credential_forms", g, "Forms that contain at least one password field.", "H")
    add("n_password_outside_form", g, "Password fields that are not inside any form.", "own")
    add(
        "n_password_forms_external",
        g,
        "Forms with a password field whose action posts to another registrable domain.",
        "H",
    )
    add("n_input_hidden", g, "Number of `<input type=hidden>` elements.", "H,P")
    add("hidden_input_ratio", g, "Hidden inputs divided by all inputs; NaN if no inputs.", "H")
    add(
        "has_submit_button", g, "A submit input, an image input or a submit `<button>` exists.", "P"
    )
    add("n_form_action_empty", g, "Forms whose action is missing or blank.", "H,U")
    add("n_form_action_hash", g, "Forms whose action starts with `#`.", "H,U")
    add("n_form_action_js", g, "Forms whose action is a `javascript:` URL.", "H,U")
    add("n_form_action_mailto", g, "Forms whose action is a `mailto:` URL.", "U")
    add(
        "n_form_action_external",
        g,
        "Forms whose action is a URL on another registrable domain.",
        "H,U",
    )
    add(
        "n_otp_fields",
        g,
        "Visible inputs whose name, id, placeholder or label mentions a one-time code.",
        "own",
    )
    add(
        "n_card_fields",
        g,
        "Visible inputs whose name, id, placeholder or label mentions a payment card (card number, cardholder, ...).",
        "own",
    )
    add("n_cvv_fields", g, "Visible inputs that ask for a CVV, CVC or card security code.", "own")
    add("n_upi_pin_fields", g, "Visible inputs that ask for a UPI PIN, MPIN or ATM PIN.", "own")

    g = "links"
    add("n_links", g, "Number of `<a>` elements with an href.", "H,P")
    add(
        "link_internal_ratio",
        g,
        "Share of links that stay on the page's domain (relative or same registrable domain); NaN if no links.",
        "H,P",
    )
    add(
        "link_external_ratio",
        g,
        "Share of links that go to another registrable domain; NaN if no links.",
        "H,P",
    )
    add(
        "link_null_ratio",
        g,
        "Share of links that go nowhere (empty, `#...`, `javascript:`); NaN if no links.",
        "H,P,U",
    )
    add(
        "n_external_link_domains",
        g,
        "Distinct other registrable domains linked from anchors.",
        "own",
    )
    add(
        "n_anchor_text_mismatch",
        g,
        "Links whose visible text is a domain different from the domain the href points to.",
        "U",
    )
    add("n_links_insecure_http", g, "Links whose href is an absolute `http://` URL.", "own")
    add("n_links_ip_host", g, "Links whose host is an IP address.", "own")
    add("n_links_shortener", g, "Links to a known URL shortener.", "own")
    add("has_base_external", g, "A `<base href>` points to another registrable domain.", "own")
    add(
        "meta_script_link_internal_ratio",
        g,
        "Share of URLs in `<meta content>`, `<script src>` and `<link href>` that stay on the page's domain; NaN if none.",
        "H",
    )

    g = "resources"
    add("n_script_src", g, "Number of `<script src>` elements.", "H")
    add(
        "script_external_ratio",
        g,
        "Share of script sources on another registrable domain; NaN if none.",
        "H,P",
    )
    add(
        "css_external_ratio",
        g,
        "Share of stylesheet links on another registrable domain; NaN if none.",
        "H,P",
    )
    add("n_img", g, "Number of `<img>` elements with a source.", "H")
    add(
        "img_external_ratio",
        g,
        "Share of image sources on another registrable domain; NaN if none.",
        "H",
    )
    add("n_img_data_uri", g, "Images embedded as `data:` URIs.", "own")
    add("has_favicon", g, "A `<link rel=icon>` (any icon relation) is declared.", "H,P")
    add(
        "favicon_external",
        g,
        "A declared favicon is on another registrable domain; NaN if no favicon is declared.",
        "H,P",
    )
    add(
        "resource_external_ratio",
        g,
        "Share of all scripts, stylesheets, images, media and frames on another registrable domain; NaN if none.",
        "H",
    )
    add(
        "n_external_resource_domains",
        g,
        "Distinct other registrable domains that supply resources.",
        "own",
    )

    g = "text"
    add("has_title", g, "The page has a `<title>` element.", "H,P")
    add(
        "title_empty",
        g,
        "The title element exists but is blank; NaN if there is no title element.",
        "H,P",
    )
    add(
        "title_has_credential_word",
        g,
        "The title contains a sign-in or verification word; NaN if no title text.",
        "own",
        "medium",
    )
    add(
        "domain_in_title",
        g,
        "The domain label appears in the title (letters and digits only); NaN if no title text or the domain is an IP, a hosting platform or under 3 characters.",
        "H",
        "medium",
    )
    add(
        "title_domain_match",
        g,
        "Share of the domain label's character trigrams found in the title; NaN as for `domain_in_title`.",
        "P",
        "medium",
    )
    add(
        "url_title_match",
        g,
        "Share of title words (3+ characters) that appear in the masked URL; NaN if the title has none.",
        "P",
        "medium",
    )
    add("has_description", g, "A non-empty `<meta name=description>` exists.", "P")
    add(
        "has_copyright",
        g,
        "The visible text contains a copyright sign, `copyright` or `all rights reserved`.",
        "H,P",
    )
    add(
        "domain_in_copyright",
        g,
        "The domain label appears in the text around the copyright notice; NaN if no notice or the domain label is not usable.",
        "H",
        "medium",
    )
    add(
        "n_bank_words",
        g,
        "Occurrences of banking words and phrases in the visible text.",
        "own",
        "medium",
    )
    add(
        "n_pay_words",
        g,
        "Occurrences of payment words and phrases in the visible text.",
        "own",
        "medium",
    )
    add(
        "n_crypto_words",
        g,
        "Occurrences of cryptocurrency words and phrases in the visible text.",
        "own",
        "medium",
    )
    add(
        "n_urgency_words",
        g,
        "Occurrences of urgency and threat phrases in the visible text.",
        "own",
        "medium",
    )
    add(
        "n_credential_words",
        g,
        "Occurrences of sign-in words (login, password, OTP, ...) in the visible text.",
        "own",
        "medium",
    )
    add(
        "brand_in_title_mismatch",
        g,
        "A brand name from the brand list is in the title but the page's own domain label is not that brand; NaN if no title text or no brand list.",
        "own",
        "medium",
    )
    add(
        "n_brands_in_text_mismatch",
        g,
        "Distinct brands mentioned at least twice in the visible text where the page's own domain label is not that brand; NaN if no brand list.",
        "own",
        "medium",
    )
    add("n_social_links", g, "Links to well-known social networks.", "H")

    g = "structure"
    add("page_size", g, "Characters in the HTML before truncation to the first 500,000.", "H,P")
    add("n_lines", g, "Lines of HTML (first 500,000 characters).", "H,P")
    add("longest_line", g, "Characters in the longest line (first 500,000 characters).", "P")
    add(
        "visible_text_len",
        g,
        "Characters of visible text after collapsing whitespace (script, style, noscript and title excluded).",
        "H",
    )
    add("text_to_code_ratio", g, "Visible text characters divided by HTML characters.", "H,P")
    add("n_tags", g, "Number of start tags.", "own")
    add(
        "max_dom_depth",
        g,
        "Deepest nesting of open elements, estimated from start and end tags (capped at 512).",
        "own",
    )
    add("n_iframes", g, "Number of `<iframe>` and `<frame>` elements.", "H,P,U")
    add(
        "n_hidden_iframes",
        g,
        "Frames that are hidden (0 or 1 pixel, `display:none`, `visibility:hidden` or `hidden`).",
        "H,U",
    )
    add("has_meta_refresh", g, "A `<meta http-equiv=refresh>` exists.", "H")
    add(
        "meta_refresh_external",
        g,
        "The refresh target is on another registrable domain; NaN if there is no refresh.",
        "H",
    )
    add(
        "right_click_disabled",
        g,
        "The page blocks the context menu (`oncontextmenu` returning false, or a script that cancels `contextmenu`).",
        "H,U",
    )
    add("n_onmouseover", g, "Elements with an `onmouseover` attribute (status-bar tricks).", "H,U")
    add(
        "n_window_open",
        g,
        "Calls to `window.open(` in scripts and inline handlers (popups).",
        "H,U",
        "medium",
    )
    add(
        "n_js_redirects",
        g,
        "Assignments to `location` / `location.href` and calls to `location.replace` or `location.assign` in scripts.",
        "H",
        "medium",
    )
    add("has_viewport_meta", g, "A `<meta name=viewport>` exists (responsive page).", "P")
    add("robots_noindex", g, "A robots meta tag contains `noindex`.", "own")

    g = "scripts"
    add("n_scripts_inline", g, "Inline JavaScript blocks with content.", "H,P")
    add("script_chars_ratio", g, "Characters of inline JavaScript divided by HTML characters.", "P")
    add(
        "n_eval",
        g,
        "Calls to `eval(` and `new Function(` in scripts and inline handlers.",
        "H",
        "medium",
    )
    add("n_atob", g, "Calls to `atob(` in scripts and inline handlers.", "own", "medium")
    add("n_unescape", g, "Calls to `unescape(` in scripts and inline handlers.", "own", "medium")
    add("n_document_write", g, "Calls to `document.write(` and `document.writeln(`.", "H", "medium")
    add("n_fromcharcode", g, "Uses of `String.fromCharCode`.", "own", "medium")
    add(
        "script_entropy",
        g,
        "Shannon entropy (bits) of the first 50,000 characters of inline JavaScript; NaN if under 100 characters of script.",
        "own",
        "medium",
    )
    add(
        "script_escape_ratio",
        g,
        "Share of inline JavaScript characters that sit inside `\\xNN`, `\\uNNNN` or octal escapes; NaN if no inline script.",
        "own",
        "medium",
    )
    add(
        "n_ajax_calls",
        g,
        "Uses of XMLHttpRequest, `fetch(`, jQuery ajax/post and `sendBeacon`.",
        "own",
        "medium",
    )
    add(
        "n_telegram_endpoints",
        g,
        "Mentions of the Telegram bot API (`api.telegram.org`) in scripts and form actions.",
        "own",
        "medium",
    )
    add(
        "n_webhook_endpoints",
        g,
        "Mentions of Discord and Slack webhooks, webhook.site, form relays and similar endpoints in scripts and form actions.",
        "own",
        "medium",
    )
    return f


C_AVAILABILITY = "live-feed hosts at first-seen"


def _rows_c() -> list[Feature]:
    """Tier C: registration, DNS and TLS facts of a live-feed host (``features/domain_features.py``).

    Captured once, when the host first appeared in a feed (``collector/domain_capture.py``);
    never computed later for old URLs. Every age is in days relative to the host's capture
    time. Missing is NaN: no RDAP data, a DNS query that errored for that record type, or a TLS
    handshake that gave no certificate (certificate fields exist only for a verified handshake).
    """
    f: list[Feature] = []

    def add(name: str, group: str, definition: str, papers: str = "own"):
        f.append(
            Feature(
                name,
                group,
                definition,
                papers,
                tier="C",
                availability=C_AVAILABILITY,
                runtime_cost="high",
                in_browser=False,
            )
        )

    g = "registration"
    add("domain_age_days", g, "Days from the RDAP registration date to the capture.", "H,U")
    add("days_to_expiry", g, "Days from the capture to the RDAP expiration date.", "H,U")
    add(
        "registration_length_days",
        g,
        "Days between the RDAP registration and expiration dates.",
        "U",
    )
    add("days_since_rdap_change", g, "Days from the RDAP `last changed` event to the capture.")
    add(
        "rdap_found",
        g,
        "1 if RDAP returned the domain, 0 if it answered 404 (not registered, or no RDAP server "
        "for the TLD), NaN for any other error (rate limit, timeout).",
        "H",
    )
    add(
        "whois_redacted",
        g,
        "RDAP registrant data is redacted for privacy (or the registrar is a privacy service).",
    )
    add("rdap_status_count", g, "Number of RDAP status values (EPP locks, holds, add period).")
    add(
        "rdap_client_hold",
        g,
        "RDAP status contains `client hold` or `server hold` (the domain is suspended).",
    )

    g = "dns"
    add("n_a", g, "A records of the host.")
    add("n_aaaa", g, "AAAA records of the host.")
    add("has_cname", g, "The host has a CNAME record.")
    add("mx_count", g, "MX records of the registrable domain.")
    add("has_mx", g, "The registrable domain has at least one MX record.")
    add("has_spf", g, "A TXT record of the registrable domain starts an SPF policy (`v=spf1`).")
    add("has_dmarc", g, "`_dmarc.<registrable domain>` has a DMARC TXT record.")
    add(
        "n_ns",
        g,
        "NS records of the registrable domain (`dns_record` in H counts any record).",
        "H",
    )
    add(
        "ns_in_own_domain",
        g,
        "A name server lies inside the host's own registrable domain; NaN with no NS records.",
    )
    add(
        "ns_cloudflare",
        g,
        "A name server is a Cloudflare one (`*.ns.cloudflare.com`); NaN with no NS records.",
    )
    add("min_ttl_s", g, "Smallest TTL (seconds) among the A, AAAA, CNAME, NS and MX answers.")

    g = "tls"
    add(
        "tls_ok",
        g,
        "A TLS handshake with port 443 completed (1) or failed (0); NaN when the name could not "
        "be looked up for the handshake.",
    )
    add("tls_verified", g, "The certificate verified for the host; NaN if no handshake.", "U")
    add(
        "cert_free_issuer",
        g,
        "Issuer organisation or common name is a free automated CA (Let's Encrypt, ZeroSSL, "
        "Buypass, cPanel, Google Trust Services, Cloudflare).",
        "U",
    )
    add("cert_validity_days", g, "Days between the certificate's notBefore and notAfter.")
    add("cert_age_days", g, "Days from the certificate's notBefore to the capture.")
    add("cert_days_left", g, "Days from the capture to the certificate's notAfter.")
    add("cert_san_count", g, "DNS names in the certificate's subjectAltName.")
    add("cert_wildcard", g, "A subjectAltName or the subject common name is a wildcard (`*.`).")
    add(
        "cert_cn_matches_host",
        g,
        "The subject common name equals the host or is a wildcard covering it (one label).",
    )
    add(
        "brand_in_cert_sans",
        g,
        "A brand from the brand list (4+ letters) appears inside a label of a subjectAltName "
        "whose registrable domain is not the brand's own.",
    )
    return f


# Tier A is the default everywhere (REGISTRY, NAMES, GROUPS); models and experiments read only
# these. Tier B has its own names so a tier B column can never leak into a tier A table.
REGISTRY: tuple[Feature, ...] = tuple(_rows())
NAMES: tuple[str, ...] = tuple(f.name for f in REGISTRY)
GROUPS: tuple[str, ...] = tuple(dict.fromkeys(f.group for f in REGISTRY))

REGISTRY_B: tuple[Feature, ...] = tuple(_rows_b())
NAMES_B: tuple[str, ...] = tuple(f.name for f in REGISTRY_B)
GROUPS_B: tuple[str, ...] = tuple(dict.fromkeys(f.group for f in REGISTRY_B))

REGISTRY_C: tuple[Feature, ...] = tuple(_rows_c())
NAMES_C: tuple[str, ...] = tuple(f.name for f in REGISTRY_C)
GROUPS_C: tuple[str, ...] = tuple(dict.fromkeys(f.group for f in REGISTRY_C))

assert len(set(NAMES)) == len(NAMES), "duplicate feature name in registry"
assert len(set(NAMES_B)) == len(NAMES_B), "duplicate tier B feature name in registry"
assert len(set(NAMES_C)) == len(NAMES_C), "duplicate tier C feature name in registry"
assert not set(NAMES) & set(NAMES_B), "a name is registered in both tier A and tier B"
assert not set(GROUPS) & set(GROUPS_B), "a group is used by both tier A and tier B"
assert not set(NAMES_C) & (set(NAMES) | set(NAMES_B)), "a tier C name is also in tier A or B"
assert not set(GROUPS_C) & (set(GROUPS) | set(GROUPS_B)), "a tier C group is also in tier A or B"
