# Feature dictionary

Generated from `features/registry.py` by `python -m features dictionary`.
Do not edit by hand; a test fails when this file is stale.

99 tier A features, 84 tier B features and 29 tier C features.
Missing values are NaN, never 0. Each tier is a separate table with separate names:
a tier B or tier C column never appears in a tier A row.

Papers: **H** = Hannousse and Yahiouche 2021 (87 features); **P** = Prasad and Chandra 2024 (PhiUSIIL); **U** = UCI Phishing Websites (Mohammad et al. 2014); **own** = this project.

## Tier A: URL features (99)

URL only, all samples, computed in the browser. The URL is canonicalised first: scheme,
leading `www.`, fragment and trailing `/` are dropped, and a hosting-platform domain is
replaced by a neutral token (only `is_hosting_platform` is exposed).

### length (16)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `url_len` | Characters in the canonical URL (no scheme, no leading www., platform domain masked). | H,P,U | all samples | low | yes |
| `host_len` | Characters in the host. | H,P | all samples | low | yes |
| `domain_len` | Characters in the registrable domain (label + public suffix). | P | all samples | low | yes |
| `subdomain_len` | Characters in the subdomain part of the host (0 if none). | own | all samples | low | yes |
| `path_len` | Characters in the path. | H | all samples | low | yes |
| `query_len` | Characters in the query string. | H | all samples | low | yes |
| `tld_len` | Characters in the public suffix. | P | all samples | low | yes |
| `shortest_word_url` | Length of the shortest word in the URL; NaN if none. | H | all samples | low | yes |
| `longest_word_url` | Length of the longest word in the URL; NaN if none. | H | all samples | low | yes |
| `avg_word_url` | Mean word length in the URL; NaN if none. | H | all samples | low | yes |
| `shortest_word_host` | Length of the shortest word in the host; NaN if none. | H | all samples | low | yes |
| `longest_word_host` | Length of the longest word in the host; NaN if none. | H | all samples | low | yes |
| `avg_word_host` | Mean word length in the host; NaN if none. | H | all samples | low | yes |
| `shortest_word_path` | Length of the shortest word in the path; NaN if none. | H | all samples | low | yes |
| `longest_word_path` | Length of the longest word in the path; NaN if none. | H | all samples | low | yes |
| `avg_word_path` | Mean word length in the path; NaN if none. | H | all samples | low | yes |

### counts (27)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `n_dot` | Number of `.` characters in the URL. | H,P,U | all samples | low | yes |
| `n_hyphen` | Number of `-` characters in the URL. | H,P,U | all samples | low | yes |
| `n_underscore` | Number of `_` characters in the URL. | H,P,U | all samples | low | yes |
| `n_slash` | Number of `/` characters in the URL. | H,P,U | all samples | low | yes |
| `n_at` | Number of `@` characters in the URL. | H,P,U | all samples | low | yes |
| `n_qmark` | Number of `?` characters in the URL. | H,P,U | all samples | low | yes |
| `n_and` | Number of `&` characters in the URL. | H,P,U | all samples | low | yes |
| `n_eq` | Number of `=` characters in the URL. | H,P,U | all samples | low | yes |
| `n_percent` | Number of `%` characters in the URL. | H,P,U | all samples | low | yes |
| `n_tilde` | Number of `~` characters in the URL. | H,P,U | all samples | low | yes |
| `n_plus` | Number of `+` characters in the URL. | H,P,U | all samples | low | yes |
| `n_star` | Number of `*` characters in the URL. | H,P,U | all samples | low | yes |
| `n_colon` | Number of `:` characters in the URL. | H,P,U | all samples | low | yes |
| `n_comma` | Number of `,` characters in the URL. | H,P,U | all samples | low | yes |
| `n_semicolon` | Number of `;` characters in the URL. | H,P,U | all samples | low | yes |
| `n_dollar` | Number of `$` characters in the URL. | H,P,U | all samples | low | yes |
| `n_pipe` | Number of `\|` characters in the URL. | H,P,U | all samples | low | yes |
| `n_space` | Number of space characters in the URL. | H,P,U | all samples | low | yes |
| `host_n_dot` | Number of `.` in the host. | H | all samples | low | yes |
| `host_n_hyphen` | Number of `-` in the host. | H | all samples | low | yes |
| `n_digits` | Number of ASCII digits in the URL. | P | all samples | low | yes |
| `n_letters` | Number of ASCII letters in the URL. | P | all samples | low | yes |
| `n_subdomain_levels` | Number of labels in the subdomain (0 if none). | H,P | all samples | low | yes |
| `path_depth` | Non-empty `/`-separated path segments (same as the corpus depth). | H | all samples | low | yes |
| `n_query_params` | Number of `&`-separated query entries. | P | all samples | low | yes |
| `n_www_tokens` | Words equal to `www` in the host or path. | H | all samples | low | yes |
| `n_com_tokens` | Words equal to `com` in the host or path. | H | all samples | low | yes |

### ratios (6)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `digit_ratio_url` | Digits divided by length of the url. | H,P | all samples | low | yes |
| `letter_ratio_url` | Letters divided by length of the url. | P | all samples | low | yes |
| `special_ratio_url` | Non-alphanumeric characters divided by length of the url. | P | all samples | low | yes |
| `digit_ratio_host` | Digits divided by length of the host. | H,P | all samples | low | yes |
| `letter_ratio_host` | Letters divided by length of the host. | P | all samples | low | yes |
| `special_ratio_host` | Non-alphanumeric characters divided by length of the host. | P | all samples | low | yes |

### host_form (19)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `host_is_ip` | Host is an IPv4 or IPv6 address. | H,P,U | all samples | low | yes |
| `host_ip_obfuscated` | Host is a hex, octal or single-decimal-number IP. | H | all samples | low | yes |
| `has_port` | A port is written in the URL. | H | all samples | low | yes |
| `nonstandard_port` | A port other than 80 or 443 is written. | H,U | all samples | low | yes |
| `has_userinfo` | The URL has `user@` before the host. | H,U | all samples | low | yes |
| `has_punycode` | The host contains `xn--`. | H | all samples | low | yes |
| `has_non_ascii_host` | The host contains non-ASCII characters. | own | all samples | low | yes |
| `https_in_host` | The word `https` appears inside the host. | H,U | all samples | low | yes |
| `http_in_path` | The word `http` appears inside the path. | H | all samples | low | yes |
| `www_in_path` | The word `www` appears inside the path. | H | all samples | low | yes |
| `www_misplaced_host` | A `www` label appears in the host after the first position. | H | all samples | low | yes |
| `double_slash_in_path` | `//` appears in the path. | H,U | all samples | low | yes |
| `tld_in_path` | The last label of the public suffix is a word in the path. | H | all samples | low | yes |
| `tld_in_subdomain` | The last label of the public suffix is a label in the subdomain. | H | all samples | low | yes |
| `abnormal_subdomain` | More than 3 subdomain labels, or a label over 25 characters. | own | all samples | low | yes |
| `prefix_suffix_hyphen` | The registrable domain label contains `-`. | H,U | all samples | low | yes |
| `path_ext_present` | The last path segment has a file extension of 1 to 5 characters. | H | all samples | low | yes |
| `path_ext_is_script` | Extension is php, asp, aspx, jsp or cgi. | own | all samples | low | yes |
| `path_ext_is_html` | Extension is html, htm or shtml. | own | all samples | low | yes |

### obfuscation (5)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `n_pct_encoded` | Number of `%XX` escapes. | H | all samples | low | yes |
| `pct_encoded_ratio` | Characters in escapes divided by URL length. | H | all samples | low | yes |
| `longest_repeat_run` | Length of the longest run of one repeated character. | own | all samples | low | yes |
| `char_continuation_rate` | Longest run of one character class (letters, digits, other) divided by URL length. | P | all samples | low | yes |
| `n_non_ascii_url` | Number of non-ASCII characters in the URL. | own | all samples | low | yes |

### randomness (6)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `entropy_url` | Shannon entropy of the URL characters (bits). | P | all samples | low | yes |
| `entropy_domain` | Shannon entropy of the registrable domain label (bits). | H | all samples | low | yes |
| `bigram_loglik_domain` | Mean log probability of the domain label's character bigrams under a model fitted on training benign domains only; NaN until fitted. Doubles as the random-domain score. | own | all samples | low | yes |
| `domain_longest_consonant_run` | Longest run of consonants in the domain label. | own | all samples | low | yes |
| `domain_vowel_ratio` | Vowels divided by letters in the domain label; NaN if no letters. | own | all samples | low | yes |
| `domain_digit_switches` | Letter to digit or digit to letter changes in the domain label. | own | all samples | low | yes |

### words (8)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `n_suspicious_keywords` | Distinct suspicious keywords (login, verify, kyc, upi, ...) found in host, path or query. | H,P | all samples | low | yes |
| `kw_in_host` | Suspicious keywords found in the host (count of distinct keywords). | H | all samples | low | yes |
| `kw_in_path` | Suspicious keywords found in the path. | H | all samples | low | yes |
| `kw_in_query` | Suspicious keywords found in the query. | own | all samples | low | yes |
| `brand_in_subdomain` | Brand names found in the subdomain (count of distinct brands). | H | all samples | low | yes |
| `brand_in_path` | Brand names found in the path (count of distinct brands). | H | all samples | low | yes |
| `domain_is_brand` | The registrable domain label equals a brand name. | own | all samples | low | yes |
| `domain_contains_brand` | The domain label contains a brand name but is not equal to it. | own | all samples | low | yes |

### squatting (5)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `min_brand_edit_distance` | Smallest edit distance from the domain label to a brand name: 0, 1, 2, or 3 meaning 3 or more. | own | all samples | medium | yes |
| `homoglyph_brand_match` | The label equals a brand name only after look-alike characters are normalised (0 to o, 1 to l, rn to m, ...). | own | all samples | medium | yes |
| `combosquat_prefix` | The label is brand + hyphen + other words (`paypal-secure`). | own | all samples | low | yes |
| `combosquat_suffix` | The label is other words + hyphen + brand (`secure-paypal`). | own | all samples | low | yes |
| `combosquat_middle` | A brand is a hyphen-separated word in the middle of the label. | own | all samples | low | yes |

### other (7)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `is_shortener` | The registrable domain is a known URL shortener. | H | all samples | low | yes |
| `has_redirect_param` | The query has a redirect-style parameter (url, redirect, next, goto, ...). | own | all samples | low | yes |
| `has_embedded_url` | Another URL (`http://` or its %-encoded form) appears in the path or query. | H | all samples | low | yes |
| `has_embedded_email` | An email address appears in the path or query. | own | all samples | low | yes |
| `suspicious_tld` | The public suffix is on the abused-TLD list. | H | all samples | low | yes |
| `tld_risk` | Smoothed phishing rate of the public suffix in training folds only; NaN until fitted. | own | all samples | low | yes |
| `is_hosting_platform` | The registrable domain is a shared hosting platform (it was masked before the other features). | own | all samples | low | yes |

## Tier B: HTML features (84)

Samples with HTML only (content script in the browser). One pass of the standard library
HTML parser over the first 500,000 characters of the page. Every tier B value is NaN when
the page has no usable HTML: missing, under 200 characters of visible text, or an obvious
parked, takedown or error page. Ratios are NaN when their denominator is zero. Links,
resources and form actions are compared with the page's registrable domain after
platform-identity masking, so a hosting platform's name never reaches a feature. No
popularity or blocklist signal is used, and nothing is fetched.

### forms (17)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `n_forms` | Number of `<form>` elements. | H,P | samples with HTML | low | yes |
| `n_password_fields` | Number of `<input type=password>` elements. | P,U | samples with HTML | low | yes |
| `n_credential_forms` | Forms that contain at least one password field. | H | samples with HTML | low | yes |
| `n_password_outside_form` | Password fields that are not inside any form. | own | samples with HTML | low | yes |
| `n_password_forms_external` | Forms with a password field whose action posts to another registrable domain. | H | samples with HTML | low | yes |
| `n_input_hidden` | Number of `<input type=hidden>` elements. | H,P | samples with HTML | low | yes |
| `hidden_input_ratio` | Hidden inputs divided by all inputs; NaN if no inputs. | H | samples with HTML | low | yes |
| `has_submit_button` | A submit input, an image input or a submit `<button>` exists. | P | samples with HTML | low | yes |
| `n_form_action_empty` | Forms whose action is missing or blank. | H,U | samples with HTML | low | yes |
| `n_form_action_hash` | Forms whose action starts with `#`. | H,U | samples with HTML | low | yes |
| `n_form_action_js` | Forms whose action is a `javascript:` URL. | H,U | samples with HTML | low | yes |
| `n_form_action_mailto` | Forms whose action is a `mailto:` URL. | U | samples with HTML | low | yes |
| `n_form_action_external` | Forms whose action is a URL on another registrable domain. | H,U | samples with HTML | low | yes |
| `n_otp_fields` | Visible inputs whose name, id, placeholder or label mentions a one-time code. | own | samples with HTML | low | yes |
| `n_card_fields` | Visible inputs whose name, id, placeholder or label mentions a payment card (card number, cardholder, ...). | own | samples with HTML | low | yes |
| `n_cvv_fields` | Visible inputs that ask for a CVV, CVC or card security code. | own | samples with HTML | low | yes |
| `n_upi_pin_fields` | Visible inputs that ask for a UPI PIN, MPIN or ATM PIN. | own | samples with HTML | low | yes |

### links (11)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `n_links` | Number of `<a>` elements with an href. | H,P | samples with HTML | low | yes |
| `link_internal_ratio` | Share of links that stay on the page's domain (relative or same registrable domain); NaN if no links. | H,P | samples with HTML | low | yes |
| `link_external_ratio` | Share of links that go to another registrable domain; NaN if no links. | H,P | samples with HTML | low | yes |
| `link_null_ratio` | Share of links that go nowhere (empty, `#...`, `javascript:`); NaN if no links. | H,P,U | samples with HTML | low | yes |
| `n_external_link_domains` | Distinct other registrable domains linked from anchors. | own | samples with HTML | low | yes |
| `n_anchor_text_mismatch` | Links whose visible text is a domain different from the domain the href points to. | U | samples with HTML | low | yes |
| `n_links_insecure_http` | Links whose href is an absolute `http://` URL. | own | samples with HTML | low | yes |
| `n_links_ip_host` | Links whose host is an IP address. | own | samples with HTML | low | yes |
| `n_links_shortener` | Links to a known URL shortener. | own | samples with HTML | low | yes |
| `has_base_external` | A `<base href>` points to another registrable domain. | own | samples with HTML | low | yes |
| `meta_script_link_internal_ratio` | Share of URLs in `<meta content>`, `<script src>` and `<link href>` that stay on the page's domain; NaN if none. | H | samples with HTML | low | yes |

### resources (10)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `n_script_src` | Number of `<script src>` elements. | H | samples with HTML | low | yes |
| `script_external_ratio` | Share of script sources on another registrable domain; NaN if none. | H,P | samples with HTML | low | yes |
| `css_external_ratio` | Share of stylesheet links on another registrable domain; NaN if none. | H,P | samples with HTML | low | yes |
| `n_img` | Number of `<img>` elements with a source. | H | samples with HTML | low | yes |
| `img_external_ratio` | Share of image sources on another registrable domain; NaN if none. | H | samples with HTML | low | yes |
| `n_img_data_uri` | Images embedded as `data:` URIs. | own | samples with HTML | low | yes |
| `has_favicon` | A `<link rel=icon>` (any icon relation) is declared. | H,P | samples with HTML | low | yes |
| `favicon_external` | A declared favicon is on another registrable domain; NaN if no favicon is declared. | H,P | samples with HTML | low | yes |
| `resource_external_ratio` | Share of all scripts, stylesheets, images, media and frames on another registrable domain; NaN if none. | H | samples with HTML | low | yes |
| `n_external_resource_domains` | Distinct other registrable domains that supply resources. | own | samples with HTML | low | yes |

### text (17)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `has_title` | The page has a `<title>` element. | H,P | samples with HTML | low | yes |
| `title_empty` | The title element exists but is blank; NaN if there is no title element. | H,P | samples with HTML | low | yes |
| `title_has_credential_word` | The title contains a sign-in or verification word; NaN if no title text. | own | samples with HTML | medium | yes |
| `domain_in_title` | The domain label appears in the title (letters and digits only); NaN if no title text or the domain is an IP, a hosting platform or under 3 characters. | H | samples with HTML | medium | yes |
| `title_domain_match` | Share of the domain label's character trigrams found in the title; NaN as for `domain_in_title`. | P | samples with HTML | medium | yes |
| `url_title_match` | Share of title words (3+ characters) that appear in the masked URL; NaN if the title has none. | P | samples with HTML | medium | yes |
| `has_description` | A non-empty `<meta name=description>` exists. | P | samples with HTML | low | yes |
| `has_copyright` | The visible text contains a copyright sign, `copyright` or `all rights reserved`. | H,P | samples with HTML | low | yes |
| `domain_in_copyright` | The domain label appears in the text around the copyright notice; NaN if no notice or the domain label is not usable. | H | samples with HTML | medium | yes |
| `n_bank_words` | Occurrences of banking words and phrases in the visible text. | own | samples with HTML | medium | yes |
| `n_pay_words` | Occurrences of payment words and phrases in the visible text. | own | samples with HTML | medium | yes |
| `n_crypto_words` | Occurrences of cryptocurrency words and phrases in the visible text. | own | samples with HTML | medium | yes |
| `n_urgency_words` | Occurrences of urgency and threat phrases in the visible text. | own | samples with HTML | medium | yes |
| `n_credential_words` | Occurrences of sign-in words (login, password, OTP, ...) in the visible text. | own | samples with HTML | medium | yes |
| `brand_in_title_mismatch` | A brand name from the brand list is in the title but the page's own domain label is not that brand; NaN if no title text or no brand list. | own | samples with HTML | medium | yes |
| `n_brands_in_text_mismatch` | Distinct brands mentioned at least twice in the visible text where the page's own domain label is not that brand; NaN if no brand list. | own | samples with HTML | medium | yes |
| `n_social_links` | Links to well-known social networks. | H | samples with HTML | low | yes |

### structure (17)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `page_size` | Characters in the HTML before truncation to the first 500,000. | H,P | samples with HTML | low | yes |
| `n_lines` | Lines of HTML (first 500,000 characters). | H,P | samples with HTML | low | yes |
| `longest_line` | Characters in the longest line (first 500,000 characters). | P | samples with HTML | low | yes |
| `visible_text_len` | Characters of visible text after collapsing whitespace (script, style, noscript and title excluded). | H | samples with HTML | low | yes |
| `text_to_code_ratio` | Visible text characters divided by HTML characters. | H,P | samples with HTML | low | yes |
| `n_tags` | Number of start tags. | own | samples with HTML | low | yes |
| `max_dom_depth` | Deepest nesting of open elements, estimated from start and end tags (capped at 512). | own | samples with HTML | low | yes |
| `n_iframes` | Number of `<iframe>` and `<frame>` elements. | H,P,U | samples with HTML | low | yes |
| `n_hidden_iframes` | Frames that are hidden (0 or 1 pixel, `display:none`, `visibility:hidden` or `hidden`). | H,U | samples with HTML | low | yes |
| `has_meta_refresh` | A `<meta http-equiv=refresh>` exists. | H | samples with HTML | low | yes |
| `meta_refresh_external` | The refresh target is on another registrable domain; NaN if there is no refresh. | H | samples with HTML | low | yes |
| `right_click_disabled` | The page blocks the context menu (`oncontextmenu` returning false, or a script that cancels `contextmenu`). | H,U | samples with HTML | low | yes |
| `n_onmouseover` | Elements with an `onmouseover` attribute (status-bar tricks). | H,U | samples with HTML | low | yes |
| `n_window_open` | Calls to `window.open(` in scripts and inline handlers (popups). | H,U | samples with HTML | medium | yes |
| `n_js_redirects` | Assignments to `location` / `location.href` and calls to `location.replace` or `location.assign` in scripts. | H | samples with HTML | medium | yes |
| `has_viewport_meta` | A `<meta name=viewport>` exists (responsive page). | P | samples with HTML | low | yes |
| `robots_noindex` | A robots meta tag contains `noindex`. | own | samples with HTML | low | yes |

### scripts (12)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `n_scripts_inline` | Inline JavaScript blocks with content. | H,P | samples with HTML | low | yes |
| `script_chars_ratio` | Characters of inline JavaScript divided by HTML characters. | P | samples with HTML | low | yes |
| `n_eval` | Calls to `eval(` and `new Function(` in scripts and inline handlers. | H | samples with HTML | medium | yes |
| `n_atob` | Calls to `atob(` in scripts and inline handlers. | own | samples with HTML | medium | yes |
| `n_unescape` | Calls to `unescape(` in scripts and inline handlers. | own | samples with HTML | medium | yes |
| `n_document_write` | Calls to `document.write(` and `document.writeln(`. | H | samples with HTML | medium | yes |
| `n_fromcharcode` | Uses of `String.fromCharCode`. | own | samples with HTML | medium | yes |
| `script_entropy` | Shannon entropy (bits) of the first 50,000 characters of inline JavaScript; NaN if under 100 characters of script. | own | samples with HTML | medium | yes |
| `script_escape_ratio` | Share of inline JavaScript characters that sit inside `\xNN`, `\uNNNN` or octal escapes; NaN if no inline script. | own | samples with HTML | medium | yes |
| `n_ajax_calls` | Uses of XMLHttpRequest, `fetch(`, jQuery ajax/post and `sendBeacon`. | own | samples with HTML | medium | yes |
| `n_telegram_endpoints` | Mentions of the Telegram bot API (`api.telegram.org`) in scripts and form actions. | own | samples with HTML | medium | yes |
| `n_webhook_endpoints` | Mentions of Discord and Slack webhooks, webhook.site, form relays and similar endpoints in scripts and form actions. | own | samples with HTML | medium | yes |

## Tier C: domain, DNS and TLS features (29)

Live-feed hosts only, captured once when the host first appeared in a feed
(`collector/domain_capture.py`); never computed later for old dataset URLs. Computed on
the backend, not in the browser. Ages are in days relative to the host's capture time.
Missing is NaN: no RDAP data, a DNS query that errored for that record type, or a TLS
handshake without a certificate (certificate fields exist only for a verified
handshake). Liveness facts (whether the host still resolves) are not features, and no
popularity or blocklist signal is used.

### registration (8)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `domain_age_days` | Days from the RDAP registration date to the capture. | H,U | live-feed hosts at first-seen | high | no |
| `days_to_expiry` | Days from the capture to the RDAP expiration date. | H,U | live-feed hosts at first-seen | high | no |
| `registration_length_days` | Days between the RDAP registration and expiration dates. | U | live-feed hosts at first-seen | high | no |
| `days_since_rdap_change` | Days from the RDAP `last changed` event to the capture. | own | live-feed hosts at first-seen | high | no |
| `rdap_found` | 1 if RDAP returned the domain, 0 if it answered 404 (not registered, or no RDAP server for the TLD), NaN for any other error (rate limit, timeout). | H | live-feed hosts at first-seen | high | no |
| `whois_redacted` | RDAP registrant data is redacted for privacy (or the registrar is a privacy service). | own | live-feed hosts at first-seen | high | no |
| `rdap_status_count` | Number of RDAP status values (EPP locks, holds, add period). | own | live-feed hosts at first-seen | high | no |
| `rdap_client_hold` | RDAP status contains `client hold` or `server hold` (the domain is suspended). | own | live-feed hosts at first-seen | high | no |

### dns (11)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `n_a` | A records of the host. | own | live-feed hosts at first-seen | high | no |
| `n_aaaa` | AAAA records of the host. | own | live-feed hosts at first-seen | high | no |
| `has_cname` | The host has a CNAME record. | own | live-feed hosts at first-seen | high | no |
| `mx_count` | MX records of the registrable domain. | own | live-feed hosts at first-seen | high | no |
| `has_mx` | The registrable domain has at least one MX record. | own | live-feed hosts at first-seen | high | no |
| `has_spf` | A TXT record of the registrable domain starts an SPF policy (`v=spf1`). | own | live-feed hosts at first-seen | high | no |
| `has_dmarc` | `_dmarc.<registrable domain>` has a DMARC TXT record. | own | live-feed hosts at first-seen | high | no |
| `n_ns` | NS records of the registrable domain (`dns_record` in H counts any record). | H | live-feed hosts at first-seen | high | no |
| `ns_in_own_domain` | A name server lies inside the host's own registrable domain; NaN with no NS records. | own | live-feed hosts at first-seen | high | no |
| `ns_cloudflare` | A name server is a Cloudflare one (`*.ns.cloudflare.com`); NaN with no NS records. | own | live-feed hosts at first-seen | high | no |
| `min_ttl_s` | Smallest TTL (seconds) among the A, AAAA, CNAME, NS and MX answers. | own | live-feed hosts at first-seen | high | no |

### tls (10)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `tls_ok` | A TLS handshake with port 443 completed (1) or failed (0); NaN when the name could not be looked up for the handshake. | own | live-feed hosts at first-seen | high | no |
| `tls_verified` | The certificate verified for the host; NaN if no handshake. | U | live-feed hosts at first-seen | high | no |
| `cert_free_issuer` | Issuer organisation or common name is a free automated CA (Let's Encrypt, ZeroSSL, Buypass, cPanel, Google Trust Services, Cloudflare). | U | live-feed hosts at first-seen | high | no |
| `cert_validity_days` | Days between the certificate's notBefore and notAfter. | own | live-feed hosts at first-seen | high | no |
| `cert_age_days` | Days from the certificate's notBefore to the capture. | own | live-feed hosts at first-seen | high | no |
| `cert_days_left` | Days from the capture to the certificate's notAfter. | own | live-feed hosts at first-seen | high | no |
| `cert_san_count` | DNS names in the certificate's subjectAltName. | own | live-feed hosts at first-seen | high | no |
| `cert_wildcard` | A subjectAltName or the subject common name is a wildcard (`*.`). | own | live-feed hosts at first-seen | high | no |
| `cert_cn_matches_host` | The subject common name equals the host or is a wildcard covering it (one label). | own | live-feed hosts at first-seen | high | no |
| `brand_in_cert_sans` | A brand from the brand list (4+ letters) appears inside a label of a subjectAltName whose registrable domain is not the brand's own. | own | live-feed hosts at first-seen | high | no |
