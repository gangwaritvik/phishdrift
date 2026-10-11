# Feature dictionary

Generated from `features/registry.py` by `python -m features dictionary`.
Do not edit by hand; a test fails when this file is stale.

99 features. Missing values are NaN, never 0. All features here are tier A
(URL only, all samples, computed in the browser). The URL is canonicalised first: scheme,
leading `www.`, fragment and trailing `/` are dropped, and a hosting-platform domain is
replaced by a neutral token (only `is_hosting_platform` is exposed).

Papers: **H** = Hannousse and Yahiouche 2021 (87 features); **P** = Prasad and Chandra 2024 (PhiUSIIL); **U** = UCI Phishing Websites (Mohammad et al. 2014); **own** = this project.

## length (16)

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

## counts (27)

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

## ratios (6)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `digit_ratio_url` | Digits divided by length of the url. | H,P | all samples | low | yes |
| `letter_ratio_url` | Letters divided by length of the url. | P | all samples | low | yes |
| `special_ratio_url` | Non-alphanumeric characters divided by length of the url. | P | all samples | low | yes |
| `digit_ratio_host` | Digits divided by length of the host. | H,P | all samples | low | yes |
| `letter_ratio_host` | Letters divided by length of the host. | P | all samples | low | yes |
| `special_ratio_host` | Non-alphanumeric characters divided by length of the host. | P | all samples | low | yes |

## host_form (19)

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

## obfuscation (5)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `n_pct_encoded` | Number of `%XX` escapes. | H | all samples | low | yes |
| `pct_encoded_ratio` | Characters in escapes divided by URL length. | H | all samples | low | yes |
| `longest_repeat_run` | Length of the longest run of one repeated character. | own | all samples | low | yes |
| `char_continuation_rate` | Longest run of one character class (letters, digits, other) divided by URL length. | P | all samples | low | yes |
| `n_non_ascii_url` | Number of non-ASCII characters in the URL. | own | all samples | low | yes |

## randomness (6)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `entropy_url` | Shannon entropy of the URL characters (bits). | P | all samples | low | yes |
| `entropy_domain` | Shannon entropy of the registrable domain label (bits). | H | all samples | low | yes |
| `bigram_loglik_domain` | Mean log probability of the domain label's character bigrams under a model fitted on training benign domains only; NaN until fitted. Doubles as the random-domain score. | own | all samples | low | yes |
| `domain_longest_consonant_run` | Longest run of consonants in the domain label. | own | all samples | low | yes |
| `domain_vowel_ratio` | Vowels divided by letters in the domain label; NaN if no letters. | own | all samples | low | yes |
| `domain_digit_switches` | Letter to digit or digit to letter changes in the domain label. | own | all samples | low | yes |

## words (8)

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

## squatting (5)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `min_brand_edit_distance` | Smallest edit distance from the domain label to a brand name: 0, 1, 2, or 3 meaning 3 or more. | own | all samples | medium | yes |
| `homoglyph_brand_match` | The label equals a brand name only after look-alike characters are normalised (0 to o, 1 to l, rn to m, ...). | own | all samples | medium | yes |
| `combosquat_prefix` | The label is brand + hyphen + other words (`paypal-secure`). | own | all samples | low | yes |
| `combosquat_suffix` | The label is other words + hyphen + brand (`secure-paypal`). | own | all samples | low | yes |
| `combosquat_middle` | A brand is a hyphen-separated word in the middle of the label. | own | all samples | low | yes |

## other (7)

| name | definition | papers | availability | cost | in browser |
|---|---|---|---|---|---|
| `is_shortener` | The registrable domain is a known URL shortener. | H | all samples | low | yes |
| `has_redirect_param` | The query has a redirect-style parameter (url, redirect, next, goto, ...). | own | all samples | low | yes |
| `has_embedded_url` | Another URL (`http://` or its %-encoded form) appears in the path or query. | H | all samples | low | yes |
| `has_embedded_email` | An email address appears in the path or query. | own | all samples | low | yes |
| `suspicious_tld` | The public suffix is on the abused-TLD list. | H | all samples | low | yes |
| `tld_risk` | Smoothed phishing rate of the public suffix in training folds only; NaN until fitted. | own | all samples | low | yes |
| `is_hosting_platform` | The registrable domain is a shared hosting platform (it was masked before the other features). | own | all samples | low | yes |
