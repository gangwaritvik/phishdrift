"""Tier A: URL-only features. Every name is declared in ``features/registry.py``.

Each group is one function of the parsed URL; a value that cannot be computed is NaN, never 0.
Written with plain loops and string operations so the JavaScript port is mechanical.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from features.fit import Fitted
from features.lists import Lists
from features.registry import CHARS
from features.urlparts import Parts, words

NAN = float("nan")
_VOWELS = "aeiou"
_PCT = re.compile(r"%[0-9a-fA-F]{2}")
_EMAIL = re.compile(r"[a-z0-9._+\-]+@[a-z0-9\-]+\.[a-z]{2,}")
_EMBEDDED = re.compile(r"https?(?:://|%3a%2f%2f|%253a%252f%252f)")
_EXT = re.compile(r"\.([a-z0-9]{1,5})$")
_SCRIPT_EXT = {"php", "asp", "aspx", "jsp", "cgi"}
_HTML_EXT = {"html", "htm", "shtml"}
# Look-alike characters mapped to the letter they imitate (applied to the domain label).
_HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ı": "i", "ɡ": "g", "ɑ": "a", "ο": "o", "ν": "v",
}  # fmt: skip
_HOMOGLYPH_SEQ = (("rn", "m"), ("vv", "w"), ("cl", "d"))


def _entropy(text: str) -> float:
    if not text:
        return NAN
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


def _word_stats(ws: list[str]) -> tuple[float, float, float]:
    if not ws:
        return NAN, NAN, NAN
    lens = [len(w) for w in ws]
    return float(min(lens)), float(max(lens)), sum(lens) / len(lens)


def _is_digit(c: str) -> bool:
    return "0" <= c <= "9"


def _is_letter(c: str) -> bool:
    return "a" <= c.lower() <= "z"


def _ratio(count: int, total: int) -> float:
    return count / total if total else NAN


def _longest_run(text: str, same) -> int:
    best = run = 0
    prev = None
    for ch in text:
        run = run + 1 if prev is not None and same(prev, ch) else 1
        best = max(best, run)
        prev = ch
    return best


def _char_class(c: str) -> int:
    return 0 if _is_letter(c) else 1 if _is_digit(c) else 2


def edit_distance(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def normalise_homoglyphs(label: str) -> str:
    out = "".join(_HOMOGLYPHS.get(c, c) for c in label)
    for src, dst in _HOMOGLYPH_SEQ:
        out = out.replace(src, dst)
    return out


def length_group(p: Parts) -> dict[str, float]:
    out = {
        "url_len": len(p.canon),
        "host_len": len(p.host),
        "domain_len": len(p.domain),
        "subdomain_len": len(p.subdomain),
        "path_len": len(p.path),
        "query_len": len(p.query),
        "tld_len": len(p.suffix),
    }
    for scope, text in (("url", p.canon), ("host", p.host), ("path", p.path)):
        lo, hi, avg = _word_stats(words(text))
        out[f"shortest_word_{scope}"] = lo
        out[f"longest_word_{scope}"] = hi
        out[f"avg_word_{scope}"] = avg
    return out


def counts_group(p: Parts) -> dict[str, float]:
    out = {f"n_{key}": p.canon.count(ch) for key, ch in CHARS.items()}
    out["host_n_dot"] = p.host.count(".")
    out["host_n_hyphen"] = p.host.count("-")
    out["n_digits"] = sum(_is_digit(c) for c in p.canon)
    out["n_letters"] = sum(_is_letter(c) for c in p.canon)
    out["n_subdomain_levels"] = len(p.subdomain.split(".")) if p.subdomain else 0
    out["path_depth"] = sum(1 for seg in p.path.split("/") if seg)
    out["n_query_params"] = sum(1 for kv in p.query.split("&") if kv)
    tokens = words(p.host) + words(p.path)
    out["n_www_tokens"] = tokens.count("www")
    out["n_com_tokens"] = tokens.count("com")
    return out


def ratios_group(p: Parts) -> dict[str, float]:
    out = {}
    for scope, text in (("url", p.canon), ("host", p.host)):
        n = len(text)
        digits = sum(_is_digit(c) for c in text)
        letters = sum(_is_letter(c) for c in text)
        out[f"digit_ratio_{scope}"] = _ratio(digits, n)
        out[f"letter_ratio_{scope}"] = _ratio(letters, n)
        out[f"special_ratio_{scope}"] = _ratio(n - digits - letters, n)
    return out


def _ip_obfuscated(host: str) -> bool:
    if host.startswith("0x") and all(c in "0123456789abcdef" for c in host[2:]) and host[2:]:
        return True
    if host.isdigit() and len(host) >= 8:
        return True
    parts = host.split(".")
    if len(parts) == 4 and all(x.isdigit() or x.startswith("0x") for x in parts):
        return any(len(x) > 1 and (x.startswith("0")) for x in parts)
    return False


def host_form_group(p: Parts) -> dict[str, float]:
    sub_labels = p.subdomain.split(".") if p.subdomain else []
    last_tld = p.suffix.rsplit(".", 1)[-1] if p.suffix else ""
    path_words = words(p.path)
    seg = p.path.rsplit("/", 1)[-1]
    ext_m = _EXT.search(seg.lower())
    ext = ext_m.group(1) if ext_m else ""
    host_labels = p.host.split(".")
    return {
        "host_is_ip": float(p.is_ip),
        "host_ip_obfuscated": float(_ip_obfuscated(p.host)),
        "has_port": float(p.port != ""),
        "nonstandard_port": float(p.port not in ("", "80", "443")),
        "has_userinfo": float(p.userinfo != ""),
        "has_punycode": float("xn--" in p.host),
        "has_non_ascii_host": float(any(ord(c) > 127 for c in p.host)),
        "https_in_host": float("https" in p.host),
        "http_in_path": float("http" in p.path.lower()),
        "www_in_path": float("www" in p.path.lower()),
        "www_misplaced_host": float("www" in host_labels),
        "double_slash_in_path": float("//" in p.path),
        "tld_in_path": float(bool(last_tld) and last_tld in path_words),
        "tld_in_subdomain": float(bool(last_tld) and last_tld in sub_labels),
        "abnormal_subdomain": float(len(sub_labels) > 3 or any(len(x) > 25 for x in sub_labels)),
        "prefix_suffix_hyphen": float("-" in p.label),
        "path_ext_present": float(ext != ""),
        "path_ext_is_script": float(ext in _SCRIPT_EXT),
        "path_ext_is_html": float(ext in _HTML_EXT),
    }


def obfuscation_group(p: Parts) -> dict[str, float]:
    n = len(p.canon)
    n_pct = len(_PCT.findall(p.canon))
    return {
        "n_pct_encoded": n_pct,
        "pct_encoded_ratio": _ratio(3 * n_pct, n),
        "longest_repeat_run": _longest_run(p.canon, lambda a, b: a == b),
        "char_continuation_rate": _ratio(
            _longest_run(p.canon, lambda a, b: _char_class(a) == _char_class(b)), n
        ),
        "n_non_ascii_url": sum(ord(c) > 127 for c in p.canon),
    }


def _bigram_loglik(label: str, fitted: Fitted) -> float:
    if not fitted.bigram_logprob or len(label) < 2:
        return NAN
    pairs = [label[i : i + 2] for i in range(len(label) - 1)]
    return sum(fitted.bigram_logprob.get(b, fitted.bigram_floor) for b in pairs) / len(pairs)


def randomness_group(p: Parts, fitted: Fitted) -> dict[str, float]:
    label = p.label
    letters = [c for c in label if _is_letter(c)]
    consonant_run = run = 0
    for c in label:
        run = run + 1 if (_is_letter(c) and c not in _VOWELS) else 0
        consonant_run = max(consonant_run, run)
    switches = sum(
        1
        for a, b in zip(label, label[1:], strict=False)
        if (_is_digit(a) and _is_letter(b)) or (_is_letter(a) and _is_digit(b))
    )
    return {
        "entropy_url": _entropy(p.canon),
        "entropy_domain": _entropy(label),
        "bigram_loglik_domain": _bigram_loglik(label, fitted),
        "domain_longest_consonant_run": 0 if not letters else consonant_run,
        "domain_vowel_ratio": _ratio(sum(c in _VOWELS for c in letters), len(letters)),
        "domain_digit_switches": switches,
    }


def _hits(text: str, vocab: tuple[str, ...]) -> int:
    return sum(1 for w in vocab if w in text)


def words_group(p: Parts, lists: Lists) -> dict[str, float]:
    host, path, query = p.host, p.path.lower(), p.query.lower()
    kw = lists.keywords
    exact = p.label in lists.brands
    return {
        "n_suspicious_keywords": _hits(f"{host}/{path}?{query}", kw),
        "kw_in_host": _hits(host, kw),
        "kw_in_path": _hits(path, kw),
        "kw_in_query": _hits(query, kw),
        "brand_in_subdomain": _hits(p.subdomain, lists.brands),
        "brand_in_path": _hits(path, lists.brands),
        "domain_is_brand": float(exact),
        "domain_contains_brand": float(
            bool(p.label) and not exact and any(b in p.label for b in lists.brands)
        ),
    }


def squatting_group(p: Parts, lists: Lists) -> dict[str, float]:
    label = p.label
    if p.is_ip or not label or not lists.brands:
        return dict.fromkeys(
            (
                "min_brand_edit_distance",
                "homoglyph_brand_match",
                "combosquat_prefix",
                "combosquat_suffix",
                "combosquat_middle",
            ),
            NAN,
        )
    dist = 3
    for b in lists.brand_candidates(label):
        dist = min(dist, edit_distance(label, b))
    parts = [x for x in label.replace("_", "-").split("-") if x]
    fixed = [normalise_homoglyphs(x) for x in parts]
    homoglyph = any(f != x and f in lists.brands for x, f in zip(parts, fixed, strict=True))
    brand_parts = [
        i
        for i, (x, f) in enumerate(zip(parts, fixed, strict=True))
        if x in lists.brands or f in lists.brands
    ]
    combo = len(parts) > 1
    return {
        "min_brand_edit_distance": dist,
        "homoglyph_brand_match": float(homoglyph),
        "combosquat_prefix": float(combo and 0 in brand_parts),
        "combosquat_suffix": float(combo and (len(parts) - 1) in brand_parts),
        "combosquat_middle": float(any(0 < i < len(parts) - 1 for i in brand_parts)),
    }


def other_group(p: Parts, lists: Lists, fitted: Fitted) -> dict[str, float]:
    keys = {kv.split("=", 1)[0].lower() for kv in p.query.split("&") if kv}
    tail = f"{p.path}?{p.query}".lower()
    tld = p.suffix.rsplit(".", 1)[-1] if p.suffix else ""
    if p.is_ip or not tld:
        tld_risk = NAN
    else:
        tld_risk = fitted.tld_risk.get(p.suffix, fitted.tld_default) if fitted.tld_risk else NAN
    return {
        "is_shortener": float(p.domain in lists.shorteners),
        "has_redirect_param": float(bool(keys & lists.redirect_params)),
        "has_embedded_url": float(bool(_EMBEDDED.search(tail))),
        "has_embedded_email": float(bool(_EMAIL.search(tail))),
        "suspicious_tld": float(tld in lists.suspicious_tlds),
        "tld_risk": tld_risk,
        "is_hosting_platform": float(p.is_platform),
    }


def compute(p: Parts, lists: Lists, fitted: Fitted) -> dict[str, float]:
    out: dict[str, float] = {}
    for part in (
        length_group(p),
        counts_group(p),
        ratios_group(p),
        host_form_group(p),
        obfuscation_group(p),
        randomness_group(p, fitted),
        words_group(p, lists),
        squatting_group(p, lists),
        other_group(p, lists, fitted),
    ):
        out.update({k: float(v) for k, v in part.items()})
    return out
