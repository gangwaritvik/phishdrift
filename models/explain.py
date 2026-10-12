"""Per-URL explanations for the tier A trees: TreeSHAP contributions and plain-English reasons.

``contributions`` is path-dependent TreeSHAP (Lundberg et al. 2020, Algorithm 2) on the compact
trees of ``models.export``; it gives the same numbers as LightGBM's ``pred_contrib`` (the sum
of a row's contributions plus ``expected_value`` is its raw score). ``js/src/explain.js`` is a
line-by-line port, checked against the same fixture.

``reasons`` turns the largest positive contributions into sentences from ``REASONS``; a feature
without a sentence falls back to its registry definition. Only features that push the score
toward phishing are reasons, and at most ``top`` of them are returned.
"""

from __future__ import annotations

import math
from decimal import ROUND_HALF_UP, Decimal

import numpy as np

from features.registry import REGISTRY

ZERO_THRESHOLD = 1e-35


def _goes_left(tree: dict, node: int, v: float) -> bool:
    m = tree["m"][node]
    nan = math.isnan(v)
    if nan and m != 2:
        v = 0.0
    if (m == 1 and abs(v) <= ZERO_THRESHOLD) or (m == 2 and nan):
        return tree["d"][node] == 1
    return v <= tree["t"][node]


def _cover(tree: dict, child: int) -> float:
    return tree["n"][~child] if child < 0 else tree["c"][child]


def _extend(path: list[list[float]], pz: float, po: float, pi: int) -> list[list[float]]:
    """Path entries are [feature, zero_fraction, one_fraction, weight]."""
    n = len(path)
    path = [e[:] for e in path] + [[pi, pz, po, 1.0 if n == 0 else 0.0]]
    for i in range(n - 1, -1, -1):
        path[i + 1][3] += po * path[i][3] * (i + 1) / (n + 1)
        path[i][3] = pz * path[i][3] * (n - i) / (n + 1)
    return path


def _unwind(path: list[list[float]], i: int) -> list[list[float]]:
    n = len(path) - 1
    path = [e[:] for e in path]
    one, zero = path[i][2], path[i][1]
    nxt = path[n][3]
    for j in range(n - 1, -1, -1):
        if one != 0:
            tmp = path[j][3]
            path[j][3] = nxt * (n + 1) / ((j + 1) * one)
            nxt = tmp - path[j][3] * zero * (n - j) / (n + 1)
        else:
            path[j][3] = path[j][3] * (n + 1) / (zero * (n - j))
    for j in range(i, n):
        path[j][:3] = path[j + 1][:3]
    return path[:n]


def _unwound_sum(path: list[list[float]], i: int) -> float:
    return sum(e[3] for e in _unwind(path, i))


def tree_contributions(tree: dict, x: np.ndarray, phi: np.ndarray) -> None:
    if not tree["f"]:
        return

    def recurse(node: int, path, pz: float, po: float, pi: int) -> None:
        path = _extend(path, pz, po, pi)
        if node < 0:
            leaf = tree["v"][~node]
            for i in range(1, len(path)):
                w = _unwound_sum(path, i)
                phi[int(path[i][0])] += w * (path[i][2] - path[i][1]) * leaf
            return
        f = tree["f"][node]
        left, right = tree["l"][node], tree["r"][node]
        hot, cold = (left, right) if _goes_left(tree, node, x[f]) else (right, left)
        iz = io = 1.0
        k = next((k for k in range(1, len(path)) if path[k][0] == f), None)
        if k is not None:
            iz, io = path[k][1], path[k][2]
            path = _unwind(path, k)
        cover = tree["c"][node]
        recurse(hot, path, iz * _cover(tree, hot) / cover, io, f)
        recurse(cold, path, iz * _cover(tree, cold) / cover, 0.0, f)

    recurse(0, [], 1.0, 1.0, -1)


def expected_value(trees: list[dict]) -> float:
    total = 0.0
    for tree in trees:
        if not tree["f"]:
            total += tree["v"][0]
        else:
            total += float(np.dot(tree["v"], tree["n"]) / np.sum(tree["n"]))
    return total


def contributions(trees: list[dict], x: np.ndarray) -> np.ndarray:
    """Log-odds contribution of each feature for one row ``x`` (float32 values, as in training)."""
    x = np.asarray(x, dtype=np.float32).astype(np.float64)
    phi = np.zeros(len(x))
    for tree in trees:
        tree_contributions(tree, x, phi)
    return phi


# --- plain-English reasons -------------------------------------------------------------

TYPICAL = "typical of phishing links"
LIKE_PHISHING = f"is {TYPICAL}"
# Sentence per feature, shown when the feature pushes the score toward phishing and its value
# lies in [lo, hi]. Yes/no features only give a reason when present (value 1). Sentences about
# amounts say the value is typical of phishing rather than "too long" or "too short": a positive
# contribution can come from either side. {v} is the value.
REASONS: dict[str, tuple[str, float, float]] = {
    "host_is_ip": ("The address is a bare IP number instead of a website name.", 1, 1),
    "host_ip_obfuscated": ("The address is a disguised IP number.", 1, 1),
    "nonstandard_port": ("The address uses an unusual port number.", 1, 1),
    "has_userinfo": (
        "Text and an @ come before the website name, which can hide the real destination.",
        1,
        1,
    ),
    "has_punycode": (
        "The website name uses encoded international letters (xn--), a common look-alike trick.",
        1,
        1,
    ),
    "has_non_ascii_host": (
        "The website name contains non-English letters that may imitate a real name.",
        1,
        1,
    ),
    "https_in_host": ("The word 'https' is part of the website name.", 1, 1),
    "http_in_path": ("The page path contains 'http', a sign of a second hidden address.", 1, 1),
    "www_in_path": ("'www' appears in the page path.", 1, 1),
    "www_misplaced_host": ("'www' appears in an unusual place in the website name.", 1, 1),
    "double_slash_in_path": ("The page path contains a double slash.", 1, 1),
    "tld_in_path": ("A domain ending like 'com' appears in the page path.", 1, 1),
    "tld_in_subdomain": ("A domain ending like 'com' appears before the real website name.", 1, 1),
    "abnormal_subdomain": (
        "The part before the real website name is unusually long or deep.",
        1,
        1,
    ),
    "prefix_suffix_hyphen": (
        "The website name contains a hyphen, common in look-alike names.",
        1,
        1,
    ),
    "path_ext_is_script": ("The page is a script file (like .php).", 1, 1),
    "domain_is_brand": ("The website name is a brand name on an unusual domain ending.", 1, 1),
    "domain_contains_brand": (
        "The website name contains a brand name but is not the brand's site.",
        1,
        1,
    ),
    "min_brand_edit_distance": ("The website name is a near-misspelling of a known brand.", 1, 2),
    "homoglyph_brand_match": (
        "The website name imitates a brand with look-alike characters.",
        1,
        1,
    ),
    "combosquat_prefix": ("A brand name is followed by extra words (like brand-login).", 1, 1),
    "combosquat_suffix": ("Extra words come before a brand name (like secure-brand).", 1, 1),
    "combosquat_middle": ("A brand name is hidden between other words in the website name.", 1, 1),
    "brand_in_subdomain": ("A brand name appears before the real website name.", 1, math.inf),
    "brand_in_path": (
        "A brand name appears in the page path, not in the website name.",
        1,
        math.inf,
    ),
    "kw_in_host": ("The website name contains words like login, verify or secure.", 1, math.inf),
    "kw_in_path": ("The page path contains words like login, verify or account.", 1, math.inf),
    "kw_in_query": ("The address contains words like login, verify or account.", 1, math.inf),
    "n_suspicious_keywords": (
        "The address contains words often used in phishing ({v}).",
        1,
        math.inf,
    ),
    "is_shortener": ("This is a link shortener, so the real destination is hidden.", 1, 1),
    "has_redirect_param": ("The address carries another address to send you to.", 1, 1),
    "has_embedded_url": ("The address contains another web address inside it.", 1, 1),
    "has_embedded_email": ("The address contains an email address.", 1, 1),
    "suspicious_tld": (
        "The website name ends in a domain extension often abused for phishing.",
        1,
        1,
    ),
    "is_hosting_platform": (
        "The page is on a shared hosting platform where anyone can publish.",
        1,
        1,
    ),
    "char_url": (
        "The overall look of the address resembles known phishing links.",
        -math.inf,
        math.inf,
    ),
    "char_host": (
        "The letters of the website name resemble known phishing sites.",
        -math.inf,
        math.inf,
    ),
    "char_path": (
        "The page path of the address resembles known phishing links.",
        -math.inf,
        math.inf,
    ),
    "word_url": (
        "The words in the address resemble known phishing links.",
        -math.inf,
        math.inf,
    ),
    "tld_risk": (
        "Sites with this domain ending were often phishing in the training data.",
        -math.inf,
        math.inf,
    ),
    "bigram_loglik_domain": (
        f"The letter pattern of the website name {LIKE_PHISHING}.",
        -math.inf,
        math.inf,
    ),
    "entropy_domain": (f"How random the website name looks {LIKE_PHISHING}.", -math.inf, math.inf),
    "url_len": (f"The address length ({{v}} characters) {LIKE_PHISHING}.", -math.inf, math.inf),
    "host_len": (
        f"The website name length ({{v}} characters) {LIKE_PHISHING}.",
        -math.inf,
        math.inf,
    ),
    "domain_len": (
        f"The website name length ({{v}} characters) {LIKE_PHISHING}.",
        -math.inf,
        math.inf,
    ),
    "subdomain_len": (
        f"The length of the part before the website name ({{v}} characters) {LIKE_PHISHING}.",
        1,
        math.inf,
    ),
    "n_subdomain_levels": (
        f"The number of parts before the website name ({{v}}) {LIKE_PHISHING}.",
        1,
        math.inf,
    ),
    "path_len": (f"The page path length ({{v}} characters) {LIKE_PHISHING}.", -math.inf, math.inf),
    "path_depth": (
        f"The number of folders in the page path ({{v}}) {LIKE_PHISHING}.",
        -math.inf,
        math.inf,
    ),
    "n_hyphen": (f"The number of hyphens ({{v}}) {LIKE_PHISHING}.", 1, math.inf),
    "host_n_hyphen": (
        f"The number of hyphens in the website name ({{v}}) {LIKE_PHISHING}.",
        1,
        math.inf,
    ),
    "n_digits": (f"The number of digits ({{v}}) {LIKE_PHISHING}.", 1, math.inf),
    "n_pct_encoded": (f"The number of %-encoded characters ({{v}}) {LIKE_PHISHING}.", 1, math.inf),
}


def fmt(v: float) -> str:
    """Same text as ``fmt`` in js/src/explain.js: integers as is, else two decimals with ties
    rounded away from zero on the exact binary value (JavaScript's ``toFixed``)."""
    if float(v).is_integer():
        return str(int(v))
    return str(Decimal(float(v)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


REGISTRY_BY_NAME = {f.name: f for f in REGISTRY}


def reason_rules(names: list[str]) -> dict[str, dict]:
    """Rule per feature for the bundle: sentence template and the value range it applies to.
    A feature without a sentence gets one from its registry definition."""
    out = {}
    for name in names:
        if name in REASONS:
            text, lo, hi = REASONS[name]
        else:
            definition = REGISTRY_BY_NAME[name].definition.split("; NaN")[0].rstrip(".")
            text, lo, hi = f"{definition}: {{v}}, {TYPICAL}.", -math.inf, math.inf
        out[name] = {
            "text": text,
            "lo": None if lo == -math.inf else lo,
            "hi": None if hi == math.inf else hi,
        }
    return out


def reasons(
    phi: np.ndarray,
    x: np.ndarray,
    names: list[str],
    rules: dict[str, dict],
    top: int,
    min_logodds: float,
) -> list[dict]:
    """Up to ``top`` sentences for the features pushing hardest toward phishing."""
    out = []
    for i in np.argsort(-phi, kind="stable"):
        if len(out) == top or phi[i] < min_logodds:
            break
        v, rule = float(x[i]), rules[names[i]]
        if (
            math.isnan(v)
            or (rule["lo"] is not None and v < rule["lo"])
            or (rule["hi"] is not None and v > rule["hi"])
        ):
            continue
        out.append(
            {
                "feature": names[i],
                "contribution": float(phi[i]),
                "text": rule["text"].replace("{v}", fmt(v)),
            }
        )
    return out
