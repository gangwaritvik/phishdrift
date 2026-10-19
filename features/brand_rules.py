"""Brand and look-alike rules: escalate-only signals next to the models (not model features).

Two kinds of evidence the models only see indirectly:

- **Address rules** (``address_signals``): the registrable domain imitates a brand's own website.
  ``homograph``: after folding look-alike characters (the Unicode confusables table plus digit
  look-alikes, ``configs/lists/confusables.json``) the label equals a brand's label (``аpple``,
  ``paypa1``, ``rnicrosoft``). ``edit1``: one edit or one swap of neighbouring letters away from
  a brand label of at least ``min_edit_len`` characters (``paypai``). ``embedded``: a brand's own
  domain sits inside a different host (``paypal.com-secure.xyz``, ``paypal-com.evil.net``).
  ``combo``: the label is a brand name plus a lure word (``onlinesbi-kyc``, ``paypalsecure``).
- **Page rule** (``page_signal``): the page shows a brand in its title, ``og:site_name`` or
  copyright line and asks for a password, OTP, card or PIN, and its domain is not one of that
  brand's websites.

A domain is the brand's own when it is in the brand-to-domains map
(``configs/lists/brand_domains.json``, built from data by ``features.brand_domains``) or its
label equals the brand name (``paypal.de``). Brand names come from ``configs/lists/brands.txt``
(the learned list), so no address is written by hand and no popularity data is used.

The rules can only raise a verdict (``extension/src/combine.js``); a rule hit on a brand's own
domain is impossible by construction. ``js/src/brand_rules.js`` mirrors this file and
``tests/fixtures/brand_rules_parity.json`` holds both sides to the same answers.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

import yaml

from features.lists import LISTS_DIR, MIN_BRAND_LEN, ROOT, load_lists
from features.urlparts import parse
from phishdrift.domains import split_host

CONFIG_FILE = ROOT / "configs" / "brand_rules.yaml"
BRAND_DOMAINS_FILE = LISTS_DIR / "brand_domains.json"
CONFUSABLES_FILE = LISTS_DIR / "confusables.json"

DIGITS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"}
SEQUENCES = (("rn", "m"), ("vv", "w"))
RULES = ("homograph", "embedded", "edit1", "combo")  # order = which reason is shown first


def load_config(path: Path = CONFIG_FILE) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


# ---- punycode (RFC 3492 decoder; mirrors js/src/brand_rules.js) -------------------------------

_BASE, _TMIN, _TMAX, _SKEW, _DAMP, _BIAS, _N = 36, 1, 26, 38, 700, 72, 128


def _adapt(delta: int, numpoints: int, first: bool) -> int:
    delta = delta // _DAMP if first else delta // 2
    delta += delta // numpoints
    k = 0
    while delta > ((_BASE - _TMIN) * _TMAX) // 2:
        delta //= _BASE - _TMIN
        k += _BASE
    return k + (_BASE - _TMIN + 1) * delta // (delta + _SKEW)


def _digit(ch: str) -> int:
    c = ord(ch)
    if 48 <= c <= 57:
        return c - 22
    if 65 <= c <= 90:
        return c - 65
    if 97 <= c <= 122:
        return c - 97
    return _BASE


def punycode_decode(text: str) -> str | None:
    """Decode the part after ``xn--``; None when it is not valid punycode."""
    cut = text.rfind("-")
    out = list(text[:cut]) if cut > 0 else []
    if any(ord(ch) >= 0x80 for ch in out):
        return None
    i, n, bias = 0, _N, _BIAS
    pos = cut + 1 if cut > 0 else 0
    while pos < len(text):
        old, w, k = i, 1, _BASE
        while True:
            if pos >= len(text):
                return None
            d = _digit(text[pos])
            pos += 1
            if d >= _BASE:
                return None
            i += d * w
            t = _TMIN if k <= bias else _TMAX if k >= bias + _TMAX else k - bias
            if d < t:
                break
            w *= _BASE - t
            k += _BASE
            if i > 0x10FFFF * 4:
                return None
        size = len(out) + 1
        bias = _adapt(i - old, size, old == 0)
        n += i // size
        i %= size
        if n > 0x10FFFF or 0xD800 <= n <= 0xDFFF:
            return None
        out.insert(i, chr(n))
        i += 1
    return "".join(out)


def decode_label(label: str) -> str:
    if label.startswith("xn--"):
        decoded = punycode_decode(label[4:])
        if decoded:
            return decoded.lower()
    return label


# ---- the rule set -----------------------------------------------------------------------------


def within_one(a: str, b: str) -> bool:
    """True when ``a`` and ``b`` differ by exactly one insertion, deletion, substitution or swap of
    two neighbouring characters (restricted Damerau-Levenshtein distance 1)."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return False
    i = 0
    while i < la and i < lb and a[i] == b[i]:
        i += 1
    if la == lb:
        if a[i + 1 :] == b[i + 1 :]:
            return True
        return i + 1 < la and a[i] == b[i + 1] and a[i + 1] == b[i] and a[i + 2 :] == b[i + 2 :]
    if la > lb:
        return a[i + 1 :] == b[i:]
    return a[i:] == b[i + 1 :]


@dataclass(frozen=True)
class BrandRules:
    skeleton_map: dict[str, str]
    brand_domains: dict[str, tuple[str, ...]]
    brands: tuple[str, ...]
    lures: tuple[str, ...]
    min_edit_len: int = 6
    min_combo_len: int = 5
    enabled: tuple[str, ...] = RULES
    platforms: frozenset[str] = frozenset()
    official: dict[str, str] = field(default_factory=dict, compare=False)  # domain -> brand
    targets: dict[str, tuple[str, ...]] = field(
        default_factory=dict, compare=False
    )  # skel -> brands
    target_keys: tuple[str, ...] = field(default=(), compare=False)  # sorted keys of targets

    @classmethod
    def build(
        cls, *, skeleton_map, brand_domains, brands, lures, min_edit_len=6, min_combo_len=5,
        enabled=RULES, platforms=frozenset(),
    ) -> BrandRules:  # fmt: skip
        brands = tuple(sorted({b for b in brands if len(b) >= MIN_BRAND_LEN}))
        domains = {b: tuple(sorted(set(ds))) for b, ds in brand_domains.items() if ds}
        rules = cls(
            skeleton_map=dict(skeleton_map),
            brand_domains=domains,
            brands=brands,
            lures=tuple(sorted(set(lures))),
            min_edit_len=min_edit_len,
            min_combo_len=min_combo_len,
            enabled=tuple(enabled),
            platforms=frozenset(platforms),
        )
        official: dict[str, str] = {}
        for b in sorted(domains):
            for d in domains[b]:
                lab = d.split(".", 1)[0]
                if lab == b or d not in official:
                    official[d] = b if lab == b or lab not in domains else lab
        targets: dict[str, set[str]] = {}
        for b in brands:
            targets.setdefault(rules.skeleton(b), set()).add(b)
        object.__setattr__(rules, "official", official)
        object.__setattr__(rules, "targets", {k: tuple(sorted(v)) for k, v in targets.items()})
        object.__setattr__(rules, "target_keys", tuple(sorted(targets)))
        return rules

    def skeleton(self, text: str) -> str:
        out = "".join(self.skeleton_map.get(c, DIGITS.get(c, c)) for c in text.lower())
        for src, dst in SEQUENCES:
            out = out.replace(src, dst)
        return out

    def owns(self, brand: str, domain: str, label: str) -> bool:
        """``domain`` is one of ``brand``'s websites (map), or its label is the brand name."""
        return (
            label == brand
            or domain in self.brand_domains.get(brand, ())
            or (domain in self.official and self.official[domain] == brand)
        )

    def is_official(self, domain: str) -> bool:
        return domain in self.official

    # ---- address ----

    def address_signals(self, url: str) -> list[dict]:
        """Rules hit by ``url``'s host, most convincing first. Empty for a brand's own domain."""
        p = parse(url, frozenset()) if isinstance(url, str) else None
        if p is None or p.is_ip or not p.suffix:
            return []
        domain, label = p.domain, p.label
        if (
            self.is_official(domain)
            or label in self.brands
            or label.replace("-", "") in self.brands
        ):
            return []
        dlabel = decode_label(label)
        skel = self.skeleton(dlabel)
        hits: list[dict] = []
        on = set(self.enabled)

        if "homograph" in on and skel != dlabel:
            # "1" stands for "l" (app1e) or "i" (c1tibank): try both readings
            alt = skel if "1" not in dlabel else self.skeleton(dlabel.replace("1", "i"))
            found = next((k for k in (skel, alt) if k in self.targets), None)
            if found:
                hits.append(self._hit("homograph", self.targets[found][0], domain))

        if "embedded" in on and p.subdomain:
            b = self._embedded(p.subdomain + "." + label)
            if b:
                hits.append(self._hit("embedded", b[0], domain, b[1]))

        if "edit1" in on and len(skel) >= self.min_edit_len - 1 and not hits:
            for t in self.target_keys:
                # one letter added to a short name often spells another real name (vivacom)
                if len(skel) > len(t) and len(t) <= self.min_edit_len:
                    continue
                if len(t) >= self.min_edit_len and t[0] == skel[0] and within_one(skel, t):
                    hits.append(self._hit("edit1", self.targets[t][0], domain))
                    break

        if "combo" in on and not hits:
            b = self._combo(skel)
            if not b and domain in self.platforms and p.subdomain:
                # on a hosting platform the tenant's name is the part that imitates the brand
                tenant = decode_label(p.subdomain.rsplit(".", 1)[-1])
                b = self._combo(self.skeleton(tenant))
            if b:
                hits.append(self._hit("combo", b[0], domain, b[1]))
        return hits

    def _embedded(self, front: str) -> tuple[str, str] | None:
        """A brand's own domain written into the part of the host in front of the registrable
        domain, with dots or hyphens (``paypal.com`` in ``paypal.com-secure`` or ``paypal-com``)."""
        labels = [x for x in front.replace("-", ".").split(".") if x]
        for i in range(len(labels)):
            for j in range(i + 2, min(len(labels), i + 4) + 1):
                cand = ".".join(labels[i:j])
                if cand in self.official:
                    return self.official[cand], cand
                # a brand name followed by a public suffix: paypal.com, sbi.co.in
                sub, lab, suf = split_host(cand)
                if not sub and suf and lab in self.brands:
                    return lab, cand
        return None

    def _combo(self, skel: str) -> tuple[str, str] | None:
        for b in self.brands:
            if len(b) < self.min_combo_len or b not in skel or skel == b:
                continue
            rest = [x for x in skel.replace(b, "-", 1).split("-") if x]
            if rest and all(self._lure_words(x) for x in rest):
                return b, " ".join(rest)
        return None

    def _lure_words(self, text: str) -> bool:
        """``text`` is one lure word or two written together (``securelogin``)."""
        if text in self.lures:
            return True
        return any(text[:i] in self.lures and text[i:] in self.lures for i in range(1, len(text)))

    def _hit(self, rule: str, brand: str, domain: str, extra: str = "") -> dict:
        text = {
            "homograph": f'This address looks like "{brand}" but is written with look-alike characters.',  # noqa: E501
            "embedded": f"This address puts {extra} in front of a different website ({domain}).",
            "edit1": f'This address is one letter away from "{brand}".',
            "combo": (
                f'This address joins the name "{brand}" with "{extra}", but {domain} does not '
                f"belong to {brand}."
            ),
        }[rule]
        return {"rule": rule, "brand": brand, "text": text}

    # ---- page ----

    def page_signal(self, url: str, facts: dict | None) -> dict | None:
        """The page claims a brand (title, ``og:site_name`` or copyright line), asks for a
        credential, and its domain is not one of that brand's websites."""
        if not facts or not credential_fields(facts):
            return None
        p = parse(url, frozenset()) if isinstance(url, str) else None
        if p is None or not p.suffix and not p.is_ip:
            return None
        domain, label = (p.host, p.host) if p.is_ip else (p.domain, p.label)
        claimed = page_claims(facts)
        if not claimed or any(self.owns(b, domain, label) for b in claimed):
            return None
        b = claimed[0]
        return {
            "rule": "brand_page",
            "brand": b,
            "text": (
                f'This page shows the name "{b}" and asks for a password or code, but {domain} '
                f"does not belong to {b}."
            ),
        }


def page_claims(facts: dict) -> list[str]:
    """Brands the page presents itself as, not merely mentions (a shop selling Ray-Ban, a news
    story about Apple). ``og:site_name`` is the site's own name: if it names no brand, the page
    claims none. A title brand counts when the title is a login/account title or is the brand
    alone ("Facebook"); a copyright owner counts when no site name says otherwise."""
    site = list(facts.get("site_brands", ()))
    if facts.get("site_named") and not site:
        return []
    claimed = list(site)
    title = facts.get("title_brands", ())
    if title and (facts.get("title_login") or facts.get("title_norm") in title):
        claimed += [b for b in title if b not in claimed]
    claimed += [b for b in facts.get("copyright_brands", ()) if b not in claimed]
    return claimed


def credential_fields(facts: dict) -> int:
    return int(
        facts.get("password_fields", 0)
        + facts.get("otp_fields", 0)
        + facts.get("card_fields", 0)
        + facts.get("pin_fields", 0)
    )


# ---- phishing_catcher-style host score (a baseline, not a model feature) -----------------------


def catcher_score(url: str, rules: BrandRules, cfg: dict, suspicious_tlds=None) -> float:
    """Hand-weighted suspicion score of a host, after x0rz/phishing_catcher (GPL-3.0; the idea is
    re-implemented, nothing copied): lure words, brand names and near-misses, entropy, hyphens,
    deep subdomains, a suspicious TLD and punycode. Weights in ``configs/brand_rules.yaml``.
    NaN when there is no host."""
    p = parse(url, frozenset()) if isinstance(url, str) else None
    if p is None:
        return math.nan
    w = cfg["weights"]
    host = p.host
    score = 0.0
    words = [x for x in host.replace("-", ".").split(".") if x]
    for word in words:
        if word in rules.lures:
            score += w["lure"]
        if word in rules.brands and not rules.owns(word, p.domain, p.label):
            score += w["brand"]
    skel = rules.skeleton(decode_label(p.label))
    if (
        len(skel) >= rules.min_edit_len
        and not rules.is_official(p.domain)
        and p.label not in rules.brands
    ):
        for t in rules.targets:
            if len(t) >= rules.min_edit_len and within_one(skel, t):
                score += w["brand_typo"]
                break
    counts = Counter(host)
    n = len(host)
    entropy = -sum(c / n * math.log2(c / n) for c in counts.values()) if n else 0.0
    score += w["entropy"] * entropy
    if "xn--" not in host:
        score += w["hyphen"] * host.count("-")
    else:
        score += w["punycode"]
    if p.subdomain:
        score += w["dot"] * max(0, p.subdomain.count(".") + 1 - cfg["free_levels"])
    tld = p.suffix.rsplit(".", 1)[-1] if p.suffix else ""
    if suspicious_tlds is None:
        suspicious_tlds = load_lists().suspicious_tlds
    if tld in suspicious_tlds:
        score += w["tld"]
    return score


# ---- loading ----------------------------------------------------------------------------------


def read_brand_domains(path: Path = BRAND_DOMAINS_FILE) -> dict[str, list[str]]:
    if not Path(path).exists():
        return {}
    return json.loads(Path(path).read_text(encoding="utf-8"))["brands"]


def read_confusables(path: Path = CONFUSABLES_FILE) -> dict[str, str]:
    if not Path(path).exists():
        return {}
    return json.loads(Path(path).read_text(encoding="utf-8"))["map"]


def lures_from(keywords, exclude) -> list[str]:
    skip = set(exclude)
    return [k.replace("-", "") for k in keywords if k not in skip and len(k) >= 3]


@cache
def load_rules(lists_dir: str | None = None) -> BrandRules:
    cfg = load_config()
    base = Path(lists_dir) if lists_dir else LISTS_DIR
    lists = load_lists(lists_dir)
    return BrandRules.build(
        skeleton_map=read_confusables(base / "confusables.json"),
        brand_domains=read_brand_domains(base / "brand_domains.json"),
        brands=lists.brands,
        lures=lures_from(lists.keywords, cfg["lure_exclude"]),
        min_edit_len=cfg["min_edit_len"],
        min_combo_len=cfg["min_combo_len"],
        enabled=tuple(cfg["rules"]),
        platforms=lists.platforms,
    )


def rules_payload(rules: BrandRules, cfg: dict) -> dict:
    """What ``js/src/brand_rules.js`` needs (``js/data/brand_rules.json``)."""
    return {
        "skeleton_map": rules.skeleton_map,
        "brand_domains": {b: list(v) for b, v in sorted(rules.brand_domains.items())},
        "brands": list(rules.brands),
        "lures": list(rules.lures),
        "min_edit_len": rules.min_edit_len,
        "min_combo_len": rules.min_combo_len,
        "enabled": list(rules.enabled),
        "catcher": cfg["catcher"],
    }
