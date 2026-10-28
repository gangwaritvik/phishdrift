"""Brand-domain mismatch signals for the look-alike experiments (experiments/lookalike_a.py).

EXPERIMENTAL: not in ``features/registry.py`` and not ported to JavaScript. If the experiment
earns its place, the four columns are registered, ported with a parity fixture and documented.

A site is a *foreign look-alike* of a brand when its registrable name is the brand's name written
with look-alike characters (``paypa1``, a Cyrillic letter, ``rn`` for ``m``) or one edit away from
it, and the registrable domain is not one of the brand's own. Inputs, none typed by hand: the
brand names (``configs/lists/brands.txt``), the brand-to-own-domains map
(``configs/lists/brand_domains.json``, Wikidata + MISP) and the Unicode confusables table
(``configs/lists/confusables.json``). The rules are those of the look-alike check removed in
PR #75 (git ``74d258f``: ``js/src/lookalike.js``), so E3r can use them as an escalate-only rule.

Columns (NaN for IP hosts, hosting-platform tenants and hosts without a suffix):

``brand_homograph``     skeleton of the name equals a brand's name, written differently
``brand_edit1``         one edit (insert, delete, substitute, swap) from a brand name, 6+ letters
``brand_other_suffix``  the name equals a brand's name, but the domain is not one of its own
``brand_official``      the registrable domain is one of some brand's own domains
"""

from __future__ import annotations

import json
from pathlib import Path

from features.lists import LISTS_DIR, read_list
from features.urlparts import Parts

NAN = float("nan")
COLUMNS = ("brand_homograph", "brand_edit1", "brand_other_suffix", "brand_official")
DIGITS = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g"}
SEQUENCES = (("rn", "m"), ("vv", "w"))


def decode_label(label: str) -> str:
    """Punycode label to Unicode (lowercase); anything undecodable stays as it is."""
    if label.startswith("xn--"):
        try:
            return label[4:].encode("ascii").decode("punycode").lower()
        except (UnicodeError, ValueError):
            return label
    return label


def within_one(a: str, b: str) -> bool:
    """Restricted Damerau-Levenshtein distance exactly 1 (insert, delete, substitute, swap)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    i = 0
    while i < len(a) and i < len(b) and a[i] == b[i]:
        i += 1
    if len(a) == len(b):
        if a[i + 1 :] == b[i + 1 :]:
            return True
        return i + 1 < len(a) and a[i] == b[i + 1] and a[i + 1] == b[i] and a[i + 2 :] == b[i + 2 :]
    if len(a) > len(b):
        return a[i + 1 :] == b[i:]
    return a[i:] == b[i + 1 :]


class BrandMismatch:
    def __init__(
        self,
        brands: list[str],
        owned: dict[str, list[str]],
        skeleton_map: dict[str, str],
        min_brand_len: int = 4,
        min_edit_len: int = 6,
    ):
        self.brands = frozenset(b for b in brands if len(b) >= min_brand_len)
        self.owned = {b: frozenset(owned.get(b, ())) for b in self.brands}
        self.official = frozenset(d for ds in self.owned.values() for d in ds)
        self.skeleton_map, self.min_edit_len = skeleton_map, min_edit_len
        self.targets: dict[str, list[str]] = {}
        for b in sorted(self.brands):
            self.targets.setdefault(self.skeleton(b), []).append(b)
        # edit-one candidates share the first letter and are at most one letter longer or shorter
        self.by_start: dict[tuple[str, int], list[str]] = {}
        for t in self.targets:
            if len(t) >= min_edit_len:
                self.by_start.setdefault((t[0], len(t)), []).append(t)
        self._cache: dict[str, tuple[float, float, float, float]] = {}

    @classmethod
    def from_lists(cls, lists_dir: Path = LISTS_DIR, **kw) -> BrandMismatch:
        owned = json.loads((lists_dir / "brand_domains.json").read_text(encoding="utf-8"))["brands"]
        skel = json.loads((lists_dir / "confusables.json").read_text(encoding="utf-8"))["map"]
        return cls(read_list(lists_dir / "brands.txt"), owned, skel, **kw)

    def skeleton(self, text: str) -> str:
        out = "".join(self.skeleton_map.get(c, DIGITS.get(c, c)) for c in text.lower())
        for src, dst in SEQUENCES:
            out = out.replace(src, dst)
        return out

    def _signal(self, label: str, domain: str) -> tuple[float, float, float, float]:
        official = domain in self.official
        plain = label if label in self.brands else label.replace("-", "")
        name_is_brand = plain in self.brands
        other = float(name_is_brand and not official and bool(self.owned[plain]))
        homograph = edit1 = 0.0
        if not official and not name_is_brand:
            text = decode_label(label)
            skel = self.skeleton(text)
            if skel != text:
                # "1" stands for "l" (app1e) or "i" (c1tibank): try both readings
                alt = self.skeleton(text.replace("1", "i")) if "1" in text else skel
                homograph = float(skel in self.targets or alt in self.targets)
            n = len(skel)
            if not homograph and n >= self.min_edit_len - 1:
                for m in (n - 1, n, n + 1):
                    for t in self.by_start.get((skel[:1], m), ()):
                        # one letter added to a short name often spells another real name
                        if n > m and m <= self.min_edit_len:
                            continue
                        if within_one(skel, t):
                            edit1 = 1.0
                            break
                    if edit1:
                        break
        return homograph, edit1, other, float(official)

    def features(self, parts: Parts | None) -> dict[str, float]:
        if parts is None or parts.is_ip or parts.is_platform or not parts.suffix:
            return dict.fromkeys(COLUMNS, NAN)
        key = parts.domain
        if key not in self._cache:
            self._cache[key] = self._signal(parts.label, parts.domain)
        return dict(zip(COLUMNS, self._cache[key], strict=True))
