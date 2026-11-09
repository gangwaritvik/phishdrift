"""Look-alike domains of a brand name, in nine styles (experiments/lookalike_a.py).

``TRAIN_STYLES`` are the styles the augmented training rows use; ``TEST_ONLY_STYLES`` are held out
from training so the evaluation also measures attack styles the model never saw. Deterministic
given the ``random.Random``. ``make_domain`` returns the registrable domain (ASCII, punycode for
the Unicode style) or None when the style does not apply to this name.
"""

from __future__ import annotations

import random
import string

from attacks.transforms import LURE_LABELS, SWAP_TLDS, UNICODE_SWAPS

TRAIN_STYLES = ("digit", "delete", "insert", "brand_word")
TEST_ONLY_STYLES = ("transpose", "leet", "rnvv", "unicode", "suffix")
STYLES = TRAIN_STYLES + TEST_ONLY_STYLES

DIGIT_SWAPS = {"l": "1", "o": "0", "i": "1"}
LEET_SWAPS = {"a": "4", "e": "3", "s": "5", "t": "7", "b": "8", "g": "9"}
SEQUENCE_SWAPS = (("m", "rn"), ("w", "vv"), ("d", "cl"))


def _swap_one(name: str, table: dict[str, str], rng: random.Random) -> str | None:
    spots = [i for i, ch in enumerate(name) if ch in table]
    if not spots:
        return None
    i = rng.choice(spots)
    return name[:i] + table[name[i]] + name[i + 1 :]


def look_alike_label(style: str, brand: str, rng: random.Random) -> str | None:
    """The look-alike name (without suffix) for ``brand`` in ``style``."""
    n = len(brand)
    if style == "digit":
        return _swap_one(brand, DIGIT_SWAPS, rng)
    if style == "leet":
        return _swap_one(brand, LEET_SWAPS, rng)
    if style == "unicode":
        out = _swap_one(brand, UNICODE_SWAPS, rng)
        try:
            return out.encode("idna").decode("ascii") if out else None
        except UnicodeError:
            return None
    if style == "delete":
        if n < 5:
            return None
        i = rng.randrange(1, n)
        return brand[:i] + brand[i + 1 :]
    if style == "insert":
        i = rng.randrange(1, n + 1)
        return brand[:i] + rng.choice(string.ascii_lowercase) + brand[i:]
    if style == "transpose":
        spots = [i for i in range(1, n - 1) if brand[i] != brand[i + 1]]
        if not spots:
            return None
        i = rng.choice(spots)
        return brand[:i] + brand[i + 1] + brand[i] + brand[i + 2 :]
    if style == "rnvv":
        options = [(a, b) for a, b in SEQUENCE_SWAPS if a in brand[1:]]
        if not options:
            return None
        a, b = rng.choice(options)
        i = rng.choice([j for j in range(1, n) if brand[j] == a])
        return brand[:i] + b + brand[i + 1 :]
    if style == "brand_word":
        word = rng.choice(LURE_LABELS)
        return f"{brand}-{word}" if rng.random() < 0.5 else f"{word}-{brand}"
    if style == "suffix":
        return brand
    raise ValueError(f"unknown look-alike style {style!r}")


def make_domain(
    style: str,
    brand: str,
    rng: random.Random,
    own_tld: str | None = None,
    tlds: tuple[str, ...] = SWAP_TLDS,
    own_prob: float = 0.5,
) -> str | None:
    """Registrable domain of the look-alike: the name plus a suffix.

    With probability ``own_prob`` the suffix is the brand's own (``paypa1.com`` for ``paypal.com``),
    so the suffix alone never gives the label away; the ``suffix`` style always uses another one.
    """
    label = look_alike_label(style, brand, rng)
    if not label or label == brand and style != "suffix":
        return None
    if style == "suffix":
        pool = [t for t in tlds if t != own_tld]
        return f"{label}.{rng.choice(pool)}"
    tld = own_tld if own_tld and rng.random() < own_prob else rng.choice(tlds)
    return f"{label}.{tld}"
