"""URL evasion transforms (milestone: robustness section).

Six families an attacker can apply to a phishing URL without touching the page. Every transform
is deterministic given its seed, keeps the URL a valid http(s) URL, and returns ``None`` when it
does not apply (for example a homoglyph swap on a host with no replaceable letter).
"""

from attacks.transforms import FAMILIES, apply_family

__all__ = ["FAMILIES", "apply_family"]
