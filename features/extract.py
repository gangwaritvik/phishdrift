"""The one feature entry point: ``extract(url, html, domain_info) -> dict[str, float]``.

Tier A uses only the URL. ``html`` (tier B) and ``domain_info`` (tier C) are accepted so the
signature never changes; they add features in later milestones. Missing values are NaN.
"""

from __future__ import annotations

from features.fit import Fitted, load_fitted
from features.lists import Lists, load_lists
from features.registry import NAMES
from features.url_features import NAN, compute
from features.urlparts import parse


def extract(
    url: str,
    html: str | None = None,
    domain_info: dict | None = None,
    *,
    lists: Lists | None = None,
    fitted: Fitted | None = None,
) -> dict[str, float]:
    lists = lists or load_lists()
    fitted = fitted or load_fitted()
    parts = parse(url, lists.platforms) if isinstance(url, str) else None
    if parts is None:
        return dict.fromkeys(NAMES, NAN)
    values = compute(parts, lists, fitted)
    return {name: values[name] for name in NAMES}
