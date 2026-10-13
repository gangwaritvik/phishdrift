"""The one feature entry point: ``extract(url, html, domain_info) -> dict[str, float]``.

Tier A uses only the URL and is always returned, exactly as before. Tier B (``html``) is added
only when the page has usable HTML (see ``features/html_features.py``); with no HTML, or a parked
or error page, the result has no tier B keys at all, so tier A rows never contain tier B names.
``domain_info`` (tier C) is accepted so the signature never changes; it adds features in a later
milestone. Missing values are NaN.
"""

from __future__ import annotations

from features.fit import Fitted, load_fitted
from features.html_features import analyze
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
    out = {name: values[name] for name in NAMES}
    if html:
        page, _ = analyze(url, html, parts, lists=lists)
        if page is not None:
            out.update(page)
    return out
