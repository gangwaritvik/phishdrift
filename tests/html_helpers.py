"""Shared helpers for the tier B (HTML feature) tests: small pages that pass the usability rules."""

from __future__ import annotations

import math

from features.html_features import extract_html
from features.lists import Lists

LISTS = Lists.build(
    platforms=["github.io", "web.app"],
    brands=["paypal", "amazon", "hdfcbank", "bankofamerica"],
    shorteners=["bit.ly"],
)
URL = "https://www.example.com/shop/index.html"
FILLER = "Ordinary readable sentence for the visitor of this page. " * 6  # about 330 characters


def page(body: str = "", head: str = "", title: str | None = "Example Shop", filler: bool = True):
    """A complete page; ``filler`` adds enough visible text to be usable (200 characters)."""
    title_tag = f"<title>{title}</title>" if title is not None else ""
    text = f"<p>{FILLER}</p>" if filler else ""
    return f"<!DOCTYPE html><html><head>{title_tag}{head}</head><body>{text}{body}</body></html>"


def feats(html: str, url: str = URL, lists: Lists = LISTS) -> dict[str, float]:
    return extract_html(url, html, lists=lists)


def isnan(x: float) -> bool:
    return math.isnan(x)
