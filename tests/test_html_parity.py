"""The Python side of the tier B Python-JS parity check (JS side: js/test/html_parity.test.js)."""

import html.entities
import json
import math
import re
import unicodedata

import pytest

from features import html_parity
from features.html_features import (
    FEED_CHUNK,
    MAX_EVENTS,
    MAX_HTML_CHARS,
    MAX_STACK,
    MIN_VISIBLE_CHARS,
)
from features.registry import NAMES_B


def _same(a, b) -> bool:
    if a is None or b is None:
        return a is None and b is None
    return math.isclose(a, b, rel_tol=1e-12)


def test_html_parity_fixture_matches_python_now():
    stored = json.loads(html_parity.PARITY_FILE_B.read_text(encoding="utf-8"))
    hint = "run `python -m features parity`"
    assert stored["names"] == list(NAMES_B), f"feature list changed: {hint}"
    assert len(stored["cases"]) >= html_parity.MIN_CASES
    fresh = html_parity.parity_fixture_b()
    assert [(c["url"], c["html"]) for c in stored["cases"]] == [
        (c["url"], c["html"]) for c in fresh["cases"]
    ], f"fixture pages changed: {hint}"
    diffs = []
    for k, (old, new) in enumerate(zip(stored["cases"], fresh["cases"], strict=True)):
        if old["status"] != new["status"]:
            diffs.append(f"#{k} status: fixture {old['status']}, python {new['status']}")
            continue
        for name, a, b in zip(NAMES_B, old["values"], new["values"], strict=True):
            if not _same(a, b):
                diffs.append(f"#{k} {old['url']!r} {name}: fixture {a}, python {b}")
    if diffs and stored["parser"] != html_parity.parser_fingerprint():
        pytest.skip(
            f"this CPython's html.parser differs from the one the fixture was written with "
            f"({stored['python']}) and gives {len(diffs)} different values"
        )
    assert not diffs, f"{hint}\n" + "\n".join(diffs[:20])


def test_fixture_covers_the_edge_cases():
    """The pages exercise the caps and the feed boundary, and include every status."""
    pages = html_parity.parity_pages()
    lengths = [len(html_parity.build_html(spec)) for _, spec in pages]
    assert max(lengths) > MAX_HTML_CHARS
    assert any(FEED_CHUNK < n < 2 * FEED_CHUNK for n in lengths)
    stored = json.loads(html_parity.PARITY_FILE_B.read_text(encoding="utf-8"))
    statuses = {c["status"] for c in stored["cases"]}
    assert {"ok", "empty", "no_url", "short", "junk", "failed"} <= statuses
    texts = [html_parity.build_html(spec) for _, spec in pages]
    assert any(t.count("<div>") > MAX_STACK for t in texts)
    assert any(2 * t.count("< ") > MAX_EVENTS for t in texts)  # "<" and " " are two events
    assert any(len(t) < MIN_VISIBLE_CHARS + 20 for t in texts)
    assert any(any(ord(ch) > 0xFFFF for ch in t) for t in texts)  # astral characters


def test_pydata_tables_match_python():
    text = html_parity.PYDATA_FILE.read_text(encoding="utf-8")
    entities = re.search(r"^export const HTML5 = (.*);$", text, re.M)
    assert entities and json.loads(entities.group(1)) == html.entities.html5
    version = re.search(r'^export const UNICODE_VERSION = "(.*)";$', text, re.M).group(1)
    if version != unicodedata.unidata_version:
        pytest.skip(f"Unicode {unicodedata.unidata_version} here, {version} in pydata.js")
    assert text.split("\n", 2)[2] == html_parity.pydata_source().split("\n", 2)[2], (
        "run `python -m features export-js`"
    )
