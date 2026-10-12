"""The Python side of the Python-JS parity check (the JS side is js/test/parity.test.js)."""

import json
import math

from features import js_export
from features.registry import NAMES


def test_parity_fixture_matches_python_now():
    stored = json.loads(js_export.PARITY_FILE.read_text(encoding="utf-8"))
    assert stored["names"] == list(NAMES), "feature list changed: run `python -m features parity`"
    assert len(stored["cases"]) >= 200
    fresh = js_export.parity_fixture()
    assert [c["url"] for c in stored["cases"]] == [c["url"] for c in fresh["cases"]]
    for old, new in zip(stored["cases"], fresh["cases"], strict=True):
        for name, a, b in zip(NAMES, old["values"], new["values"], strict=True):
            same = (a is None and b is None) or (
                a is not None and b is not None and math.isclose(a, b, rel_tol=1e-12)
            )
            hint = "run `python -m features parity`"
            assert same, f"{old['url']!r} {name}: fixture {a}, python {b} ({hint})"


def test_psl_export_contains_punycode_aliases():
    rules = set(js_export.psl_rules())
    assert {"рф", "xn--p1ai", "co.uk", "*.ck", "!www.ck"} <= rules
