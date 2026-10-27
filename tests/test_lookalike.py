"""The look-alike payload is built from the brand lists, and the committed file is current."""

from __future__ import annotations

import json

from features.lookalike import OUT_FILE, build_payload


def test_committed_payload_is_current() -> None:
    assert json.loads(OUT_FILE.read_text(encoding="utf-8")) == build_payload()


def test_payload_comes_from_the_lists() -> None:
    p = build_payload()
    assert p["rules"] == ["homograph", "edit1"]
    assert all(len(b) >= 4 for b in p["brands"]) and p["brands"] == sorted(set(p["brands"]))
    assert "paypal.com" in p["domains"] and all("." in d for d in p["domains"])
    assert p["skeleton_map"]["а"] == "a"  # Cyrillic a
