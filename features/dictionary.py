"""Generate ``docs/FEATURE_DICTIONARY.md`` from the registry. Never edit that file by hand."""

from __future__ import annotations

from pathlib import Path

from features.registry import (
    GROUPS,
    GROUPS_B,
    GROUPS_C,
    PAPERS,
    REGISTRY,
    REGISTRY_B,
    REGISTRY_C,
    Feature,
)

DICTIONARY_FILE = Path(__file__).resolve().parent.parent / "docs" / "FEATURE_DICTIONARY.md"


def _table(rows: list[Feature]) -> list[str]:
    lines = [
        "| name | definition | papers | availability | cost | in browser |",
        "|---|---|---|---|---|---|",
    ]
    for f in rows:
        definition = f.definition.replace("|", "\\|")
        browser = "yes" if f.in_browser else "no"
        lines.append(
            f"| `{f.name}` | {definition} | {f.papers} | {f.availability} | "
            f"{f.runtime_cost} | {browser} |"
        )
    return lines


def render() -> str:
    lines = [
        "# Feature dictionary",
        "",
        "Generated from `features/registry.py` by `python -m features dictionary`.",
        "Do not edit by hand; a test fails when this file is stale.",
        "",
        f"{len(REGISTRY)} tier A features, {len(REGISTRY_B)} tier B features and "
        f"{len(REGISTRY_C)} tier C features.",
        "Missing values are NaN, never 0. Each tier is a separate table with separate names:",
        "a tier B or tier C column never appears in a tier A row.",
        "",
        "Papers: " + "; ".join(f"**{k}** = {v}" for k, v in PAPERS.items()) + ".",
        "",
        f"## Tier A: URL features ({len(REGISTRY)})",
        "",
        "URL only, all samples, computed in the browser. The URL is canonicalised first: scheme,",
        "leading `www.`, fragment and trailing `/` are dropped, and a hosting-platform domain is",
        "replaced by a neutral token (only `is_hosting_platform` is exposed).",
        "",
    ]
    for group in GROUPS:
        rows = [f for f in REGISTRY if f.group == group]
        lines += [f"### {group} ({len(rows)})", "", *_table(rows), ""]
    lines += [
        f"## Tier B: HTML features ({len(REGISTRY_B)})",
        "",
        "Samples with HTML only (content script in the browser). One pass of the standard library",
        "HTML parser over the first 500,000 characters of the page. Every tier B value is NaN when",
        "the page has no usable HTML: missing, under 200 characters of visible text, or an obvious",
        "parked, takedown or error page. Ratios are NaN when their denominator is zero. Links,",
        "resources and form actions are compared with the page's registrable domain after",
        "platform-identity masking, so a hosting platform's name never reaches a feature. No",
        "popularity or blocklist signal is used, and nothing is fetched.",
        "",
    ]
    for group in GROUPS_B:
        rows = [f for f in REGISTRY_B if f.group == group]
        lines += [f"### {group} ({len(rows)})", "", *_table(rows), ""]
    lines += [
        f"## Tier C: domain, DNS and TLS features ({len(REGISTRY_C)})",
        "",
        "Live-feed hosts only, captured once when the host first appeared in a feed",
        "(`collector/domain_capture.py`); never computed later for old dataset URLs. Computed on",
        "the backend, not in the browser. Ages are in days relative to the host's capture time.",
        "Missing is NaN: no RDAP data, a DNS query that errored for that record type, or a TLS",
        "handshake without a certificate (certificate fields exist only for a verified",
        "handshake). Liveness facts (whether the host still resolves) are not features, and no",
        "popularity or blocklist signal is used.",
        "",
    ]
    for group in GROUPS_C:
        rows = [f for f in REGISTRY_C if f.group == group]
        lines += [f"### {group} ({len(rows)})", "", *_table(rows), ""]
    return "\n".join(lines)


def write() -> Path:
    DICTIONARY_FILE.write_text(render(), encoding="utf-8")
    return DICTIONARY_FILE
