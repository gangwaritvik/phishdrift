"""Generate ``docs/FEATURE_DICTIONARY.md`` from the registry. Never edit that file by hand."""

from __future__ import annotations

from pathlib import Path

from features.registry import GROUPS, PAPERS, REGISTRY

DICTIONARY_FILE = Path(__file__).resolve().parent.parent / "docs" / "FEATURE_DICTIONARY.md"


def render() -> str:
    lines = [
        "# Feature dictionary",
        "",
        "Generated from `features/registry.py` by `python -m features dictionary`.",
        "Do not edit by hand; a test fails when this file is stale.",
        "",
        f"{len(REGISTRY)} features. Missing values are NaN, never 0. All features here are tier A",
        "(URL only, all samples, computed in the browser). The URL is canonicalised first: scheme,",
        "leading `www.`, fragment and trailing `/` are dropped, and a hosting-platform domain is",
        "replaced by a neutral token (only `is_hosting_platform` is exposed).",
        "",
        "Papers: " + "; ".join(f"**{k}** = {v}" for k, v in PAPERS.items()) + ".",
        "",
    ]
    for group in GROUPS:
        rows = [f for f in REGISTRY if f.group == group]
        lines += [
            f"## {group} ({len(rows)})",
            "",
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
        lines.append("")
    return "\n".join(lines)


def write() -> Path:
    DICTIONARY_FILE.write_text(render(), encoding="utf-8")
    return DICTIONARY_FILE
