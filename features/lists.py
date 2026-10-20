"""Frozen word lists used by the URL features, plus the platform list for masking.

The lists live in ``configs/lists/*.txt`` and ``configs/platforms.yaml`` and are written by
``python -m features lists`` (see ``features/scrape.py``). Each text file has ``#`` comment
lines naming its source and fetch date. One entry per line, lowercase.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

import yaml

PLATFORM_TOKEN = "hostingplatform.com"  # neutral host that replaces every platform domain
MIN_BRAND_LEN = 4  # shorter brand names match too many unrelated words
ROOT = Path(__file__).resolve().parent.parent
LISTS_DIR = ROOT / "configs" / "lists"
PLATFORMS_FILE = ROOT / "configs" / "platforms.yaml"


def read_list(path: Path) -> list[str]:
    if not Path(path).exists():
        return []
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [ln.strip().lower() for ln in lines if ln.strip() and not ln.startswith("#")]


def read_platforms(path: Path = PLATFORMS_FILE) -> frozenset[str]:
    if not Path(path).exists():
        return frozenset()
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return frozenset(str(d).lower() for d in data.get("platforms", []))


def _deletes(word: str, max_dist: int) -> set[str]:
    """All strings obtained by deleting up to ``max_dist`` characters (symmetric-delete index)."""
    out = {word}
    frontier = {word}
    for _ in range(max_dist):
        frontier = {w[:i] + w[i + 1 :] for w in frontier for i in range(len(w))}
        out |= frontier
    return out


def lists_digest(lists: Lists) -> str:
    """Short hash of every word list, so files built with other lists can be told apart."""
    payload = {
        name: sorted(getattr(lists, name))
        for name in (
            "platforms",
            "brands",
            "keywords",
            "shorteners",
            "suspicious_tlds",
            "redirect_params",
        )
    }
    return hashlib.sha256(json.dumps(payload).encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class Lists:
    platforms: frozenset[str] = frozenset()
    brands: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    shorteners: frozenset[str] = frozenset()
    suspicious_tlds: frozenset[str] = frozenset()
    redirect_params: frozenset[str] = frozenset()
    _delete_index: dict[str, tuple[str, ...]] = field(default_factory=dict, compare=False)

    @classmethod
    def build(
        cls,
        *,
        platforms=(),
        brands=(),
        keywords=(),
        shorteners=(),
        suspicious_tlds=(),
        redirect_params=(),
    ) -> Lists:
        brand_tokens = tuple(sorted({b for b in brands if len(b) >= MIN_BRAND_LEN}))
        index: dict[str, set[str]] = {}
        for b in brand_tokens:
            for d in _deletes(b, 2):
                index.setdefault(d, set()).add(b)
        return cls(
            platforms=frozenset(platforms),
            brands=brand_tokens,
            keywords=tuple(sorted(set(keywords))),
            shorteners=frozenset(shorteners),
            suspicious_tlds=frozenset(suspicious_tlds),
            redirect_params=frozenset(redirect_params),
            _delete_index={k: tuple(sorted(v)) for k, v in index.items()},
        )

    def brand_candidates(self, label: str) -> set[str]:
        """Brands possibly within edit distance 2 of ``label`` (verify with the true distance)."""
        found: set[str] = set()
        for d in _deletes(label, 2):
            found.update(self._delete_index.get(d, ()))
        return found


@cache
def load_lists(lists_dir: str | None = None, platforms_file: str | None = None) -> Lists:
    base = Path(lists_dir) if lists_dir else LISTS_DIR
    return Lists.build(
        platforms=read_platforms(Path(platforms_file) if platforms_file else PLATFORMS_FILE),
        brands=read_list(base / "brands.txt"),
        keywords=read_list(base / "keywords.txt"),
        shorteners=read_list(base / "shorteners.txt"),
        suspicious_tlds=read_list(base / "suspicious_tlds.txt"),
        redirect_params=read_list(base / "redirect_params.txt"),
    )
