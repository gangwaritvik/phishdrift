"""Deduplication before splitting.

1. Exact: URLs are normalized (phishdrift.domains.normalize_url). The earliest-dated copy
   is kept. A URL labelled both phishing and benign is dropped entirely.
2. Near-identical HTML: 64-bit SimHash over word shingles of the visible text; pages
   within a small Hamming distance form a cluster and only the earliest page is kept.
   Clustering is within a label by default, because phishing kits clone real pages and a
   phish that looks like its target must not be removed.
"""

from __future__ import annotations

import hashlib
import html as htmllib
import re
from dataclasses import asdict, dataclass

import numpy as np
import pandas as pd

from phishdrift.domains import normalize_url

_DROP_BLOCKS = re.compile(r"<(script|style|noscript|template)\b.*?</\1\s*>|<!--.*?-->", re.S | re.I)
_TAGS = re.compile(r"<[^>]+>")
_WORDS = re.compile(r"\w+", re.U)
N_BANDS = 4
BAND_BITS = 64 // N_BANDS


@dataclass
class DedupStats:
    n_in: int = 0
    exact_duplicates: int = 0
    label_conflicts: int = 0
    near_duplicate_html: int = 0
    n_out: int = 0

    def as_dict(self) -> dict[str, int]:
        return asdict(self)


def visible_tokens(html: str, max_chars: int) -> list[str]:
    text = _DROP_BLOCKS.sub(" ", html[:max_chars])
    text = htmllib.unescape(_TAGS.sub(" ", text))
    return _WORDS.findall(text.lower())


def simhash(tokens: list[str], shingle_size: int) -> int:
    """Signed 64-bit SimHash of word shingles (signed so it fits an int64 column)."""
    if len(tokens) < shingle_size:
        shingles = [" ".join(tokens)]
    else:
        shingles = [
            " ".join(tokens[i : i + shingle_size]) for i in range(len(tokens) - shingle_size + 1)
        ]
    digests = np.frombuffer(
        b"".join(hashlib.blake2b(s.encode(), digest_size=8).digest() for s in shingles),
        dtype=np.uint8,
    ).reshape(-1, 8)
    bits = np.unpackbits(digests, axis=1).astype(np.int32)  # (n_shingles, 64)
    votes = (2 * bits - 1).sum(axis=0)
    packed = np.packbits((votes > 0).astype(np.uint8))
    return int(np.frombuffer(packed.tobytes(), dtype=">i8")[0])


def html_simhash(html: str | None, cfg: dict) -> int | None:
    """SimHash of a page, or None when it has too little visible text to compare."""
    if not html:
        return None
    tokens = visible_tokens(html, cfg["html_max_chars"])
    if len(tokens) < cfg["html_min_tokens"]:
        return None
    return simhash(tokens, cfg["shingle_size"])


def hamming(a: int, b: int) -> int:
    return ((a ^ b) & 0xFFFFFFFFFFFFFFFF).bit_count()


def _keep_order(df: pd.DataFrame) -> pd.DataFrame:
    """Earliest date first (undated last), then lowest row_id, for 'keep first' rules."""
    return df.sort_values(["date", "row_id"], na_position="last", kind="stable")


def exact_dedup(df: pd.DataFrame, stats: DedupStats) -> pd.DataFrame:
    df = df.assign(url_norm=df["url"].map(normalize_url))
    n_labels = df.groupby("url_norm")["label"].transform("nunique")
    conflicts = n_labels > 1
    stats.label_conflicts = int(conflicts.sum())
    df = df.loc[~conflicts]
    before = len(df)
    df = _keep_order(df).drop_duplicates("url_norm", keep="first")
    stats.exact_duplicates = before - len(df)
    return df.drop(columns="url_norm")


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict = {}

    def find(self, x):
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a, b) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def near_dup_clusters(hashes: list[int], max_hamming: int) -> dict[int, int]:
    """Map each distinct hash to a cluster root. Exact for max_hamming < N_BANDS
    (pigeonhole: two hashes within that distance agree on at least one band)."""
    if max_hamming >= N_BANDS:
        raise ValueError(f"simhash_max_hamming must be < {N_BANDS}")
    uniq = sorted(set(hashes))
    uf = _UnionFind()
    for band in range(N_BANDS):
        shift = band * BAND_BITS
        buckets: dict[int, list[int]] = {}
        for h in uniq:
            buckets.setdefault((h >> shift) & 0xFFFF, []).append(h)
        for members in buckets.values():
            for i, a in enumerate(members):
                for b in members[i + 1 :]:
                    if hamming(a, b) <= max_hamming:
                        uf.union(a, b)
    return {h: uf.find(h) for h in uniq}


def near_dup_html(df: pd.DataFrame, cfg: dict, stats: DedupStats) -> pd.DataFrame:
    has = df["html_simhash"].notna()
    if not has.any():
        return df
    hashed = df.loc[has]
    groups = (
        [hashed]
        if not cfg["near_dup_within_label_only"]
        else [g for _, g in hashed.groupby("label")]
    )
    drop_ids: list[int] = []
    for g in groups:
        roots = near_dup_clusters(
            g["html_simhash"].astype("int64").tolist(), cfg["simhash_max_hamming"]
        )
        g = _keep_order(g.assign(_cluster=g["html_simhash"].astype("int64").map(roots)))
        dup = g.duplicated("_cluster", keep="first")
        drop_ids.extend(g.loc[dup, "row_id"].tolist())
    stats.near_duplicate_html = len(drop_ids)
    return df.loc[~df["row_id"].isin(drop_ids)]


def deduplicate(df: pd.DataFrame, cfg: dict) -> tuple[pd.DataFrame, DedupStats]:
    """Run exact then near-dup HTML dedup. ``df`` needs row_id and html_simhash columns."""
    stats = DedupStats(n_in=len(df))
    df = exact_dedup(df, stats)
    df = near_dup_html(df, cfg, stats)
    df = df.sort_values("row_id").reset_index(drop=True)
    stats.n_out = len(df)
    return df, stats
