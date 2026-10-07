"""Pooled corpus build: every source -> one deduplicated, leakage-controlled corpus.

Order (each step's removals are counted for the data card):
 1. canonical-URL dedup across all sources (conflicting labels dropped)
 2. near-identical HTML removal within label
 3. remove domains that appear in more than one phishing source, from all sources (§8)
 4. domain ownership: a domain present in several sources stays with one of them
 5. cap URLs per domain
 6. carve out the held-out source, the newest time slice and evaluation-only sources;
    drop pool rows sharing a domain with any of them
 7. depth balance on the pool, then the depth check (a bucket fails if more than
    ``fail_share`` of it is one class; the pipeline stops after writing the data card)
 8. per-source class weights for the pool

Steps work on metadata only (no HTML); the pipeline streams HTML into the outputs later.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from data_pipeline.dedup import near_dup_html
from data_pipeline.split import assert_disjoint
from phishdrift.domains import url_key

log = logging.getLogger(__name__)

POOL, HELDOUT, TIME_SLICE, EVAL_ONLY = "pool", "heldout_source", "time_slice", "eval_only"
DROPPED_OVERLAP = "dropped_holdout_overlap"


class DepthImbalanceError(RuntimeError):
    pass


@dataclass
class CorpusStats:
    rows_in: int = 0
    removed: dict[str, dict[str, int]] = field(default_factory=dict)  # step -> source -> n
    shared_phishing_domains: int = 0
    depth_check: dict = field(default_factory=dict)

    def record(self, step: str, before: pd.DataFrame, after: pd.DataFrame) -> None:
        gone = before.loc[~before.index.isin(after.index), "source"].value_counts()
        self.removed[step] = {k: int(v) for k, v in gone.items()}
        log.info("%s: removed %d rows", step, int(gone.sum()))


def _priority_rank(df: pd.DataFrame, priority: list[str]) -> pd.Series:
    order = {s: i for i, s in enumerate(priority)}
    return df["source"].map(lambda s: order.get(s, len(order)))


def keep_order(df: pd.DataFrame, priority: list[str]) -> pd.DataFrame:
    """Earliest date first (undated last), then source priority, then uid."""
    return (
        df.assign(_prio=_priority_rank(df, priority))
        .sort_values(["date", "_prio", "uid"], na_position="last", kind="stable")
        .drop(columns="_prio")
    )


def dedup_urls(df: pd.DataFrame, priority: list[str]) -> pd.DataFrame:
    """Canonical-URL dedup across all sources. A URL with both labels is dropped entirely."""
    keys = df["url"].map(url_key)
    conflict = keys.groupby(keys).transform("size").gt(1) & df.groupby(keys)["label"].transform(
        "nunique"
    ).gt(1)
    kept = keep_order(df.loc[~conflict], priority)
    return kept.loc[~kept["url"].map(url_key).duplicated(keep="first")]


def shared_phishing_domains(df: pd.DataFrame) -> set[str]:
    """Domains that appear in phishing rows of more than one source (mostly hosting
    platforms and shorteners, report §8)."""
    n_sources = df.loc[df["label"] == 1].groupby("domain")["source"].nunique()
    return set(n_sources.index[n_sources > 1])


def assign_domain_owner(df: pd.DataFrame, priority: list[str]) -> pd.DataFrame:
    """Keep each domain in one source: the one where it was seen earliest (undated counts
    as latest), ties broken by source priority."""
    per = (
        df.assign(_prio=_priority_rank(df, priority))
        .groupby(["domain", "source"])
        .agg(first=("date", "min"), prio=("_prio", "first"))
        .reset_index()
        .sort_values(["domain", "first", "prio"], na_position="last", kind="stable")
    )
    owner = per.drop_duplicates("domain").set_index("domain")["source"]
    return df.loc[df["source"] == df["domain"].map(owner)]


def cap_per_domain(df: pd.DataFrame, cap: int, seed: int) -> pd.DataFrame:
    """At most ``cap`` URLs per domain, chosen at random (seeded)."""
    r = pd.Series(np.random.default_rng(seed).random(len(df)), index=df.index)
    rank = r.groupby(df["domain"]).rank(method="first")
    return df.loc[rank <= cap]


def newest_slice_mask(df: pd.DataFrame, cfg: dict) -> pd.Series:
    """Rows in the newest time slice: listed origins (e.g. PhreshPhish's official later
    test split) plus, per listed source, rows dated on/after the source's cutoff."""
    mask = df["origin"].isin(cfg.get("origins") or [])
    for source, scfg in (cfg.get("sources") or {}).items():
        rows = df["source"] == source
        dated = df.loc[rows, "date"].dropna()
        if dated.empty:
            continue
        cutoff = (
            pd.Timestamp(scfg["cutoff"], tz="UTC")
            if scfg.get("cutoff")
            else dated.quantile(1 - scfg["newest_fraction"])
        )
        mask |= rows & (df["date"] >= cutoff)
    return mask


def carve_holdouts(df: pd.DataFrame, cfg: dict) -> pd.Series:
    """Label each row pool / heldout_source / time_slice / eval_only. Pool rows whose
    domain also occurs in a holdout are marked dropped, so holdouts stay unseen."""
    part = pd.Series(POOL, index=df.index, dtype=object)
    part[newest_slice_mask(df, cfg["time_slice"])] = TIME_SLICE
    part[df["source"] == cfg["heldout_source"]] = HELDOUT
    part[df["source"].isin(cfg.get("eval_only_sources") or [])] = EVAL_ONLY
    held_domains = set(df.loc[part != POOL, "domain"])
    part[(part == POOL) & df["domain"].isin(held_domains)] = DROPPED_OVERLAP
    return part


# --- depth -----------------------------------------------------------------------------


def depth_bucket(depth: pd.Series, top: int) -> pd.Series:
    """0, 1, ..., top-1, and 'top+' for everything deeper."""
    return depth.clip(upper=top).map(lambda d: f"{top}+" if d >= top else str(d))


def depth_table(df: pd.DataFrame, top: int) -> pd.DataFrame:
    """Rows per depth bucket and class, with each bucket's majority-class share."""
    t = (
        pd.crosstab(depth_bucket(df["depth"], top), df["label"])
        .reindex(columns=[0, 1], fill_value=0)
        .rename(columns={0: "benign", 1: "phishing"})
    )
    t["total"] = t["benign"] + t["phishing"]
    t["majority_share"] = (t[["benign", "phishing"]].max(axis=1) / t["total"]).round(4)
    t["benign_pct_of_class"] = (100 * t["benign"] / max(t["benign"].sum(), 1)).round(2)
    t["phishing_pct_of_class"] = (100 * t["phishing"] / max(t["phishing"].sum(), 1)).round(2)
    return t


def balance_depth(df: pd.DataFrame, cfg: dict, seed: int) -> pd.DataFrame:
    """In buckets where one class exceeds ``target_share``, downsample that class until it
    is at ``target_share``. Buckets whose minority has fewer than ``min_minority`` rows are
    left alone (the check then reports them)."""
    buckets = depth_bucket(df["depth"], cfg["top_bucket"])
    rng = np.random.default_rng(seed)
    drop: list = []
    target = cfg["target_share"]
    for _, idx in df.groupby(buckets).groups.items():
        part = df.loc[idx]
        counts = part["label"].value_counts()
        if len(counts) < 2 or counts.min() < cfg["min_minority"]:
            continue
        major = counts.idxmax()
        if counts.max() / counts.sum() <= target:
            continue
        keep_n = int(counts.min() * target / (1 - target))
        major_idx = part.index[part["label"] == major].to_numpy()
        drop.extend(rng.choice(major_idx, size=len(major_idx) - keep_n, replace=False))
    return df.drop(index=drop)


def check_depth(df: pd.DataFrame, cfg: dict) -> dict:
    """Depth table plus the buckets that are more than ``fail_share`` one class."""
    table = depth_table(df, cfg["top_bucket"])
    bad = table[table["majority_share"] > cfg["fail_share"]]
    return {
        "fail_share": cfg["fail_share"],
        "passed": bad.empty,
        "bad_buckets": {str(b): float(r.majority_share) for b, r in bad.iterrows()},
        "table": table.reset_index().rename(columns={"depth": "bucket"}).to_dict("records"),
    }


def enforce_depth(result: dict) -> None:
    """Raise DepthImbalanceError when the depth check failed (after reports are written)."""
    if not result["passed"]:
        raise DepthImbalanceError(
            f"depth buckets more than {result['fail_share']:.0%} one class: "
            + ", ".join(f"{b} ({v:.1%})" for b, v in result["bad_buckets"].items())
            + ". Add benign inner pages (python -m collector run) or deeper data first."
        )


# --- weights ---------------------------------------------------------------------------


def source_weights(df: pd.DataFrame, max_source_share: float) -> pd.Series:
    """Sample weights: within each source the classes it has carry equal weight; each
    source's share of total weight is proportional to its size, capped at
    ``max_source_share``. Mean weight is 1."""
    n = df.groupby("source").size().astype(float)
    share = n / n.sum()
    for _ in range(len(share)):  # iterative capping
        over = share > max_source_share
        if not over.any() or over.all():
            break
        excess = (share[over] - max_source_share).sum()
        share[over] = max_source_share
        share[~over] += excess * share[~over] / share[~over].sum()
    k = df.groupby("source")["label"].nunique()
    n_sc = df.groupby(["source", "label"])["label"].transform("size")
    w = df["source"].map(share) * len(df) / (df["source"].map(k) * n_sc)
    return (w / w.mean()).rename("weight")


# --- whole build -----------------------------------------------------------------------


def build_corpus(meta: pd.DataFrame, cfg: dict) -> tuple[pd.DataFrame, CorpusStats]:
    """Run steps 1-8 on the pooled metadata. Returns rows with ``part`` and ``weight``."""
    c = cfg["corpus"]
    priority = c["source_priority"]
    stats = CorpusStats(rows_in=len(meta))

    df = dedup_urls(meta, priority)
    stats.record("url_dedup", meta, df)

    before = df
    df, _ = near_dup_html(keep_order(df, priority), cfg["dedup"])
    stats.record("near_dup_html", before, df)

    shared = shared_phishing_domains(df)
    stats.shared_phishing_domains = len(shared)
    before, df = df, df.loc[~df["domain"].isin(shared)]
    stats.record("shared_phishing_domains", before, df)

    before, df = df, assign_domain_owner(df, priority)
    stats.record("domain_ownership", before, df)

    before, df = df, cap_per_domain(df, c["max_urls_per_domain"], c["seed"])
    stats.record("domain_cap", before, df)

    df = df.assign(part=carve_holdouts(df, cfg["holdouts"]))
    before, df = df, df.loc[df["part"] != DROPPED_OVERLAP]
    stats.record("holdout_domain_overlap", before, df)

    pool = df.loc[df["part"] == POOL]
    if c["depth"]["balance"]:
        balanced = balance_depth(pool, c["depth"], c["seed"])
        stats.record("depth_balance", pool, balanced)
        df = df.drop(index=pool.index.difference(balanced.index))
        pool = balanced
    stats.depth_check = check_depth(pool, c["depth"])

    assert_disjoint(df, df["part"])
    df = df.assign(weight=1.0)
    df.loc[pool.index, "weight"] = source_weights(pool, c["max_source_share"])
    return df.sort_values("uid").reset_index(drop=True), stats
