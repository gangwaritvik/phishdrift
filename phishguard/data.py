# ruff: noqa: E501
"""PhishGuard study data: populations, cells, representations and the feature cache.

A population is one class from one source (``phish:phiusiil``, ``benign:crawl``). A cell pairs one
phishing and one benign population. Every row is sampled once per population, so cells share rows
(the report states this). Features are computed once per representation and cached as parquet.
"""

from __future__ import annotations

import dataclasses
import hashlib
from functools import partial
from multiprocessing import Pool
from pathlib import Path

import numpy as np
import pandas as pd

from features.extract import extract
from features.fit import Fitted
from features.lists import Lists
from features.registry import NAMES, NAMES_B
from features.urlparts import parse
from phishdrift.domains import url_depth, url_key

REPS = ("R1", "R2", "R3", "R4")
# Sources whose domains a population can share (the crawl was seeded from PhiUSIIL and URL-Phish
# legitimate domains), used to keep transfer test sets independent of the training cell.
FAMILY = {"crawl": {"crawl", "phiusiil", "urlphish", "live"}}


def family(pop: str) -> set[str]:
    src = pop.split(":", 1)[1]
    return FAMILY.get(src, {src})


def represent(url: str, domain: str, rep: str, platforms: frozenset[str]) -> str:
    """R1 raw; R2 host only (path and query removed); R3 also a leading www removed;
    R4 ``www.<registrable domain>``. The scheme is dropped by the feature engine anyway."""
    if rep == "R1":
        return url
    if rep == "R4":
        return f"https://www.{domain}"
    p = parse(url, platforms) if isinstance(url, str) else None
    host = (p.host if p else domain) or domain
    if rep == "R3" and host.startswith("www."):
        host = host[4:]
    return f"https://{host}"


def _select(meta: pd.DataFrame, pop: str) -> pd.DataFrame:
    kind, src = pop.split(":", 1)
    label = 1 if kind == "phish" else 0
    df = meta[meta["label"] == label]
    if src == "crawl":
        return df[df["origin"] == "crawl"]
    df = df[df["source"] == src]
    return df[df["origin"] != "crawl"]


def _cap(df: pd.DataFrame, per_domain: int, total: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    df = df.sample(frac=1.0, random_state=int(rng.integers(1 << 31)))
    df = df.groupby("domain", sort=False).head(per_domain)
    return df.head(total)


def build_populations(data: Path, cfg: dict, html_uids: set[str]) -> pd.DataFrame:
    """Rows for every population of part A and part B (``pop``, ``part``)."""
    meta = pd.concat(
        [pd.read_parquet(data / f"meta_{p}.parquet") for p in ("pool", "heldout_source")],
        ignore_index=True,
    )
    meta["domain"] = meta["domain"].astype(str).str.lower()
    out = []
    for part, ph, bn in (
        ("A", cfg["phishing"], cfg["benign"]),
        ("B", cfg["phishing_b"], cfg["benign_b"]),
    ):
        for pop in [f"phish:{s}" for s in ph] + [f"benign:{s}" for s in bn]:
            rows = _select(meta, pop)
            if part == "B":
                rows = rows[rows["uid"].isin(html_uids)]
            rows = _cap(rows, cfg["cap_per_domain"], cfg["cap_per_class"], cfg["seed"])
            out.append(rows.assign(pop=pop, part=part))
    pops = pd.concat(out, ignore_index=True)
    pops["depth"] = [url_depth(u) for u in pops["url"]]
    pops["_key"] = pops["url"].map(url_key)
    return pops[["uid", "url", "domain", "label", "depth", "pop", "part", "_key"]]


def _features(urls: list[str], lists: Lists) -> list[dict]:
    return [extract(u, lists=lists, fitted=Fitted()) for u in urls]


def featurise(urls: list[str], lists: Lists, workers: int) -> pd.DataFrame:
    """Tier A features (fitted ones left NaN; refitted per split) plus the char n-gram text."""
    chunks = [urls[i : i + 2000] for i in range(0, len(urls), 2000)]
    with Pool(workers) as pool:
        rows = [r for part in pool.map(partial(_features, lists=lists), chunks) for r in part]
    df = pd.DataFrame(rows, columns=list(NAMES)).astype("float32")
    df["_text"] = [p.canon if (p := parse(u, lists.platforms)) else "" for u in urls]
    return df


def unmasked(lists: Lists) -> Lists:
    return dataclasses.replace(lists, platforms=frozenset())


def prepare(
    data: Path, out: Path, cfg: dict, lists: Lists, workers: int, natural_urls: Path | None
) -> None:
    """Write populations.parquet and features_<rep>.parquet (plus R4u = R4 without masking)."""
    out.mkdir(parents=True, exist_ok=True)
    fb = pd.read_parquet(data / "features_b.parquet")
    pops = build_populations(data, cfg, set(fb["uid"]))
    pops.to_parquet(out / "populations.parquet", index=False)
    rows = pops.drop_duplicates("uid")
    for rep, lst in [*((r, lists) for r in REPS), ("R4u", unmasked(lists))]:
        path = out / f"features_{rep}.parquet"
        if path.exists():
            continue
        base = "R4" if rep == "R4u" else rep
        reps = [
            represent(u, d, base, lists.platforms)
            for u, d in zip(rows["url"], rows["domain"], strict=True)
        ]
        feats = featurise(reps, lst, workers)
        feats.insert(0, "uid", rows["uid"].to_numpy())
        feats["_rep_url"] = reps
        feats.to_parquet(path, index=False)
        print(f"features {rep}: {len(feats):,} rows", flush=True)
    fb[fb["uid"].isin(set(pops["uid"]))].to_parquet(out / "features_page.parquet", index=False)
    if natural_urls is not None and not (out / "natural_a.parquet").exists():
        nat = pd.read_csv(natural_urls)
        nat = nat[nat["ok"].astype(bool)].drop_duplicates("url")
        feats = featurise(nat["url"].tolist(), lists, workers)
        feats["url"] = nat["url"].to_numpy()
        feats["_rep_url"] = feats["url"]
        feats["domain"] = nat["domain"].astype(str).str.lower().to_numpy()
        feats.to_parquet(out / "natural_a.parquet", index=False)


def prepare_natural_b(html_dir: Path, out: Path, lists: Lists) -> None:
    """Natural legitimate pages with usable HTML: tier A (R1) + tier B features."""
    path = out / "natural_b.parquet"
    if path.exists() or not html_dir.exists():
        return
    from experiments.ood_fpr_b import load_ood_b

    df, _ = load_ood_b(html_dir, lists)
    keep = [*NAMES, *NAMES_B, "url", "domain", "_text"]
    df[keep].assign(_rep_url=df["url"]).to_parquet(path, index=False)


def unit_hash(domain: str, seed: int, split: int) -> float:
    h = hashlib.blake2b(f"{seed}:{split}:{domain}".encode(), digest_size=8).digest()
    return int.from_bytes(h, "big") / 2**64


def assign_split(domains: pd.Series, seed: int, split: int, frac: dict) -> np.ndarray:
    """Domain-grouped train / cal / test: the same domain lands on the same side in every cell,
    representation and model of one split."""
    u = np.array([unit_hash(d, seed, split) for d in domains])
    return np.where(
        u < frac["train"], "train", np.where(u < frac["train"] + frac["cal"], "cal", "test")
    )
