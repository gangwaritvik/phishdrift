"""Look-alike training examples for the tier A address model (default off).

Used by ``experiments.lookalike_a`` (E0-E3), ``experiments.hybrid_a --variant hybrid2_la`` and
``models.export_hybrid --lookalike``. ``with_lookalikes`` adds, to the TRAINING rows of split k,
look-alike domains of the brands outside the split's held-out brand fold (label phishing) and the
official domains of the same brands (label legitimate). Brands are split into ``n_brand_folds``
folds by hash and split k holds out fold ``k % n_brand_folds``: its brands, and every variant of
them, never reach training (hard failure otherwise), so the evaluation can ask about unseen brands.
Nothing here changes a dataset on disk. Settings: ``configs/lookalike_exp.yaml``.
"""

from __future__ import annotations

import hashlib
import random

import pandas as pd

from attacks.lookalike import TRAIN_STYLES, make_domain
from experiments.tier_a import apply_fitted
from features.brand_mismatch import COLUMNS, BrandMismatch
from features.extract import extract
from features.fit import Fitted
from features.lists import Lists
from features.registry import NAMES
from features.urlparts import parse
from phishdrift.config import load_config


class LeakageError(RuntimeError):
    pass


# ---- frames --------------------------------------------------------------------------------------


def add_brand(df: pd.DataFrame, bm: BrandMismatch) -> pd.DataFrame:
    cols = pd.DataFrame([bm.features(p) for p in df["_parts"]], index=df.index, columns=COLUMNS)
    return df.assign(**{c: cols[c].astype("float32") for c in COLUMNS})


def url_frame(urls: list[str], lists: Lists, fitted: Fitted, bm: BrandMismatch) -> pd.DataFrame:
    """Tier A features, text pieces and brand columns of arbitrary URLs."""
    feats = pd.DataFrame(
        [extract(u, lists=lists, fitted=Fitted()) for u in urls], columns=list(NAMES)
    ).astype("float32")
    feats["url"] = urls
    feats["_parts"] = [parse(u, lists.platforms) for u in urls]
    feats["_text"] = [p.canon if p is not None else "" for p in feats["_parts"]]
    feats["domain"] = [p.domain if p is not None else "" for p in feats["_parts"]]
    return add_brand(apply_fitted(feats, fitted), bm)


def path_of(parts) -> str:
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


def real_paths(frame: pd.DataFrame) -> list[str]:
    return [
        path_of(p) for p, d in zip(frame["_parts"], frame["depth"], strict=True) if p and d >= 1
    ]


# ---- brands --------------------------------------------------------------------------------------


def brand_fold(brand: str, n_folds: int) -> int:
    return int(hashlib.md5(brand.encode()).hexdigest(), 16) % n_folds


def own_tld(bm: BrandMismatch, brand: str, rng: random.Random) -> str | None:
    doms = sorted(bm.owned.get(brand, ()))
    return rng.choice(doms).split(".", 1)[1] if doms else None


def augmentation(train, brands, bm, exp, lists, fitted, taken, rng) -> pd.DataFrame:
    """Look-alike phishing rows and official-domain legitimate rows from ``brands`` only."""
    n_each = int(exp["aug_fraction"] * len(train))
    paths = real_paths(train)
    tlds = tuple(exp["tlds"])

    def path() -> str:
        return "/" if rng.random() < exp["aug_bare_share"] or not paths else rng.choice(paths)

    pos, neg = [], []
    for _ in range(n_each * 30):
        if len(pos) >= n_each:
            break
        b = rng.choice(brands)
        dom = make_domain(rng.choice(TRAIN_STYLES), b, rng, own_tld(bm, b, rng), tlds)
        if not dom or dom in bm.official or dom in taken or dom.split(".")[0] in bm.brands:
            continue
        pos.append((f"https://{dom}{path()}", b))
    with_domains = [b for b in brands if bm.owned.get(b)]
    while len(neg) < n_each:
        b = rng.choice(with_domains)
        host = rng.choice(sorted(bm.owned[b]))
        host = f"www.{host}" if rng.random() < 0.3 else host
        neg.append((f"https://{host}{path()}", b))
    urls = [u for u, _ in pos] + [u for u, _ in neg]
    out = url_frame(urls, lists, fitted, bm)
    out["domain"] = [f"brand:{b}" for _, b in pos + neg]  # a brand's variants share one group
    out["label"] = [1] * len(pos) + [0] * len(neg)
    out["weight"] = float(train["weight"].median())
    return out


def split_brands(lists: Lists, exp: dict, k: int) -> tuple[list[str], list[str]]:
    """(training brands, held-out brands) of split k."""
    names = sorted(b for b in lists.brands if b.isalpha() and len(b) >= exp["min_brand_len"])
    fold = k % exp["n_brand_folds"]
    held = [b for b in names if brand_fold(b, exp["n_brand_folds"]) == fold]
    return [b for b in names if brand_fold(b, exp["n_brand_folds"]) != fold], held


def with_lookalikes(
    train: pd.DataFrame,
    k: int,
    lists: Lists,
    fitted: Fitted,
    taken: set[str],
    exp: dict | None = None,
    keep_brand_columns: bool = False,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """(train + look-alike rows, the look-alike rows). ``taken`` = registrable domains of every
    real row in the split (train, cal, test, holdouts): a generated name equal to one is dropped."""
    exp = exp or load_config("lookalike_exp")
    bm = BrandMismatch.from_lists(min_brand_len=exp["min_brand_len"])
    train_brands, held = split_brands(lists, exp, k)
    rng = random.Random(exp["seed"] + k)
    aug = augmentation(train, train_brands, bm, exp, lists, fitted, taken, rng)
    if set(held) & {g[6:] for g in aug["domain"]} or set(aug["domain"]) & set(train["domain"]):
        raise LeakageError("look-alike rows overlap a held-out brand or a real training domain")
    if not keep_brand_columns:
        aug = aug.drop(columns=list(COLUMNS))
    return pd.concat([train, aug], ignore_index=True), aug
