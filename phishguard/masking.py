# ruff: noqa: E501
"""Exploratory platform-masking test (question Q5), outside the frozen study design.

The frozen populations cap URLs per registrable domain, and the corpus drops domains shared by
several phishing sources, so hosting-platform URLs were almost absent (Q5 was "not testable").
This builds platform-bearing cells from the per-source interim files instead:

* platform rows = registrable domain listed in ``configs/platforms.yaml``; at most
  ``platform_test.cap_per_tenant`` URLs per tenant host, no cross-source domain removal;
* normal rows = the usual cap (``cap_per_domain`` per registrable domain);
* splits are grouped by registrable domain, so a held-out platform is unseen in training;
* masked (R4) against unmasked (R4u) tier A models, same holds rule as the study.

    python -m phishguard.masking count   # counts only, no training
    python -m phishguard.masking run     # cells, features, splits (resumable), report
"""

from __future__ import annotations

import argparse
import json
import os
from itertools import product
from multiprocessing import Pool
from pathlib import Path
from urllib.parse import urlsplit

os.environ.setdefault("PHISHDRIFT_THREADS", "1")

import numpy as np
import pandas as pd
import yaml

from data_pipeline.split import LeakageError
from features.fit import Fitted, fit
from features.lists import Lists, load_lists
from features.registry import NAMES
from features.urlparts import parse
from phishdrift.domains import url_key
from phishguard import analyze, run
from phishguard.data import assign_split, featurise, represent, unmasked

OUT = Path("data/interim/phishguard_masking")
TABLES = Path("reports/phishguard/tables")
MODELS_KEY = "masking_models"


def tenant(url: str) -> str:
    return (urlsplit(url if "//" in url else f"https://{url}").hostname or "").lower()


def load_source(interim: Path, name: str) -> pd.DataFrame:
    """url, domain, label of one interim source (no HTML is read)."""
    path = interim / f"{name}.parquet"
    df = pd.read_parquet(path, columns=["url", "domain", "label"])
    df["domain"] = df["domain"].astype(str).str.lower()
    df["source"] = name
    return df[df["label"].isin([0, 1])].reset_index(drop=True)


def counts(df: pd.DataFrame, platforms: frozenset[str]) -> pd.DataFrame:
    df = df.assign(plat=df["domain"].isin(platforms))
    df["tenant"] = [tenant(u) if p else "" for u, p in zip(df["url"], df["plat"], strict=True)]
    p = df[df["plat"]]
    out = df.groupby(["source", "label"]).size().rename("urls").to_frame()
    out["platform_urls"] = p.groupby(["source", "label"]).size()
    out["platform_domains"] = p.groupby(["source", "label"])["domain"].nunique()
    out["tenant_hosts"] = p.groupby(["source", "label"])["tenant"].nunique()
    out = out.fillna(0).astype(int)
    out["platform_share"] = (out["platform_urls"] / out["urls"]).round(4)
    return out.reset_index()


def population(df: pd.DataFrame, platforms: frozenset[str], cfg: dict, seed: int) -> pd.DataFrame:
    """One source and class: normal rows capped per domain, platform rows capped per tenant host."""
    t = cfg["platform_test"]
    df = df.assign(_key=df["url"].map(url_key)).drop_duplicates("_key")
    df = df.sample(frac=1.0, random_state=seed)
    plat = df["domain"].isin(platforms)
    norm = (
        df[~plat]
        .groupby("domain", sort=False)
        .head(cfg["cap_per_domain"])
        .head(cfg["cap_per_class"])
    )
    pl = df[plat].assign(_tenant=lambda d: [tenant(u) for u in d["url"]])
    pl = pl.groupby("_tenant", sort=False).head(t["cap_per_tenant"]).head(t["cap_per_class"])
    return pd.concat([norm, pl.drop(columns="_tenant")], ignore_index=True)


def cells(
    frames: dict[str, pd.DataFrame], platforms: frozenset[str], cfg: dict
) -> dict[str, pd.DataFrame]:
    """Every phishing x benign pair whose platform rows meet the thresholds in both classes."""
    t = cfg["platform_test"]
    pops: dict[tuple[str, int], pd.DataFrame] = {}
    for name, df in frames.items():
        for label in (0, 1):
            sub = df[df["label"] == label]
            if len(sub):
                pops[(name, label)] = population(sub, platforms, cfg, cfg["seed"])
    out = {}
    for ph, bn in product(cfg["phishing"], cfg["benign"]):
        if (ph, 1) not in pops or (bn, 0) not in pops:
            continue
        a, b = pops[(ph, 1)], pops[(bn, 0)]
        ok = True
        for d in (a, b):
            p = d[d["domain"].isin(platforms)]
            ok &= (
                len(p) >= t["min_platform_urls"]
                and p["url"].map(tenant).nunique() >= t["min_tenant_hosts"]
            )
        if ok:
            rows = pd.concat([a, b], ignore_index=True).drop_duplicates("_key", keep=False)
            rows["uid"] = [f"{ph}_{bn}_{i}" for i in range(len(rows))]
            out[f"{ph}__{bn}"] = rows
    return out


def prepare_cell(name: str, rows: pd.DataFrame, lists: Lists, out: Path, workers: int) -> None:
    rows.to_parquet(out / f"rows_{name}.parquet", index=False)
    for rep, lst in (("R4", lists), ("R4u", unmasked(lists))):
        path = out / f"features_{name}_{rep}.parquet"
        if path.exists():
            continue
        urls = [
            represent(u, d, "R4", lists.platforms)
            for u, d in zip(rows["url"], rows["domain"], strict=True)
        ]
        f = featurise(urls, lst, workers)
        f["_rep_url"] = urls
        f.to_parquet(path, index=False)


def one_split(args: tuple[str, int, str, dict, Lists]) -> str:
    name, k, out_s, cfg, lists = args
    out = Path(out_s)
    res_path = out / "results" / f"{name}__{k}.json"
    if res_path.exists():
        return f"skip {name} {k}"
    run.G.update(cfg=cfg)
    rows = pd.read_parquet(out / f"rows_{name}.parquet")
    side = pd.Series(assign_split(rows["domain"], cfg["seed"], k, cfg["split"]))
    tr, te = side == "train", side == "test"
    if set(rows.loc[tr, "domain"]) & set(rows.loc[te, "domain"]) or set(rows.loc[tr, "_key"]) & set(
        rows.loc[te, "_key"]
    ):
        raise LeakageError("train/test overlap")
    y = rows["label"].to_numpy()
    w = run.cluster_weights(rows.loc[te, "domain"].to_numpy(), cfg["bootstrap"], cfg["seed"] + k)
    plat = rows["domain"].isin(lists.platforms)
    res: dict = {
        "cell": name,
        "split": k,
        "test_platform_share": float(plat[te].mean()) if te.any() else float("nan"),
        "test_platform_domains": int(rows.loc[te & plat, "domain"].nunique()),
        "auc": {},
        "draws": {},
    }
    for rep in ("R4", "R4u"):
        f = pd.read_parquet(out / f"features_{name}_{rep}.parquet")
        plats = frozenset() if rep == "R4u" else lists.platforms
        parts = pd.Series([parse(u, plats) for u in f["_rep_url"]])
        fitted = Fitted(**fit(f.loc[tr, "_rep_url"].tolist(), y[tr].tolist(), plats))
        x = run._with_fitted(f, parts, fitted)
        for m in cfg[MODELS_KEY]:
            model = run.make(m, list(NAMES)).fit(x[tr], y[tr])
            s = model.score(x[te])
            res["auc"][f"{rep}|{m}"] = run.wauc(y[te], s)
            res["draws"][f"{rep}|{m}"] = [run.wauc(y[te], s, wi) for wi in w]
    res_path.parent.mkdir(parents=True, exist_ok=True)
    res_path.write_text(json.dumps(res), encoding="utf-8")
    return f"done {name} {k}"


def _md(df: pd.DataFrame) -> str:
    rows = [" | ".join(map(str, r)) for r in df.itertuples(index=False)]
    head = " | ".join(df.columns)
    return "\n".join([f"| {head} |", "|" + "---|" * len(df.columns), *(f"| {r} |" for r in rows)])


def analyse(out: Path, cfg: dict, counts_df: pd.DataFrame) -> Path:
    files = sorted((out / "results").glob("*.json"))
    rs = [json.loads(p.read_text(encoding="utf-8")) for p in files]
    TABLES.mkdir(parents=True, exist_ok=True)
    rows, flags = [], []
    for cell in sorted({r["cell"] for r in rs}):
        cr = [r for r in rs if r["cell"] == cell]
        for m in cfg[MODELS_KEY]:
            eff = np.array([r["auc"][f"R4|{m}"] - r["auc"][f"R4u|{m}"] for r in cr])
            dr = np.concatenate(
                [np.array(r["draws"][f"R4|{m}"]) - np.array(r["draws"][f"R4u|{m}"]) for r in cr]
            )
            h, same, med, lo, hi = analyze.holds(eff, dr, cfg, direction=1)
            flags.append(h)
            rows.append(
                {
                    "cell": cell,
                    "model": m,
                    "splits": len(cr),
                    "masked_auc": float(np.nanmedian([r["auc"][f"R4|{m}"] for r in cr])),
                    "unmasked_auc": float(np.nanmedian([r["auc"][f"R4u|{m}"] for r in cr])),
                    "median_gain": med,
                    "ci_lo": lo,
                    "ci_hi": hi,
                    "splits_positive": same,
                    "holds": h,
                    "test_platform_share": float(
                        np.nanmedian([r["test_platform_share"] for r in cr])
                    ),
                    "test_platform_domains": float(
                        np.median([r["test_platform_domains"] for r in cr])
                    ),
                }
            )
    tbl = pd.DataFrame(rows)
    tbl.to_csv(TABLES / "HP_platform.csv", index=False)
    share = (sum(flags) / len(flags)) if flags else float("nan")
    verdict = analyze.verdict(flags, cfg)
    md = [
        "# Platform masking (exploratory deviation from the frozen design)",
        "",
        f"Settings: {len(flags)}; masking raises held-out R4 AUC in {sum(flags)} ({share:.0%}); verdict: {verdict}.",
        "Platform rows kept per tenant host; splits grouped by registrable domain; not part of the seven frozen questions.",
        "",
        "## Counts per source and class",
        "",
        _md(counts_df),
        "",
        "## Masked against unmasked (R4), median of splits",
        "",
        _md(tbl.round(4)) if len(tbl) else "No cell met the thresholds.",
    ]
    p = TABLES.parent / "HP_platform.md"
    p.write_text("\n".join(md) + "\n", encoding="utf-8")
    return p


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="phishguard.masking")
    ap.add_argument("step", choices=["count", "run"])
    ap.add_argument("--interim", type=Path, default=Path("data/interim"))
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--config", type=Path, default=Path("configs/phishguard.yaml"))
    ap.add_argument("--workers", type=int, default=3)
    a = ap.parse_args(argv)
    cfg = yaml.safe_load(a.config.read_text(encoding="utf-8"))
    lists = load_lists()
    names = sorted((set(cfg["phishing"]) | set(cfg["benign"])) - {"crawl"})
    frames = {}
    for n in names:
        try:
            frames[n] = load_source(a.interim, n)
        except (FileNotFoundError, OSError, KeyError) as e:
            print(f"skip source {n}: {e}", flush=True)
    c = counts(pd.concat(frames.values(), ignore_index=True), lists.platforms)
    print(c.to_string(index=False), flush=True)
    TABLES.mkdir(parents=True, exist_ok=True)
    c.to_csv(TABLES / "HP_platform_counts.csv", index=False)
    if a.step == "count":
        return 0
    cs = cells(frames, lists.platforms, cfg)
    print(f"cells meeting the thresholds: {sorted(cs)}", flush=True)
    a.out.mkdir(parents=True, exist_ok=True)
    for name, rows in cs.items():
        prepare_cell(name, rows, lists, a.out, a.workers)
        print(f"features ready: {name} ({len(rows):,} rows)", flush=True)
    jobs = [(n, k, str(a.out), cfg, lists) for n in cs for k in range(cfg["n_splits"])]
    with Pool(a.workers, maxtasksperchild=20) as pool:
        for i, msg in enumerate(pool.imap_unordered(one_split, jobs), 1):
            print(f"[{i}/{len(jobs)}] {msg}", flush=True)
    print(analyse(a.out, cfg, c), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
