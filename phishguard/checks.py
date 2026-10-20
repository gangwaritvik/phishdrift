# ruff: noqa: E501
"""Follow-up checks after the verification run.

    python -m phishguard.checks reproduce --phiusiil data/interim/phiusiil.parquet
    python -m phishguard.checks control --cell urlphish__phiusiil

``reproduce`` walks from the raw PhiUSIIL benchmark (as the first study used it) to the study cell,
one cleaning step at a time, so the gap to the published numbers can be attributed to a step.
``control`` repeats one shuffled-label control with several shuffle seeds.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

os.environ.setdefault("PHISHDRIFT_THREADS", "4")

import numpy as np
import pandas as pd
import yaml

from features.fit import Fitted, fit
from features.lists import load_lists
from features.registry import NAMES
from phishdrift.domains import url_key
from phishguard import run
from phishguard.data import _cap, assign_split, featurise, represent

REPS = ("R1", "R2", "R4")


def _eval_stage(
    rows: pd.DataFrame, cfg: dict, lists, workers: int, splits: int, models: list[str]
) -> list[dict]:
    out = []
    feats = {}
    for rep in REPS:
        urls = [
            represent(u, d, rep, lists.platforms)
            for u, d in zip(rows["url"], rows["domain"], strict=True)
        ]
        f = featurise(urls, lists, workers)
        f["_rep_url"] = urls
        feats[rep] = f
    from features.urlparts import parse

    parts = {
        rep: pd.Series([parse(u, lists.platforms) for u in feats[rep]["_rep_url"]]) for rep in REPS
    }
    y = rows["label"].to_numpy()
    for k in range(splits):
        side = assign_split(rows["domain"], cfg["seed"], k, {"train": 0.8, "cal": 0.0})
        tr, te = side == "train", side == "test"
        for rep in REPS:
            fitted = Fitted(
                **fit(feats[rep].loc[tr, "_rep_url"].tolist(), y[tr].tolist(), lists.platforms)
            )
            x = run._with_fitted(feats[rep], parts[rep], fitted)
            for m in models:
                model = run.make(m, list(NAMES)).fit(x[tr], y[tr])
                out.append(
                    {"split": k, "rep": rep, "model": m, "auc": run.wauc(y[te], model.score(x[te]))}
                )
    return out


def reproduce(
    phiusiil: Path, data: Path, out: Path, cfg: dict, lists, workers: int, splits: int
) -> pd.DataFrame:
    run.G.update(cfg=cfg, lists=lists)
    raw = pd.read_parquet(phiusiil, columns=["url", "domain", "label", "origin", "depth"])
    raw = raw[raw["origin"] == "original"].copy()
    raw["domain"] = raw["domain"].astype(str).str.lower()
    raw["_key"] = raw["url"].map(url_key)
    raw = raw.drop_duplicates("_key")
    pool = pd.read_parquet(data / "meta_pool.parquet")
    pool = pool[(pool["source"] == "phiusiil") & (pool["origin"] == "original")]
    keep_dom, keep_key = set(pool["domain"].str.lower()), set(pool["url"].map(url_key))
    pops = pd.read_parquet(out / "populations.parquet")
    cell = set(
        pops[(pops["part"] == "A") & pops["pop"].isin(["phish:phiusiil", "benign:phiusiil"])][
            "_key"
        ]
    )
    stages = {
        "S0 raw PhiUSIIL (as in the first study)": raw,
        "S1 + domains shared with other sources removed": raw[raw["domain"].isin(keep_dom)],
        "S2 + pool URL rules (20 per domain, depth balance)": raw[raw["_key"].isin(keep_key)],
        "S3 + study caps (5 per domain, 10,000 per class) = study cell": raw[
            raw["_key"].isin(cell)
        ],
    }
    # S0b: the raw benchmark capped to the study's size, so stage S0 -> S3 is not just a size change
    s0b = pd.concat(
        [_cap(raw[raw["label"] == c], 10**9, cfg["cap_per_class"], cfg["seed"]) for c in (0, 1)]
    )
    stages = {
        **dict(list(stages.items())[:1]),
        "S0b raw, sampled to 10,000 per class": s0b,
        **dict(list(stages.items())[1:]),
    }
    rows = []
    for name, df in stages.items():
        df = df.reset_index(drop=True)
        info = {
            "stage": name,
            "urls_phish": int((df["label"] == 1).sum()),
            "urls_benign": int((df["label"] == 0).sum()),
            "depth0_phish": float((df.loc[df["label"] == 1, "depth"] == 0).mean()),
            "depth0_benign": float((df.loc[df["label"] == 0, "depth"] == 0).mean()),
        }
        print(info, flush=True)
        for r in _eval_stage(df, cfg, lists, workers, splits, ["xgboost", "char_ngram"]):
            rows.append(info | r)
    res = pd.DataFrame(rows)
    res.to_csv(out / "reproduce.csv", index=False)
    return res


def control(cell: str, out: Path, cfg: dict, lists, seeds: int) -> pd.DataFrame:
    run._init(str(out), cfg, lists)
    ph, bn = cell.split("__")
    rows = run._cell_rows("A", f"phish:{ph}", f"benign:{bn}")
    y = rows["label"].to_numpy()
    res = []
    for k in range(cfg["n_splits"]):
        side = run._split_rows(rows, k)
        tr, te = (side == "train").to_numpy(), (side == "test").to_numpy()
        f, parts = run.G["feats"]["R1"], run.G["parts"]["R1"]
        fitted = Fitted(
            **fit(f.loc[rows.loc[tr, "uid"], "_rep_url"].tolist(), y[tr].tolist(), lists.platforms)
        )
        x = run._with_fitted(
            f.loc[rows["uid"]].reset_index(drop=True), parts.loc[rows["uid"]], fitted
        )
        for s in range(seeds):
            rng = np.random.default_rng(10_000 + 97 * k + s)
            ys = rng.permutation(y[tr])
            for m in ("lightgbm", "char_ngram"):
                a = run.wauc(y[te], run.make(m, list(NAMES)).fit(x[tr], ys).score(x[te]))
                res.append({"split": k, "seed": s, "model": m, "auc": a})
        # also: fitted features computed from shuffled labels (as a full control would)
        rng = np.random.default_rng(10_000 + 97 * k)
        ys = rng.permutation(y[tr])
        fitted_s = Fitted(
            **fit(f.loc[rows.loc[tr, "uid"], "_rep_url"].tolist(), ys.tolist(), lists.platforms)
        )
        xs = run._with_fitted(
            f.loc[rows["uid"]].reset_index(drop=True), parts.loc[rows["uid"]], fitted_s
        )
        a = run.wauc(y[te], run.make("lightgbm", list(NAMES)).fit(xs[tr], ys).score(xs[te]))
        res.append({"split": k, "seed": -1, "model": "lightgbm_shuffled_fit", "auc": a})
        print(k, flush=True)
    df = pd.DataFrame(res)
    df.to_csv(out / f"control_{cell}.csv", index=False)
    return df


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="phishguard.checks")
    ap.add_argument("check", choices=["reproduce", "control"])
    ap.add_argument("--data", type=Path, default=Path("data/processed"))
    ap.add_argument("--out", type=Path, default=Path("data/interim/phishguard"))
    ap.add_argument("--config", type=Path, default=Path("configs/phishguard.yaml"))
    ap.add_argument("--platforms-file", default=None)
    ap.add_argument("--phiusiil", type=Path, default=Path("data/interim/phiusiil.parquet"))
    ap.add_argument("--cell", default="urlphish__phiusiil")
    ap.add_argument("--splits", type=int, default=5)
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--workers", type=int, default=2)
    a = ap.parse_args(argv)
    cfg = yaml.safe_load(a.config.read_text(encoding="utf-8"))
    lists = load_lists(None, a.platforms_file)
    if a.check == "reproduce":
        r = reproduce(a.phiusiil, a.data, a.out, cfg, lists, a.workers, a.splits)
        print(r.groupby(["stage", "model", "rep"])["auc"].median().unstack().round(4).to_string())
    else:
        r = control(a.cell, a.out, cfg, lists, a.seeds)
        print(
            json.dumps(
                r.groupby("model")["auc"].agg(["mean", "std", "min", "max"]).round(4).to_dict()
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
