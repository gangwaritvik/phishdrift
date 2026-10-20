# ruff: noqa: E501
"""PhishGuard study jobs: one job per (part, cell, split), each writing one result file.

Jobs run in a process pool (``PHISHDRIFT_THREADS=1`` per booster) and are skipped when their
result file exists, so a stopped run resumes where it left off.
"""

from __future__ import annotations

import math
import os
import pickle
import time
import traceback
from itertools import product
from multiprocessing import Pool
from pathlib import Path

os.environ.setdefault("PHISHDRIFT_THREADS", "1")

import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import balanced_accuracy_score, roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from data_pipeline.split import LeakageError
from experiments.metrics import evaluate, operating_point
from features.fit import Fitted, fit
from features.lists import Lists
from features.registry import NAMES, REGISTRY_B
from features.url_features import fitted_values
from features.urlparts import parse
from models.char_ngram import CharNgramLR
from models.gbdt import GBDT
from phishguard.data import REPS, assign_split, family

FITTED = ("bigram_loglik_domain", "tld_risk")
G: dict = {}  # per-process state, filled by _init


# --- per-process state -----------------------------------------------------------------


def _init(out: str, cfg: dict, lists: Lists) -> None:
    out = Path(out)
    G.update(cfg=cfg, lists=lists, out=out)
    pops = pd.read_parquet(out / "populations.parquet")
    G["pops"] = pops
    G["feats"], G["parts"] = {}, {}
    for rep in (*REPS, "R4u"):
        f = pd.read_parquet(out / f"features_{rep}.parquet").set_index("uid")
        G["feats"][rep] = f
        plats = frozenset() if rep == "R4u" else lists.platforms
        G["parts"][rep] = pd.Series([parse(u, plats) for u in f["_rep_url"]], index=f.index)
    page = out / "features_page.parquet"
    G["page"] = pd.read_parquet(page).set_index("uid") if page.exists() else None
    for name in ("natural_a", "natural_b"):
        p = out / f"{name}.parquet"
        if p.exists():
            df = pd.read_parquet(p)
            df["_parts"] = [parse(u, lists.platforms) for u in df["_rep_url"]]
            G[name] = df


def _with_fitted(x: pd.DataFrame, parts: pd.Series, fitted: Fitted) -> pd.DataFrame:
    vals = [
        fitted_values(p, fitted) if p is not None else dict.fromkeys(FITTED, math.nan)
        for p in parts
    ]
    x = x.copy()
    for name in FITTED:
        x[name] = np.array([v[name] for v in vals], dtype=np.float32)
    return x


# --- models ----------------------------------------------------------------------------


class LogReg:
    def __init__(self, params: dict, columns: list[str], seed: int):
        self.columns = columns
        self.model = make_pipeline(
            SimpleImputer(strategy="median", keep_empty_features=True),
            StandardScaler(),
            LogisticRegression(C=params["C"], max_iter=params["max_iter"], random_state=seed),
        )

    def fit(self, x: pd.DataFrame, y: np.ndarray):
        self.model.fit(x[self.columns].to_numpy(np.float32), y)
        return self

    def score(self, x: pd.DataFrame) -> np.ndarray:
        return self.model.predict_proba(x[self.columns].to_numpy(np.float32))[:, 1]


class Char:
    def __init__(self, params: dict, seed: int):
        self.m = CharNgramLR(params, seed)

    def fit(self, x: pd.DataFrame, y: np.ndarray):
        self.m.fit(x["_text"].tolist(), y)
        return self

    def score(self, x: pd.DataFrame) -> np.ndarray:
        return self.m.score(x["_text"].tolist())


def make(name: str, columns: list[str]):
    cfg = G["cfg"]
    if name == "char_ngram":
        return Char(cfg["char_ngram"], cfg["seed"])
    if name == "logreg":
        return LogReg(cfg["logreg"], columns, cfg["seed"])
    return GBDT(name, cfg[name], columns, cfg["seed"])


# --- metrics ---------------------------------------------------------------------------


def cluster_weights(domains: np.ndarray, n: int, seed: int) -> np.ndarray:
    """Domain-cluster bootstrap as multinomial weights per row (n draws x rows)."""
    uniq, inv = np.unique(domains, return_inverse=True)
    rng = np.random.default_rng(seed)
    counts = rng.multinomial(len(uniq), np.full(len(uniq), 1 / len(uniq)), size=n)
    return counts[:, inv].astype(np.float64)


def depth_weights(depth: np.ndarray, y: np.ndarray) -> np.ndarray:
    """Post-stratification on depth buckets 0/1/2/3+ both classes occupy (prior report §13.7)."""
    b = np.minimum(depth, 3)
    w = np.zeros(len(y))
    shared = [d for d in range(4) if ((b == d) & (y == 1)).any() and ((b == d) & (y == 0)).any()]
    if not shared:
        return w
    m = np.isin(b, shared)
    q = {d: ((b == d) & m).sum() / m.sum() for d in shared}
    for c in (0, 1):
        n_c = (m & (y == c)).sum()
        for d in shared:
            sel = (b == d) & (y == c)
            w[sel] = q[d] / (sel.sum() / n_c)
    return w


def wauc(y: np.ndarray, s: np.ndarray, w: np.ndarray | None = None) -> float:
    if w is not None:
        keep = w > 0
        y, s, w = y[keep], s[keep], w[keep]
    if len(np.unique(y)) < 2:
        return math.nan
    return float(roc_auc_score(y, s, sample_weight=w))


def score_block(y_cal, s_cal, y_test, s_test, test_w, depth_w) -> dict:
    cfg = G["cfg"]
    thr = {}
    for t in cfg["target_fprs"]:
        op = operating_point(y_cal, s_cal, t, cfg["min_negatives"])
        thr[t] = op["threshold"]
    row = evaluate(y_test, s_test, cfg["target_fprs"], cfg["min_negatives"], thr)
    row["thresholds"] = thr
    row["draws"] = np.array([wauc(y_test, s_test, w) for w in test_w], dtype=np.float32)
    row["auc_depth"] = wauc(y_test, s_test, depth_w)
    row["draws_depth"] = np.array(
        [wauc(y_test, s_test, w * depth_w) for w in test_w], dtype=np.float32
    )
    return row


def natural_fpr(scores: np.ndarray, thr: dict) -> dict:
    out = {"n": len(scores), "fpr_0p5": float((scores >= 0.5).mean())}
    for t, v in thr.items():
        out[f"fpr_{t}"] = float((scores >= v).mean()) if not math.isnan(v) else math.nan
    return out


# --- jobs ------------------------------------------------------------------------------


def _split_rows(rows: pd.DataFrame, k: int) -> pd.Series:
    cfg = G["cfg"]
    side = pd.Series(assign_split(rows["domain"], cfg["seed"], k, cfg["split"]), index=rows.index)
    tr, te = rows[side == "train"], rows[side == "test"]
    if set(tr["domain"]) & set(te["domain"]) or set(tr["_key"]) & set(te["_key"]):
        raise LeakageError("train/test overlap")
    return side


def _cell_rows(part: str, ph: str, bn: str) -> pd.DataFrame:
    p = G["pops"]
    rows = p[(p["part"] == part) & p["pop"].isin([ph, bn])].drop_duplicates("uid")
    return rows.reset_index(drop=True)


def _targets(part: str, ph: str, bn: str, cfg: dict) -> list[tuple[str, str]]:
    names = ("phishing", "benign") if part == "A" else ("phishing_b", "benign_b")
    train_fam = family(ph) | family(bn)
    out = []
    for p2, b2 in product(cfg[names[0]], cfg[names[1]]):
        t = (f"phish:{p2}", f"benign:{b2}")
        if not ((family(t[0]) | family(t[1])) & train_fam):
            out.append(t)
    return out


def job_a(ph: str, bn: str, k: int) -> dict:
    cfg = G["cfg"]
    rows = _cell_rows("A", ph, bn)
    side = _split_rows(rows, k)
    y = rows["label"].to_numpy()
    tr, ca, te = (side == s for s in ("train", "cal", "test"))
    test_w = cluster_weights(rows.loc[te, "domain"].to_numpy(), cfg["bootstrap"], cfg["seed"] + k)
    dw = depth_weights(rows.loc[te, "depth"].to_numpy(), y[te])
    res = {
        "cell": cell_name(ph, bn),
        "split": k,
        "counts": _counts(rows, side),
        "runs": {},
        "natural": {},
        "transfer": {},
        "controls": {},
    }
    p = G["pops"]
    targets = _targets("A", ph, bn, cfg)
    cell_domains = set(rows["domain"])
    for rep in (*REPS, "R4u"):
        f, parts = G["feats"][rep], G["parts"][rep]
        fitted = Fitted(
            **fit(
                f.loc[rows.loc[tr, "uid"], "_rep_url"].tolist(),
                y[tr].tolist(),
                frozenset() if rep == "R4u" else G["lists"].platforms,
            )
        )
        x = _with_fitted(f.loc[rows["uid"]].reset_index(drop=True), parts.loc[rows["uid"]], fitted)
        models = cfg["masking_models"] if rep == "R4u" else cfg["models_a"]
        for m in models:
            model = make(m, list(NAMES)).fit(x[tr], y[tr])
            s_cal, s_te = model.score(x[ca]), model.score(x[te])
            row = score_block(y[ca], s_cal, y[te], s_te, test_w, dw)
            res["runs"][(rep, m)] = row
            if rep == "R1" and "natural_a" in G:
                nat = G["natural_a"]
                xn = _with_fitted(nat, nat["_parts"], fitted)
                res["natural"][m] = natural_fpr(model.score(xn), row["thresholds"])
            if rep in ("R1", "R4") and m in cfg["transfer_models"]:
                res["transfer"][(rep, m)] = _transfer(
                    model, rep, fitted, targets, cell_domains, p, "A"
                )
            if rep in ("R1", "R4") and m in cfg["control_models"]:
                rng = np.random.default_rng(cfg["seed"] + 1000 + k)
                ctl = make(m, list(NAMES)).fit(x[tr], rng.permutation(y[tr]))
                res["controls"][(rep, m)] = wauc(y[te], ctl.score(x[te]))
    return res


def _transfer(model, rep, fitted, targets, cell_domains, p, part) -> dict:
    out = {}
    f, parts = G["feats"][rep], G["parts"][rep]
    for t in targets:
        rows = p[(p["part"] == part) & p["pop"].isin(t)].drop_duplicates("uid")
        rows = rows[~rows["domain"].isin(cell_domains)]
        x = _with_fitted(f.loc[rows["uid"]].reset_index(drop=True), parts.loc[rows["uid"]], fitted)
        if part == "B":
            x = _join_page(x, rows)
        out[t] = {
            "auc": wauc(rows["label"].to_numpy(), model.score(x)),
            "n": len(rows),
            "n_domains": rows["domain"].nunique(),
        }
    return out


def cell_name(ph: str, bn: str) -> str:
    return f"{ph.split(':')[1]}__{bn.split(':')[1]}"


def _counts(rows: pd.DataFrame, side: pd.Series) -> dict:
    te = rows[side == "test"]
    plat = G["parts"]["R1"].loc[te["uid"]]
    share = (
        float(np.mean([bool(q is not None and q.is_platform) for q in plat])) if len(te) else 0.0
    )
    return {"platform_share": share} | {
        f"{n}_{c}": v
        for c in (0, 1)
        for n, v in (
            ("urls", int((te["label"] == c).sum())),
            ("domains", int(te.loc[te["label"] == c, "domain"].nunique())),
        )
    }


def page_cols(rep: str) -> list[str]:
    groups = set(G["cfg"]["page_representations"][rep])
    return [f.name for f in REGISTRY_B if f.group in groups]


def _join_page(x: pd.DataFrame, rows: pd.DataFrame) -> pd.DataFrame:
    page = G["page"].loc[rows["uid"]].reset_index(drop=True)
    return pd.concat([x.reset_index(drop=True), page], axis=1)


def job_b(ph: str, bn: str, k: int) -> dict:
    cfg = G["cfg"]
    rows = _cell_rows("B", ph, bn)
    side = _split_rows(rows, k)
    y = rows["label"].to_numpy()
    tr, ca, te = (side == s for s in ("train", "cal", "test"))
    test_w = cluster_weights(rows.loc[te, "domain"].to_numpy(), cfg["bootstrap"], cfg["seed"] + k)
    dw = depth_weights(rows.loc[te, "depth"].to_numpy(), y[te])
    res = {
        "cell": cell_name(ph, bn),
        "split": k,
        "counts": _counts(rows, side),
        "runs": {},
        "natural": {},
        "transfer": {},
        "controls": {},
    }
    targets = _targets("B", ph, bn, cfg)
    cell_domains = set(rows["domain"])
    xs, fits = {}, {}
    for rep in ("R1", "R4"):
        f, parts = G["feats"][rep], G["parts"][rep]
        fits[rep] = Fitted(
            **fit(
                f.loc[rows.loc[tr, "uid"], "_rep_url"].tolist(),
                y[tr].tolist(),
                G["lists"].platforms,
            )
        )
        x = _with_fitted(
            f.loc[rows["uid"]].reset_index(drop=True), parts.loc[rows["uid"]], fits[rep]
        )
        xs[rep] = _join_page(x, rows)
    specs = [
        (prep, m, page_cols(prep), "R1")
        for prep in cfg["page_representations"]
        for m in cfg["models_b"]
    ]
    specs += [
        ("P1+R1", "lightgbm", page_cols("P1") + list(NAMES), "R1"),
        ("P1+R4", "lightgbm", page_cols("P1") + list(NAMES), "R4"),
        ("R1", "lightgbm", list(NAMES), "R1"),
        ("R4", "lightgbm", list(NAMES), "R4"),
    ]
    for prep, m, cols, urep in specs:
        x = xs[urep]
        model = make(m, cols).fit(x[tr], y[tr])
        row = score_block(y[ca], model.score(x[ca]), y[te], model.score(x[te]), test_w, dw)
        res["runs"][(prep, m)] = row
        if m == "lightgbm" and prep in ("P1", "P1+R1") and "natural_b" in G:
            nat = G["natural_b"]
            xn = _with_fitted(nat, nat["_parts"], fits["R1"])
            res["natural"][prep] = natural_fpr(model.score(xn), row["thresholds"])
        if m == "lightgbm" and prep in ("P1", "P1+R4"):
            res["transfer"][(prep, m)] = _transfer(
                model, urep, fits[urep], targets, cell_domains, G["pops"], "B"
            )
        if m == "lightgbm" and prep == "P1":
            rng = np.random.default_rng(cfg["seed"] + 1000 + k)
            ctl = make(m, cols).fit(x[tr], rng.permutation(y[tr]))
            res["controls"][(prep, m)] = wauc(y[te], ctl.score(x[te]))
    return res


def job_signature() -> dict:
    """E8: within one class, how well do features tell the populations apart (5-fold, by domain)."""
    cfg = G["cfg"]
    p = G["pops"]
    out = {}
    configs = [("A", lab, rep) for lab in (0, 1) for rep in ("R1", "R4")] + [
        ("B", lab, "P1") for lab in (0, 1)
    ]
    for part, lab, rep in configs:
        rows = (
            p[(p["part"] == part) & (p["label"] == lab)]
            .drop_duplicates("uid")
            .reset_index(drop=True)
        )
        if part == "A":
            x = G["feats"][rep].loc[rows["uid"], list(NAMES)].reset_index(drop=True)
        else:
            x = G["page"].loc[rows["uid"], page_cols("P1")].reset_index(drop=True)
        yy = pd.Categorical(rows["pop"]).codes
        fold = np.array([hash_fold(d) for d in rows["domain"]])
        pred = np.zeros(len(rows), dtype=int)
        for f in range(5):
            m = GBDT(
                "lightgbm", {**cfg["lightgbm"], "n_estimators": 150}, list(x.columns), cfg["seed"]
            )
            m.model.fit(x[fold != f].to_numpy(np.float32), yy[fold != f])
            pred[fold == f] = m.model.predict(x[fold == f].to_numpy(np.float32))
        k = len(np.unique(yy))
        out[(part, lab, rep)] = {
            "balanced_accuracy": balanced_accuracy_score(yy, pred),
            "chance": 1 / k,
            "populations": sorted(rows["pop"].unique()),
            "n": len(rows),
        }
    return out


def hash_fold(domain: str) -> int:
    from phishguard.data import unit_hash

    return int(unit_hash(domain, 7, 99) * 5)


def _run(job: tuple) -> str:
    kind, args, path = job
    path = Path(path)
    if path.exists():
        return f"skip {path.name}"
    t = time.time()
    try:
        res = {"A": job_a, "B": job_b, "sig": job_signature}[kind](*args)
    except Exception:
        return f"FAILED {kind} {args}\n{traceback.format_exc()}"
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(pickle.dumps(res))
    tmp.replace(path)
    return f"done {kind} {args} in {time.time() - t:.0f}s"


def jobs(out: Path, cfg: dict) -> list[tuple]:
    res = out / "results"
    js = [("sig", (), str(res / "signature.pkl"))]
    for k in range(cfg["n_splits"]):
        for ph, bn in product(cfg["phishing_b"], cfg["benign_b"]):
            js.append(
                (
                    "B",
                    (f"phish:{ph}", f"benign:{bn}", k),
                    str(res / "B" / f"{ph}__{bn}" / f"{k}.pkl"),
                )
            )
        for ph, bn in product(cfg["phishing"], cfg["benign"]):
            js.append(
                (
                    "A",
                    (f"phish:{ph}", f"benign:{bn}", k),
                    str(res / "A" / f"{ph}__{bn}" / f"{k}.pkl"),
                )
            )
    return js


def run_all(out: Path, cfg: dict, lists: Lists, workers: int) -> int:
    todo = jobs(out, cfg)
    failed = 0
    with Pool(
        workers, initializer=_init, initargs=(str(out), cfg, lists), maxtasksperchild=40
    ) as pool:
        for i, msg in enumerate(pool.imap_unordered(_run, todo), 1):
            failed += msg.startswith("FAILED")
            print(f"[{i}/{len(todo)}] {msg}", flush=True)
    return failed
