"""Hybrid tier A browser export: LightGBM trees plus the two char n-gram models.

python -m models.export_hybrid [--processed data/processed] [--split 0] [--max-features 100000]

Writes ``js/data/tier_a_hybrid.json`` and ``tests/fixtures/hybrid_parity.json``. The bundle
holds what the browser needs to score a URL exactly as ``models.hybrid.HybridA`` does: the
feature order (99 URL features, then ``char_url`` and ``char_host``), the lists and fitted
values, the LightGBM trees, and for each char model its vocabulary, IDF weights, logistic-
regression weights and intercept; plus thresholds, isotonic map, reason rules and the model's
metrics on the split's test side, the held-out source and the newest time slice.

The char models are refitted with a vocabulary of ``--max-features`` terms (the evaluated
experiment, ``experiments.hybrid_a``, uses ``char_ngram.max_features`` = 500,000, about 14 MB of
JSON per model); a vocabulary cut after fitting would change the L2 norm the browser can
compute. The smaller vocabulary is its own model: its metrics are in the bundle and in
``reports/tables/hybrid_export.csv``.

``tests/fixtures/hybrid_parity.json``: probability and reasons from Python for every parity URL.
pytest and the JS suite both reproduce it.
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd

from data_pipeline.split import CAL, TEST, TRAIN
from experiments.hybrid_a import make_hybrid
from experiments.metrics import evaluate
from experiments.tier_a import (
    PARTS,
    apply_fitted,
    assert_no_overlap,
    load_part,
    refit,
)
from features.extract import extract
from features.js_export import JS_DATA, lists_payload, parity_cases
from features.lists import ROOT, Lists, load_lists
from features.registry import NAMES
from features.urlparts import parse
from models.calibrate import Calibrator
from models.explain import expected_value, reason_rules, reasons
from models.export import _clean, compact_trees, lists_from_payload, probability
from models.hybrid import TEXTS
from models.stack import EPS
from phishdrift.config import load_config

log = logging.getLogger("export_hybrid")
BUNDLE_FILE = JS_DATA / "tier_a_hybrid.json"
PARITY_FILE = ROOT / "tests" / "fixtures" / "hybrid_parity.json"
CHAR_NAMES = tuple(TEXTS)  # char_url, char_host


def f32(a: np.ndarray) -> list[float]:
    """Shortest decimal that reads back as the same float32 (the browser stores Float32Array)."""
    return [float(np.format_float_scientific(x, unique=True)) for x in np.asarray(a, np.float32)]


def char_payload(model) -> dict:
    vec, lr = model.vectorizer, model.model
    vocab = vec.vocabulary_
    terms = [None] * len(vocab)
    for term, i in vocab.items():
        terms[i] = term
    return {
        "ngram_range": list(vec.ngram_range),
        "sublinear_tf": bool(vec.sublinear_tf),
        "terms": terms,
        "idf": f32(vec.idf_),
        "coef": f32(lr.coef_[0]),
        "intercept": float(lr.intercept_[0]),
        "eps": EPS,
    }


def frame_for_urls(urls: list[str], lists: Lists, fitted, names: list[str]) -> pd.DataFrame:
    rows = [extract(u, lists=lists, fitted=fitted) for u in urls]
    frame = pd.DataFrame(rows, columns=names).astype("float32")
    frame["_parts"] = [parse(u, lists.platforms) for u in urls]
    frame["_text"] = [p.canon if p is not None else "" for p in frame["_parts"]]
    return frame


def bundle_names() -> list[str]:
    return list(NAMES) + list(CHAR_NAMES)


def build(processed: Path, k: int, lists: Lists, cfg: dict, max_features: int) -> tuple[dict, dict]:
    cfg = cfg | {"char_ngram": cfg["char_ngram"] | {"max_features": max_features}}
    ev = cfg["eval"]
    targets, min_neg = ev["target_fprs"], ev["min_negatives"]
    frames = {p: load_part(processed, p, lists) for p in PARTS}
    pool = frames.pop("pool")
    splits = pd.read_parquet(processed / "splits.parquet")
    side = pool[["uid"]].merge(splits, on="uid", how="left", validate="one_to_one")
    side = side[f"split_{k}"].to_numpy()
    train, cal, test = (pool[side == s] for s in (TRAIN, CAL, TEST))
    for name, other in {"cal": cal, "test": test, **frames}.items():
        assert_no_overlap(train, other, "train", name)
    fitted = refit(train, lists)
    train, cal, test = (apply_fitted(f, fitted) for f in (train, cal, test))
    held = {n: apply_fitted(h, fitted) for n, h in frames.items()}

    model = make_hybrid(cfg).fit(train, train["label"].to_numpy(), train["weight"].to_numpy())
    s_cal = model.score(cal)
    calib = Calibrator({"suspicious": targets[0], "dangerous": targets[1]}, min_neg)
    calib.fit(cal["label"].to_numpy(), s_cal)
    thresholds = dict(zip(targets, calib.thresholds.values(), strict=True))
    metrics = {}
    for set_name, frame in {"test": test, **held}.items():
        row = evaluate(frame["label"].to_numpy(), model.score(frame), targets, min_neg, thresholds)
        metrics[set_name] = {key: _clean(v) for key, v in row.items()}

    names = bundle_names()
    booster = model.gbdt.model.booster_
    trees = compact_trees(booster)
    bundle = {
        "note": "Generated by `python -m models.export_hybrid`. Do not edit by hand.",
        "created": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "model": "hybrid tier A: lightgbm/all + char_url + char_host",
        "split": k,
        "max_features": max_features,
        "names": names,
        "lists": lists_payload(lists, fitted),
        "trees": trees,
        "expected_value": expected_value(trees),
        "char": {n: char_payload(model.chars[n]) for n in CHAR_NAMES},
        "reasons": reason_rules(names),
        "explain": dict(cfg["explain"]),
        "thresholds": dict(calib.thresholds),
        "isotonic": {"x": calib.iso.X_thresholds_.tolist(), "y": calib.iso.y_thresholds_.tolist()},
        "metrics": metrics,
    }
    return bundle, {"model": model, "booster": booster, "fitted": fitted}


def parity(bundle: dict, model, booster, lists: Lists, fitted) -> dict:
    """Python's probability and reasons for every parity URL, from the fitted model itself."""
    names = bundle["names"]
    urls = parity_cases()
    frame = frame_for_urls(urls, lists, fitted, list(NAMES))
    probs = model.score(frame)
    full = frame.assign(**model.char_scores(frame))
    x = full[names].to_numpy(dtype=np.float32)
    contrib = booster.predict(x, pred_contrib=True)
    walked = probability(bundle["trees"], x)
    if np.max(np.abs(walked - probs)) > 1e-9:
        raise AssertionError("exported trees differ from the fitted hybrid")
    cases = []
    for u, p, c, row in zip(urls, probs, contrib, x, strict=True):
        why = reasons(c[:-1], row, names, bundle["reasons"], **bundle["explain"])
        cases.append({"url": u, "prob": float(p), "reasons": why})
    return {
        "note": "Generated by `python -m models.export_hybrid`. Do not edit by hand.",
        "bundle_created": bundle["created"],
        "cases": cases,
    }


def write(bundle: dict, parity_doc: dict, bundle_file: Path, parity_file: Path) -> list[Path]:
    bundle_file.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(bundle, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    bundle_file.write_text(text, encoding="utf-8")
    parity_file.write_text(
        json.dumps(parity_doc, ensure_ascii=False, indent=1, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    return [bundle_file, parity_file]


def metrics_table(bundle: dict) -> pd.DataFrame:
    rows = []
    for set_name, m in bundle["metrics"].items():
        rows.append(
            {"split": bundle["split"], "max_features": bundle["max_features"], "eval_set": set_name}
            | {k: v for k, v in m.items() if isinstance(v, int | float | type(None))}
        )
    return pd.DataFrame(rows)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="models.export_hybrid")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--split", type=int, default=0)
    ap.add_argument("--max-features", type=int, default=100_000)
    ap.add_argument("--lists-dir", default=None)
    ap.add_argument("--platforms-file", default=None)
    ap.add_argument("--out", type=Path, default=BUNDLE_FILE)
    ap.add_argument("--parity-out", type=Path, default=PARITY_FILE)
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    lists = load_lists(a.lists_dir, a.platforms_file)
    bundle, fitted_objs = build(a.processed, a.split, lists, load_config("models"), a.max_features)
    doc = parity(bundle, fitted_objs["model"], fitted_objs["booster"], lists, fitted_objs["fitted"])
    # The bundle's lists are the ones used to train; parity uses the same.
    assert lists_from_payload(bundle["lists"])[0].platforms == lists.platforms
    for p in write(bundle, doc, a.out, a.parity_out):
        print(p, f"{p.stat().st_size / 1e6:.2f} MB")
    table = metrics_table(bundle)
    (a.reports / "tables").mkdir(parents=True, exist_ok=True)
    table.to_csv(a.reports / "tables" / "hybrid_export.csv", index=False)
    log.info("test ROC-AUC %.4f", bundle["metrics"]["test"]["roc_auc"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
