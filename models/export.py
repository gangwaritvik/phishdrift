"""Tier A browser export: one JSON bundle the extension scores URLs with.

python -m models.export [--processed data/processed] [--split 0] [--lists-dir ...]

The bundle (``js/data/tier_a_model.json``) holds everything the in-browser URL model needs:
the feature order, the lists and fitted values the model was trained with (so JavaScript
computes the same features), the LightGBM trees in a compact array form, the "suspicious"
(FPR 1%) and "dangerous" (FPR 0.1%) thresholds and the isotonic map, all from one
domain-grouped split. The model is exactly the ``lightgbm/all`` model that
``experiments.tier_a`` evaluated on that split, so its reported numbers describe what ships.

LightGBM was chosen for the browser over the char n-gram model: it is as good or better at
0.1% FPR on the held-out source and the time slice (``reports/tier_a.md``), and its trees are
small; the char n-gram model has a 500k-term vocabulary.

``tests/fixtures/model_parity.json`` holds LightGBM's own probability for every parity URL,
computed from the bundle's lists. pytest checks that the pure-Python tree walker below
reproduces it and the JS suite checks that JavaScript does.

Tree format, per tree: ``f`` split feature index, ``t`` threshold, ``m`` missing type
(0 none, 1 zero, 2 NaN), ``d`` 1 if missing values go left, ``l``/``r`` children (a negative
child ``c`` is leaf ``~c``), ``c`` training rows through the node, ``v`` leaf values, ``n``
training rows per leaf (the covers TreeSHAP needs, ``models.explain``). Features are float32
before comparison, as in training (``models.gbdt.GBDT``).
"""

from __future__ import annotations

import argparse
import json
import logging
import math
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
import pandas as pd

from data_pipeline.split import CAL, TEST, TRAIN
from experiments.metrics import evaluate
from experiments.tier_a import (
    Spec,
    apply_fitted,
    assert_no_overlap,
    load_part,
    make_model,
    refit,
)
from features.extract import extract
from features.fit import Fitted
from features.js_export import JS_DATA, lists_payload, parity_cases
from features.lists import ROOT, Lists, load_lists
from models.calibrate import Calibrator
from models.explain import expected_value, reason_rules, reasons
from phishdrift.config import load_config

log = logging.getLogger("export")
BUNDLE_FILE = JS_DATA / "tier_a_model.json"
MODEL_PARITY_FILE = ROOT / "tests" / "fixtures" / "model_parity.json"
MISSING = {"None": 0, "Zero": 1, "NaN": 2}
ZERO_THRESHOLD = 1e-35  # LightGBM's kZeroThreshold
SPEC = Spec("lightgbm", "all")


# --- trees -----------------------------------------------------------------------------


def compact_tree(root: dict) -> dict:
    tree = {k: [] for k in ("f", "t", "m", "d", "l", "r", "c", "v", "n")}

    def walk(node: dict) -> int:
        if "split_index" not in node:
            tree["v"].append(node["leaf_value"])
            tree["n"].append(node.get("leaf_count", 1))
            return ~(len(tree["v"]) - 1)
        if node["decision_type"] != "<=":
            raise ValueError(f"unsupported split {node['decision_type']!r}")
        i = len(tree["f"])
        tree["f"].append(node["split_feature"])
        tree["t"].append(node["threshold"])
        tree["m"].append(MISSING[node["missing_type"]])
        tree["d"].append(int(node["default_left"]))
        tree["c"].append(node["internal_count"])
        tree["l"].append(0)
        tree["r"].append(0)
        tree["l"][i] = walk(node["left_child"])
        tree["r"][i] = walk(node["right_child"])
        return i

    walk(root)
    return tree


def compact_trees(booster) -> list[dict]:
    dump = booster.dump_model()
    if dump["objective"].split()[0] != "binary":
        raise ValueError(f"expected a binary objective, got {dump['objective']!r}")
    return [compact_tree(t["tree_structure"]) for t in dump["tree_info"]]


def raw_score(trees: list[dict], x: np.ndarray) -> np.ndarray:
    """Sum of leaf values for each row of ``x``, following LightGBM's numerical decision."""
    x = np.asarray(x, dtype=np.float32).astype(np.float64)
    total = np.zeros(len(x))
    rows = np.arange(len(x))
    for tree in trees:
        f, t, m, d = (np.asarray(tree[k]) for k in "ftmd")
        left, right, leaves = np.asarray(tree["l"]), np.asarray(tree["r"]), np.asarray(tree["v"])
        if len(f) == 0:
            total += leaves[0]
            continue
        node = np.zeros(len(x), dtype=np.int64)
        active = node >= 0
        while active.any():
            n = node[active]
            v = x[rows[active], f[n]]
            nan = np.isnan(v)
            v = np.where(nan & (m[n] != 2), 0.0, v)
            missing = ((m[n] == 1) & (np.abs(v) <= ZERO_THRESHOLD)) | ((m[n] == 2) & nan)
            go_left = np.where(missing, d[n] == 1, v <= t[n])
            node[active] = np.where(go_left, left[n], right[n])
            active = node >= 0
        total += leaves[~node]
    return total


def probability(trees: list[dict], x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-raw_score(trees, x)))


# --- bundle ----------------------------------------------------------------------------


def lists_from_payload(payload: dict) -> tuple[Lists, Fitted]:
    keys = ("platforms", "brands", "keywords", "shorteners", "suspicious_tlds", "redirect_params")
    lists = Lists.build(**{k: payload[k] for k in keys})
    fitted = Fitted(**payload["fitted"])
    return lists, fitted


def feature_matrix(urls: list[str], lists: Lists, fitted: Fitted, names: list[str]) -> np.ndarray:
    rows = [extract(u, lists=lists, fitted=fitted) for u in urls]
    return np.array([[r[n] for n in names] for r in rows], dtype=np.float32)


def _clean(v: float) -> float | None:
    return None if v is None or (isinstance(v, float) and math.isnan(v)) else v


def build_bundle(processed: Path, k: int, lists: Lists, cfg: dict) -> tuple[dict, object]:
    ev = cfg["eval"]
    targets, min_neg = ev["target_fprs"], ev["min_negatives"]
    pool = load_part(processed, "pool", lists)
    splits = pd.read_parquet(processed / "splits.parquet")
    side = pool[["uid"]].merge(splits, on="uid", how="left", validate="one_to_one")
    side = side[f"split_{k}"].to_numpy()
    train, cal, test = (pool[side == s] for s in (TRAIN, CAL, TEST))
    assert_no_overlap(train, cal, "train", "cal")
    assert_no_overlap(train, test, "train", "test")
    fitted = refit(train, lists)
    train, cal, test = (apply_fitted(f, fitted) for f in (train, cal, test))

    model = make_model(SPEC, cfg).fit(train, train["label"].to_numpy(), train["weight"].to_numpy())
    names = model.columns
    booster = model.model.booster_
    trees = compact_trees(booster)

    # The compact trees must give LightGBM's own probabilities.
    s_cal = model.score(cal)
    walked = probability(trees, cal[names].to_numpy(dtype=np.float32))
    worst = float(np.max(np.abs(walked - s_cal)))
    if worst > 1e-9:
        raise AssertionError(f"exported trees differ from LightGBM by {worst:.3g} on cal")

    calib = Calibrator({"suspicious": targets[0], "dangerous": targets[1]}, min_neg)
    calib.fit(cal["label"].to_numpy(), s_cal)
    names_by_fpr = dict(zip(targets, ("suspicious", "dangerous"), strict=True))
    thresholds = {t: calib.thresholds[n] for t, n in names_by_fpr.items()}
    test_row = evaluate(test["label"].to_numpy(), model.score(test), targets, min_neg, thresholds)

    bundle = {
        "note": "Generated by `python -m models.export`. Do not edit by hand.",
        "created": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "model": "lightgbm/all, tier A (URL only)",
        "split": k,
        "names": list(names),
        "lists": lists_payload(lists, fitted),
        "trees": trees,
        "expected_value": expected_value(trees),
        "reasons": reason_rules(list(names)),
        "explain": dict(cfg["explain"]),
        "thresholds": dict(calib.thresholds),
        "isotonic": {
            "x": calib.iso.X_thresholds_.tolist(),
            "y": calib.iso.y_thresholds_.tolist(),
        },
        "cal_points": {
            name: {key: _clean(v) for key, v in p.items()} for name, p in calib.points.items()
        },
        "test_metrics": {key: _clean(v) for key, v in test_row.items()},
    }
    log.info(
        "split %d: %d trees, cal max diff %.2g, test ROC-AUC %.4f",
        k,
        len(trees),
        worst,
        test_row["roc_auc"],
    )
    return bundle, booster


def model_parity(bundle: dict, booster) -> dict:
    """LightGBM's probability and reasons (from its own SHAP values, ``pred_contrib``) for
    every parity URL, with features from the bundle's lists."""
    lists, fitted = lists_from_payload(bundle["lists"])
    names, rules, ex = bundle["names"], bundle["reasons"], bundle["explain"]
    urls = parity_cases()
    x = feature_matrix(urls, lists, fitted, names)
    probs = booster.predict(x)
    contrib = booster.predict(x, pred_contrib=True)
    if np.max(np.abs(contrib[:, -1] - bundle["expected_value"])) > 1e-9:
        raise AssertionError("expected value differs from LightGBM's")
    cases = [
        {"url": u, "prob": float(p), "reasons": reasons(c[:-1], row, names, rules, **ex)}
        for u, p, c, row in zip(urls, probs, contrib, x, strict=True)
    ]
    return {
        "note": "Generated by `python -m models.export`. Do not edit by hand.",
        "bundle_created": bundle["created"],
        "cases": cases,
    }


def write(bundle: dict, parity: dict, bundle_file: Path, parity_file: Path) -> list[Path]:
    bundle_file.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(bundle, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    bundle_file.write_text(text, encoding="utf-8")
    lines = json.dumps(parity, ensure_ascii=False, indent=1, allow_nan=False)
    parity_file.write_text(lines + "\n", encoding="utf-8")
    return [bundle_file, parity_file]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="models.export")
    ap.add_argument("--processed", type=Path, default=Path("data/processed"))
    ap.add_argument("--split", type=int, default=0)
    ap.add_argument("--lists-dir", default=None)
    ap.add_argument("--platforms-file", default=None)
    ap.add_argument("--out", type=Path, default=BUNDLE_FILE)
    ap.add_argument("--parity-out", type=Path, default=MODEL_PARITY_FILE)
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s: %(message)s")
    lists = load_lists(a.lists_dir, a.platforms_file)
    bundle, booster = build_bundle(a.processed, a.split, lists, load_config("models"))
    for p in write(bundle, model_parity(bundle, booster), a.out, a.parity_out):
        print(p, f"{p.stat().st_size / 1e6:.2f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
