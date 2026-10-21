"""Uncleaned-data condition: repeated domains are kept; end-to-end run on synthetic sources."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import yaml

from features.lists import load_lists
from phishguard import sensitivity


def _cfg() -> dict:
    cfg = yaml.safe_load(Path("configs/phishguard.yaml").read_text(encoding="utf-8"))
    cfg.update(n_splits=2, bootstrap=10, phishing=["pa", "pb"], benign=["phiusiil", "urlphish"])
    cfg["lightgbm"] = {**cfg["lightgbm"], "n_estimators": 20}
    return cfg


def _source(label: int, seed: int, n: int = 300) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        d = f"site{label}{seed}x{i % 150}.com"  # two URLs per domain: the cap must not apply
        rows.append((f"https://{d}/{'a' if label else 'b'}{rng.integers(10**6)}/{i}", d, label))
    return pd.DataFrame(rows, columns=["url", "domain", "label"])


def test_populations_keep_repeated_domains_and_drop_conflicts():
    cfg = sensitivity.condition_cfg(_cfg())
    a, b = _source(1, 1), _source(0, 2)
    b.loc[0, "url"] = a.loc[0, "url"]  # same URL labelled both ways
    pops = sensitivity.build_populations({"pa": a, "phiusiil": b}, cfg)
    assert a.loc[0, "url"] not in set(pops["url"])
    per_domain = pops.groupby("domain").size()
    assert per_domain.max() >= 2
    assert set(pops["pop"]) == {"phish:pa", "benign:phiusiil"}


def test_end_to_end(tmp_path):
    cfg = sensitivity.condition_cfg(_cfg())
    lists = load_lists()
    frames = {
        "pa": _source(1, 1),
        "pb": _source(1, 3),
        "phiusiil": _source(0, 2),
        "urlphish": _source(0, 4),
    }
    for k, v in frames.items():
        v.to_parquet(tmp_path / f"{k}.parquet")
    out = tmp_path / "out"
    sensitivity.prepare(tmp_path, out, cfg, lists, 1)
    assert sensitivity.run_cells(out, cfg, lists, 1) == 0
    path = sensitivity.analyse(out, out, _cfg(), tmp_path / "rep")
    assert "Q2" in path.read_text(encoding="utf-8")
