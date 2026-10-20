"""Platform-masking test: counts, caps per tenant and one end-to-end run on synthetic sources."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import yaml

from features.lists import load_lists
from phishguard import masking


def _cfg() -> dict:
    cfg = yaml.safe_load(Path("configs/phishguard.yaml").read_text(encoding="utf-8"))
    cfg.update(
        n_splits=2, bootstrap=10, phishing=["pa"], benign=["bb"], masking_models=["lightgbm"]
    )
    cfg["lightgbm"] = {**cfg["lightgbm"], "n_estimators": 20}
    cfg["platform_test"] = {**cfg["platform_test"], "min_platform_urls": 40, "min_tenant_hosts": 10}
    return cfg


def _source(label: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    plats = ["github.io", "pages.dev", "web.app", "blogspot.com"]
    rows = []
    for i in range(300):  # normal rows
        d = f"site{label}{i}.com"
        rows.append((f"https://{d}/a/{i}", d, label))
    for i in range(120):  # platform rows, many tenants, several URLs per tenant
        pl = plats[i % 4]
        host = f"t{label}{i % 40}.{pl}"
        rows.append((f"https://{host}/{rng.integers(1000)}/p{i}", pl, label))
    return pd.DataFrame(rows, columns=["url", "domain", "label"]).assign(source="x")


def test_counts_and_tenant_cap():
    lists = load_lists()
    df = pd.concat([_source(1, 1), _source(0, 2)], ignore_index=True)
    c = masking.counts(df, lists.platforms)
    assert (c["platform_urls"] == 120).all()
    assert (c["tenant_hosts"] == 40).all()
    cfg = _cfg()
    cfg["platform_test"]["cap_per_tenant"] = 2
    pop = masking.population(df[df["label"] == 1], lists.platforms, cfg, 0)
    pl = pop[pop["domain"].isin(lists.platforms)]
    assert pl["url"].map(masking.tenant).value_counts().max() <= 2


def test_cell_filter_and_split(tmp_path, monkeypatch):
    monkeypatch.setattr(masking, "TABLES", tmp_path / "reports" / "tables")
    lists = load_lists()
    cfg = _cfg()
    frames = {"pa": _source(1, 1), "bb": _source(0, 2)}
    cs = masking.cells(frames, lists.platforms, cfg)
    assert list(cs) == ["pa__bb"]
    cfg["platform_test"]["min_platform_urls"] = 10_000
    assert masking.cells(frames, lists.platforms, cfg) == {}
    cfg = _cfg()
    masking.prepare_cell("pa__bb", cs["pa__bb"], lists, tmp_path, 1)
    assert masking.one_split(("pa__bb", 0, str(tmp_path), cfg, lists)).startswith("done")
    counts = masking.counts(pd.concat(frames.values()), lists.platforms)
    table = masking.analyse(tmp_path, cfg, counts)
    assert table.exists()
