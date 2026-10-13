"""Summary tables are built from per-split run tables only."""

import pandas as pd

from experiments import summary_tables


def _runs(n_splits=3, **extra):
    rows = []
    for k in range(n_splits):
        row = {
            "split": k, "model": "hybrid2", "features": "all", "eval_set": "test",
            "n_urls": 100 + k, "n_pos": 30, "n_neg": 70 + k, "roc_auc": 0.9 + k / 100,
            "op_1pct_recall": 0.5, "op_0p1pct_recall": 0.3, "op_0p1pct_granularity_limited": True,
        }  # fmt: skip
        for col in summary_tables.CAL_COLS:
            row[col] = 0.1 * (k + 1)
        rows.append(row | extra)
    return pd.DataFrame(rows)


def test_cal_and_depth_summaries_use_median_and_range(tmp_path):
    tables = tmp_path / "tables"
    tables.mkdir()
    _runs().to_csv(tables / "hybrid2_runs.csv", index=False)
    _runs(eval_set="test:phiusiil").to_csv(tables / "blend_runs.csv", index=False)
    depth = pd.concat([_runs(depth="0"), _runs(depth="4+")]).drop(columns="eval_set")
    depth.to_csv(tables / "tier_a_depth.csv", index=False)
    out = summary_tables.run(tmp_path)
    cal = pd.read_csv(tables / "summary_cal.csv")
    assert list(cal["model"]) == ["hybrid2"]  # per-source rows are not summarised
    assert cal.loc[0, "cal 1% recall"] == "20.0 [10.0, 30.0]"
    assert cal.loc[0, "negatives"] == 71
    d = pd.read_csv(tables / "summary_depth.csv", dtype={"depth": str})
    assert list(d["depth"]) == ["0", "4+"]
    assert d.loc[0, "ROC-AUC"] == "0.9100 [0.9000, 0.9200]"
    assert d.loc[0, "0.1% granularity-limited splits"] == 3
    assert "Depth-matched" in out.read_text()
