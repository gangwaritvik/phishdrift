"""The depth-matched report renders from per-split rows, NaN cells as n/a."""

import math

import pandas as pd

from experiments import hybrid_depth as hd


def test_render_handles_one_class_buckets():
    row = {
        "split": 0,
        "eval_set": "heldout_source",
        "depth": "0",
        "n_domains": 5,
        "n_pos": 5,
        "n_neg": 0,
        "roc_auc": math.nan,
        "op_1pct_recall": math.nan,
        "op_0p1pct_recall": math.nan,
        "op_0p1pct_granularity_limited": True,
        "cal_1pct_recall": 0.4,
        "cal_1pct_fpr": math.nan,
        "cal_0p1pct_recall": 0.2,
        "cal_0p1pct_fpr": math.nan,
    }
    text = hd.render(pd.DataFrame([row]))
    assert "| heldout_source | 0 | 1 | 5 | 0 | n/a | n/a | n/a* | 40.0 / n/a | 20.0 / n/a |" in text
