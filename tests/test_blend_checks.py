"""The blend checks report renders from per-split rows."""

import pandas as pd

from experiments import blend_checks as bc


def test_render_reports_control_flag():
    def row(model, ev, auc):
        return {"split": 0, "model": model, "eval_set": ev, "n_urls": 10, "n_domains": 9} | {
            "roc_auc": auc,
            "op_1pct_recall": 0.5,
            "op_0p1pct_recall": 0.2,
        }

    runs = pd.DataFrame([row("blend", "test", 0.96), row("blend_shuffled", "test", 0.58)])
    text = bc.render(runs, {"eval": {"shuffled_label_flag": 0.05}})
    assert "| blend | test | 1 | 10 | 9 | 0.9600" in text
    assert "FLAGGED" in text
