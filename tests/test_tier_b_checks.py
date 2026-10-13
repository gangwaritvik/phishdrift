"""The tier B leakage report renders from per-split rows."""

import pandas as pd

from experiments import tier_b_checks as tbc


def test_render_flags_and_twins():
    def row(model, eval_set, auc, **extra):
        return (
            {"split": 0, "model": model, "eval_set": eval_set, "n_urls": 100}
            | {
                "n_domains": 90,
                "roc_auc": auc,
            }
            | extra
        )

    runs = pd.DataFrame(
        [
            row("ab_lgbm", "test", 0.99),
            row("ab_lgbm", "test:no_twin", 0.98, n_twins=10),
            row("ab_lgbm_shuffled", "test", 0.62),
        ]
    )
    text = tbc.render(runs, {"eval": {"shuffled_label_flag": 0.05}})
    assert "FLAGGED" in text
    assert "10 of 100 test rows (10.00%)" in text


def test_key_matches_equal_vectors():
    from features.registry import NAMES_B

    frame = pd.DataFrame(0.0, index=[0, 1, 2], columns=list(NAMES_B))
    frame.loc[2, NAMES_B[0]] = 1.0
    k = tbc._key(frame)
    assert k[0] == k[1] and k[0] != k[2]
