"""Helpers of the look-alike experiments: interval, brand folds."""

import pytest

from experiments.lookalike_a import brand_fold, wilson


def test_wilson_interval_brackets_the_rate_and_handles_edges():
    lo, hi = wilson(30, 100)
    assert lo < 0.30 < hi and lo > 0.2 and hi < 0.4
    assert wilson(0, 50)[0] == 0.0 and wilson(50, 50)[1] == 1.0
    assert all(x != x for x in wilson(0, 0))  # NaN


def test_brand_folds_are_stable_and_cover_all_folds():
    assert brand_fold("paypal", 5) == brand_fold("paypal", 5)
    assert {brand_fold(f"brand{i}", 5) for i in range(200)} == set(range(5))


@pytest.mark.parametrize("n", [3, 5])
def test_fold_is_below_fold_count(n):
    assert 0 <= brand_fold("microsoft", n) < n
