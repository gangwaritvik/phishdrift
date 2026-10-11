import pandas as pd

from experiments.feature_source_check import run


def test_flags_source_predictive_feature(tmp_path):
    n = 200
    uid = [f"s:{i}" for i in range(n)]
    source = ["a", "b"] * (n // 2)
    label = [0, 0, 1, 1] * (n // 4)
    pd.DataFrame({"uid": uid, "f_src": [s == "a" for s in source], "f_lab": label}).astype(
        {"f_src": float, "f_lab": float}
    ).to_parquet(tmp_path / "features_a.parquet")
    pd.DataFrame({"uid": uid, "label": label, "source": source}).to_parquet(
        tmp_path / "pool.parquet"
    )
    res = run(tmp_path, tmp_path / "out.csv").set_index("feature")
    assert bool(res.loc["f_src", "flag"]) and not bool(res.loc["f_lab", "flag"])
