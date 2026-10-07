import pandas as pd
import pytest

from collector.store import INDEX_COLUMNS
from data_pipeline.loaders import live_frame, phiusiil_frame, to_binary_label
from phishdrift.schema import COLUMNS, SchemaError, drop_unparsable, to_schema, validate


def _frame(**kw):
    base = dict(
        urls=pd.Series(["https://a.example.com/x", "http://evil.xyz/login"]),
        labels=pd.Series([0, 1]),
        source="test",
        dates=pd.Series(["2025-01-01", "2025-02-01T10:00:00Z"]),
    )
    base.update(kw)
    return to_schema(**base)


def test_to_schema_produces_valid_frame():
    df = validate(_frame())
    assert list(df.columns) == COLUMNS
    assert df["domain"].tolist() == ["example.com", "evil.xyz"]
    assert str(df["label"].dtype) == "int8"
    assert str(df["date"].dt.tz) == "UTC"
    assert df["html"].isna().all()


def test_missing_dates_are_nat_not_dropped():
    df = validate(_frame(dates=None))
    assert df["date"].isna().all()
    assert len(df) == 2


def test_validate_rejects_missing_column():
    with pytest.raises(SchemaError, match="missing columns"):
        validate(_frame().drop(columns="domain"))


def test_validate_rejects_bad_labels():
    df = _frame()
    df["label"] = [0, 2]
    with pytest.raises(SchemaError, match="labels"):
        validate(df)


def test_validate_rejects_naive_dates():
    df = _frame()
    df["date"] = df["date"].dt.tz_localize(None)
    with pytest.raises(SchemaError, match="UTC"):
        validate(df)


def test_validate_rejects_null_source():
    df = _frame()
    df.loc[0, "source"] = None
    with pytest.raises(SchemaError, match="source"):
        validate(df)


def test_drop_unparsable():
    df = _frame(urls=pd.Series(["http://", "http://ok.com/"]))
    with pytest.raises(SchemaError, match="empty domain"):
        validate(df)
    kept, dropped = drop_unparsable(df)
    assert dropped == 1 and kept["domain"].tolist() == ["ok.com"]


def test_to_binary_label_encodings():
    s = pd.Series(["phish", "benign", 1, 0, "Phishing", "legitimate", True])
    assert to_binary_label(s).tolist() == [1, 0, 1, 0, 1, 0, 1]
    with pytest.raises(ValueError, match="unrecognized"):
        to_binary_label(pd.Series(["phish", "maybe"]))


def test_phiusiil_label_is_flipped():
    raw = pd.DataFrame({"URL": ["https://www.uci.edu", "http://evil.xyz"], "label": [1, 0]})
    df = validate(
        phiusiil_frame(
            raw, {"columns": {"url": "URL", "label": "label"}, "phishing_label_value": 0}
        )
    )
    assert df["label"].tolist() == [0, 1]
    assert (df["source"] == "phiusiil").all()


def test_live_frame_filters_threats_and_conflicts():
    t = pd.Timestamp("2026-10-07", tz="UTC")
    index = pd.DataFrame(
        [
            [
                "u1",
                "https://p.xyz/",
                1,
                "phishing",
                "openphish,phishtank",
                t,
                t,
                pd.NaT,
                None,
                False,
            ],
            ["u2", "http://m.xyz/x.sh", 1, "malware", "urlhaus", t, t, pd.NaT, None, False],
            ["u3", "https://ok.com/", 0, "benign", "tranco", t, t, pd.NaT, None, False],
            ["u4", "https://c.com/", 1, "phishing", "openphish,tranco", t, t, pd.NaT, None, True],
        ],
        columns=INDEX_COLUMNS,
    )
    df = validate(live_frame(index, {"include_threats": ["phishing"]}))
    assert df["url"].tolist() == ["https://p.xyz/", "https://ok.com/"]
    assert df["source"].tolist() == ["openphish", "tranco"]
    assert df["date"].notna().all()
