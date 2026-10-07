import pandas as pd
import pytest

from collector.store import INDEX_COLUMNS
from data_pipeline.sources import crawl_frame, live_frame, phiusiil_frame, to_binary_label
from phishdrift.schema import COLUMNS, SchemaError, drop_unparsable, to_schema, validate


def _frame(**kw):
    base = dict(
        urls=pd.Series(["https://a.example.com/x", "http://evil.xyz/login/now"]),
        labels=pd.Series([0, 1]),
        source="test",
        dates=pd.Series(["2025-01-01", "2025-02-01T10:00:00Z"]),
    )
    base.update(kw)
    return to_schema(**base)


def test_to_schema_produces_valid_frame():
    df = validate(_frame())
    assert list(df.columns[: len(COLUMNS)]) == COLUMNS
    assert df["domain"].tolist() == ["example.com", "evil.xyz"]
    assert df["depth"].tolist() == [1, 2]
    assert str(df["label"].dtype) == "int8" and str(df["depth"].dtype) == "int16"
    assert str(df["date"].dt.tz) == "UTC"
    assert df["html"].isna().all()
    assert df["origin"].tolist() == ["", ""]


def test_domain_u2_is_bookkeeping_next_to_u1():
    df = _frame(urls=pd.Series(["https://a.web.app/x", "https://b.web.app/"]))
    assert df["domain"].tolist() == ["web.app", "web.app"]
    assert df["domain_u2"].tolist() == ["a.web.app", "b.web.app"]


def test_missing_dates_are_nat_not_dropped():
    df = validate(_frame(dates=None))
    assert df["date"].isna().all()
    assert len(df) == 2


def test_empty_html_becomes_none():
    df = _frame(html=pd.Series(["", "<p>x</p>"]))
    assert df["html"].tolist() == [None, "<p>x</p>"]


def test_validate_rejects_missing_column():
    with pytest.raises(SchemaError, match="missing columns"):
        validate(_frame().drop(columns="depth"))


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


def test_phiusiil_label_is_recoded_and_features_ignored():
    raw = pd.DataFrame(
        {
            "URL": ["https://www.uci.edu", "http://evil.xyz/a/b"],
            "label": [1, 0],
            "URLSimilarityIndex": [100.0, 12.5],  # precomputed, leaks labels: must be ignored
        }
    )
    cfg = {"columns": {"url": "URL", "label": "label"}, "phishing_label_value": 0}
    df = validate(phiusiil_frame(raw, "phiusiil", cfg))
    assert df["label"].tolist() == [0, 1]
    assert (df["source"] == "phiusiil").all()
    assert "URLSimilarityIndex" not in df.columns


def _index_row(norm, url, label, sources, conflict=False):
    t = pd.Timestamp("2026-10-07", tz="UTC")
    return [norm, url, label, "phishing", sources, t, t, pd.NaT, None, conflict]


def test_live_frame_keeps_training_feeds_only_and_drops_conflicts():
    index = pd.DataFrame(
        [
            _index_row("u1", "https://p.xyz/", 1, "openphish,phishtank"),
            _index_row("u2", "http://m.xyz/x.sh", 1, "urlhaus"),  # old index: blocklist feed
            _index_row("u3", "https://q.xyz/a", 1, "phishing_database"),
            _index_row("u4", "https://c.com/", 1, "openphish", conflict=True),
        ],
        columns=INDEX_COLUMNS,
    )
    cfg = {"training_feeds": ["openphish", "phishing_database", "phishtank"]}
    df = validate(live_frame(index, cfg))
    assert df["url"].tolist() == ["https://p.xyz/", "https://q.xyz/a"]
    assert (df["source"] == "live").all()
    assert df["origin"].tolist() == ["openphish", "phishing_database"]
    assert df["date"].notna().all()


def test_crawl_frame_belongs_to_seed_source():
    t = pd.Timestamp("2026-10-07T06:15", tz="UTC")
    crawl = pd.DataFrame(
        {
            "url": ["https://uni.edu/about/team", "https://news.com/world/a"],
            "html": ["<p>a</p>", None],
            "seed_source": ["phiusiil", "live"],
            "seed_domain": ["uni.edu", "news.com"],
            "crawled_at": [t, t],
        }
    )
    df = validate(crawl_frame(crawl, "phiusiil"))
    assert df["url"].tolist() == ["https://uni.edu/about/team"]
    assert df["source"].tolist() == ["phiusiil"] and df["origin"].tolist() == ["crawl"]
    assert df["label"].tolist() == [0] and df["depth"].tolist() == [2]
    assert df["date"].tolist() == [t]
