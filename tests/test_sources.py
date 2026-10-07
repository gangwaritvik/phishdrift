import pandas as pd
import pyarrow.parquet as pq
import pytest

from data_pipeline import sources
from phishdrift.schema import validate

PAGE = "<html><body><p>" + " ".join(f"w{i}" for i in range(80)) + "</p></body></html>"


def _collect(name, cfg):
    return pd.concat(list(sources.LOADERS[cfg["kind"]](name, cfg, 2)), ignore_index=True)


def test_table_loader_reads_mapped_columns_only(tmp_path):
    (tmp_path / "a.csv").write_text(
        "url,label,qty_dot_url,date\n"
        "https://x.edu/,0,1,2025-01-01\n"
        "http://bad.xyz/login/x,1,2,2025-01-02\n"
        ",1,3,2025-01-03\n"  # no URL: skipped
        "https://y.edu/p,legitimate,0,2025-01-04\n"
    )
    cfg = {
        "kind": "table",
        "path": str(tmp_path / "*.csv"),
        "columns": {"url": "url", "label": "label", "date": "date"},
    }
    df = validate(_collect("urlphish", cfg))
    assert df["url"].tolist() == ["https://x.edu/", "http://bad.xyz/login/x", "https://y.edu/p"]
    assert df["label"].tolist() == [0, 1, 0]
    assert "qty_dot_url" not in df.columns
    assert df["date"].notna().all()


def test_table_loader_one_class_source(tmp_path):
    (tmp_path / "n.csv").write_text("url\nhttps://site.org/a/b\nhttps://site.org/c\n")
    cfg = {"kind": "table", "path": str(tmp_path / "n.csv"), "columns": {"url": "url"}, "label": 0}
    df = validate(_collect("natural_legit", cfg))
    assert df["label"].tolist() == [0, 0]


def test_table_loader_missing_files_raise(tmp_path):
    cfg = {"kind": "table", "path": str(tmp_path / "nothing/*.csv"), "columns": {"url": "u"}}
    with pytest.raises(FileNotFoundError, match="download the source"):
        _collect("phish360", cfg)


def test_phishstorm_style_url_column(tmp_path):
    (tmp_path / "urlset.csv").write_bytes(
        "domain,ranking,label\nwww.ok.com/a,1,0.0\nevil.xyz/p/q,2,1.0\n".encode("latin-1")
    )
    cfg = {
        "kind": "table",
        "path": str(tmp_path / "urlset.csv"),
        "columns": {"url": "domain", "label": "label"},
        "read_options": {"encoding": "latin-1"},
    }
    df = validate(_collect("phishstorm", cfg))
    assert df["domain"].tolist() == ["ok.com", "evil.xyz"]
    assert df["label"].tolist() == [0, 1] and df["depth"].tolist() == [1, 2]


def test_folder_loader_phishpedia(tmp_path):
    for i, url in enumerate(["https://paypa1.xyz/signin", "http://amaz0n.top/a/b"]):
        d = tmp_path / f"site{i}"
        d.mkdir()
        (d / "info.txt").write_text(url + "\n")
        (d / "html.txt").write_text(PAGE)
    (tmp_path / "empty").mkdir()  # no info.txt: skipped
    cfg = {
        "kind": "folders",
        "path": str(tmp_path / "*/"),
        "url_file": "info.txt",
        "html_file": "html.txt",
        "label": 1,
    }
    df = validate(_collect("phishpedia", cfg))
    assert sorted(df["url"]) == ["http://amaz0n.top/a/b", "https://paypa1.xyz/signin"]
    assert (df["label"] == 1).all() and df["html"].notna().all()


def test_phishblitz_loader(tmp_path):
    for label, root in ((1, "phishing_resources"), (0, "legitimate_resources")):
        r = tmp_path / root
        page = r / "fully_downloaded_web_pages" / f"p{label}"
        page.mkdir(parents=True)
        (page / "index.html").write_text(PAGE)
        (r / "info.csv").write_text(
            f"Index,URL,HTML Folder\n0,https://s{label}.com/a,p{label}\n1,https://t{label}.com/,\n"
        )
    cfg = {
        "kind": "phishblitz",
        "roots": {
            1: str(tmp_path / "phishing_resources"),
            0: str(tmp_path / "legitimate_resources"),
        },
        "info_csv": "info.csv",
        "columns": {"url": "URL", "html_folder": "HTML Folder"},
        "page_dirs": ["fully_downloaded_web_pages", "no_screenshot_web_pages"],
    }
    df = validate(_collect("phishblitz", cfg)).set_index("url")
    assert df.loc["https://s1.com/a", "label"] == 1 and df.loc["https://s0.com/a", "label"] == 0
    assert df.loc["https://s1.com/a", "html"] == PAGE
    assert df.loc["https://t1.com/", "html"] is None


def test_iter_source_appends_crawled_pages(monkeypatch, tmp_path):
    (tmp_path / "p.csv").write_text("URL,label\nhttps://www.uni.edu,legitimate\n")
    t = pd.Timestamp("2026-10-07", tz="UTC")
    crawl = pd.DataFrame(
        {
            "url": ["https://uni.edu/research/labs"],
            "html": [PAGE],
            "seed_source": ["phiusiil"],
            "seed_domain": ["uni.edu"],
            "crawled_at": [t],
        }
    )
    monkeypatch.setattr(sources, "load_crawl", lambda _: crawl)
    cfg = {
        "kind": "table",
        "path": str(tmp_path / "p.csv"),
        "columns": {"url": "URL", "label": "label"},
    }
    df = pd.concat(list(sources.iter_source("phiusiil", cfg, 100)), ignore_index=True)
    assert df["origin"].tolist() == ["", "crawl"]
    assert df["label"].tolist() == [0, 0]
    assert df["depth"].tolist() == [0, 2]


def test_write_interim_streams_and_counts(tmp_path, dedup_cfg):
    from phishdrift.schema import to_schema

    chunks = [
        to_schema(pd.Series(["https://a.com/x", "http://"]), pd.Series([0, 1]), "s"),
        to_schema(pd.Series(["https://b.com/y"]), pd.Series([1]), "s", html=pd.Series([PAGE])),
    ]
    out = tmp_path / "s.parquet"
    stats = sources.write_interim(chunks, out, dedup_cfg)
    assert stats == {"rows_loaded": 3, "rows_unparsable_url": 1}
    df = pq.read_table(out).to_pandas()
    assert df["row_id"].tolist() == [0, 1]
    assert df["has_html"].tolist() == [False, True]
    assert df["html_simhash"].isna().tolist() == [True, False]
    assert list(df.columns) == sources.INTERIM_COLUMNS
