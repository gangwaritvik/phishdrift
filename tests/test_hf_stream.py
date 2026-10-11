"""PhreshPhish is streamed one parquet file at a time, trimmed, and deleted after reading."""

import shutil
from pathlib import Path

import pandas as pd

from data_pipeline import sources


def test_iter_huggingface_streams_and_cleans_up(tmp_path, monkeypatch):
    remote = tmp_path / "remote"
    remote.mkdir()
    for i, rows in enumerate(
        ([("https://a.example/x/y", 1), ("https://b.example/", 0)], [("https://c.example/p", 0)])
    ):
        df = pd.DataFrame(rows, columns=["url", "label"])
        df["date"] = "2025-01-01"
        df["html"] = "<html>" + "x" * 500 + "</html>"
        df.to_parquet(remote / f"train-{i:03d}.parquet")

    seen: list[Path] = []

    def fake_download(repo_id, fname, repo_type, revision, local_dir):
        dest = Path(local_dir) / Path(fname).name
        shutil.copy(remote / Path(fname).name, dest)
        seen.append(dest)
        return str(dest)

    monkeypatch.setattr("huggingface_hub.hf_hub_download", fake_download)
    monkeypatch.setattr(
        sources,
        "_hf_files",
        lambda cfg, split: ["data/train-000.parquet", "data/train-001.parquet"],
    )
    cfg = {
        "hf_id": "x/y",
        "revision": "main",
        "splits": {"train": "hf_train"},
        "columns": {"url": "url", "label": "label", "date": "date", "html": "html"},
        "html_max_chars": 100,
        "download_dir": str(tmp_path),
    }
    frames = list(sources.iter_huggingface("phreshphish", cfg, 1000))
    out = pd.concat(frames)
    assert len(out) == 3
    assert out["html"].str.len().max() == 100
    assert set(out["origin"]) == {"hf_train"}
    assert len(seen) == 2 and not any(p.exists() for p in seen)


def _fake_dataset(tmp_path, monkeypatch, fail_on=None):
    """Three one-row-group parquet files; downloads copy them and may fail on one file."""
    remote = tmp_path / "remote"
    remote.mkdir(exist_ok=True)
    for i in range(3):
        df = pd.DataFrame({"url": [f"https://d{i}.example/a/b", f"https://e{i}.example/"]})
        df["label"] = ["phishing", "benign"]
        df["date"] = "2025-01-01"
        df["html"] = "<html>" + "x" * 50 + "</html>"
        df.to_parquet(remote / f"train-{i:03d}.parquet")
    calls: list[str] = []

    def fake_download(repo_id, fname, repo_type, revision, local_dir):
        calls.append(fname)
        if fname == fail_on:
            raise OSError("network down")
        dest = Path(local_dir) / Path(fname).name
        shutil.copy(remote / Path(fname).name, dest)
        return str(dest)

    monkeypatch.setattr("huggingface_hub.hf_hub_download", fake_download)

    monkeypatch.setattr(
        sources, "_hf_files", lambda cfg, split: [f"data/train-{i:03d}.parquet" for i in range(3)]
    )
    monkeypatch.setattr(sources, "_crawl_chunks", lambda name, n: iter(()))
    cfg = {
        "chunk_rows": 1000,
        "dedup": {"html_max_chars": 1000, "html_min_tokens": 50, "shingle_size": 5},
        "sources": {
            "phreshphish": {
                "kind": "huggingface",
                "hf_id": "x/y",
                "revision": "main",
                "splits": {"train": "hf_train"},
                "columns": {"url": "url", "label": "label", "date": "date", "html": "html"},
                "download_dir": str(tmp_path),
            }
        },
    }
    return cfg, calls


def test_sharded_load_resumes_after_a_crash(tmp_path, monkeypatch):
    import pyarrow.dataset as pads
    import pyarrow.parquet as pq

    cfg, calls = _fake_dataset(tmp_path, monkeypatch, fail_on="data/train-002.parquet")
    monkeypatch.setattr("time.sleep", lambda s: None)
    out = tmp_path / "interim" / "phreshphish.parquet"
    try:
        sources.load_hf_sharded("phreshphish", cfg, out)
    except OSError:
        pass
    else:
        raise AssertionError("expected the failing download to stop the load")
    assert not sources.interim_complete(out)

    cfg, calls = _fake_dataset(tmp_path, monkeypatch)  # network is back
    stats = sources.load_hf_sharded("phreshphish", cfg, out)
    assert calls == ["data/train-002.parquet"]  # only the unfinished file is fetched again
    assert sources.interim_complete(out)
    assert stats == {"rows_loaded": 6, "rows_unparsable_url": 0}
    table = pq.read_table(out)
    assert sorted(table["row_id"].to_pylist()) == list(range(6))
    assert sum(b.num_rows for b in pads.dataset(out, format="parquet").to_batches()) == 6
