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
