import json

import pandas as pd
import pyarrow.parquet as pq
import pytest

from data_pipeline.corpus import POOL, DepthImbalanceError
from data_pipeline.pipeline import OUTPUT_COLUMNS, build
from data_pipeline.sources import write_interim
from phishdrift.schema import to_schema
from tests.test_corpus import HOLDOUT_CFG, _corpus_cfg

PAGE = "<html><body><p>{}</p></body></html>"


def _page(i: int) -> str:
    return PAGE.format(" ".join(f"tok{i}x{j}" for j in range(60)))


def _sources(homepage_only_benign: bool = False) -> dict[str, pd.DataFrame]:
    ph_urls, ph_labels, ph_dates, ph_origin, ph_html = [], [], [], [], []
    for d in range(150):
        lab = d % 2
        for k in range(3):
            ph_urls.append(f"https://site{d}.{'xyz' if lab else 'com'}/a/{k}")
            ph_labels.append(lab)
            ph_dates.append("2025-08-01" if d >= 130 else "2025-01-01")
            ph_origin.append("hf_test" if d >= 130 else "hf_train")
            ph_html.append(_page(d * 10 + k))
    for i in range(20):  # phishing on bare domains, so depth 0 is not all benign
        ph_urls.append(f"https://bare{i}.top/")
        ph_labels.append(1)
        ph_dates.append("2025-01-01")
        ph_origin.append("hf_train")
        ph_html.append(_page(10_000 + i))
    if homepage_only_benign:
        keep = [i for i, lab in enumerate(ph_labels) if lab == 1]
        ph_urls, ph_labels, ph_dates, ph_origin, ph_html = (
            [x[i] for i in keep] for x in (ph_urls, ph_labels, ph_dates, ph_origin, ph_html)
        )
    phresh = to_schema(
        pd.Series(ph_urls),
        pd.Series(ph_labels),
        "phreshphish",
        dates=pd.Series(ph_dates),
        html=pd.Series(ph_html),
        origin=pd.Series(ph_origin),
    )
    phiusiil = to_schema(
        pd.Series([f"https://www.home{i}.edu" for i in range(60)] + ["http://p.top/x/y"] * 1),
        pd.Series([0] * 60 + [1]),
        "phiusiil",
        origin="original",
    )
    p360 = to_schema(
        pd.Series([f"https://h{i}.net/login" for i in range(20)]),
        pd.Series([i % 2 for i in range(20)]),
        "phish360",
    )
    return {"phreshphish": phresh, "phiusiil": phiusiil, "phish360": p360}


def _run(tmp_path, frames, dedup_cfg):
    interim = {}
    load_stats = {}
    for name, df in frames.items():
        path = tmp_path / "interim" / f"{name}.parquet"
        load_stats[name] = write_interim([df], path, dedup_cfg)
        interim[name] = path
    cfg = {
        **_corpus_cfg(),
        "paths": {
            "processed_dir": str(tmp_path / "processed"),
            "reports_dir": str(tmp_path / "reports"),
        },
        "sources": {
            "phreshphish": {"license": "CC BY 4.0"},
            "phiusiil": {"license": "CC BY 4.0", "homepage_only_benign": True},
            "phish360": {"license": "to confirm"},
        },
    }
    cfg["corpus"]["max_urls_per_domain"] = 20
    cfg["holdouts"] = HOLDOUT_CFG
    split_cfg = {"seed": 0, "n_splits": 10, "test_fraction": 0.2, "cal_fraction": 0.1}
    attempts = pd.DataFrame(
        {
            "seed_source": ["phiusiil", "phiusiil", "live"],
            "seed_domain": ["home1.edu", "home2.edu", "news.com"],
            "status": ["ok", "robots_disallow_all", "few_pages"],
            "pages": [4, 0, 2],
            "attempted_at": pd.Timestamp("2026-10-07", tz="UTC"),
        }
    )
    return build(interim, cfg, split_cfg, load_stats, attempts)


def test_pipeline_writes_parts_splits_and_card(tmp_path, dedup_cfg):
    card = _run(tmp_path, _sources(), dedup_cfg)
    out = tmp_path / "processed"
    pool = pq.read_table(out / "pool.parquet").to_pandas()
    assert list(pool.columns) == OUTPUT_COLUMNS
    assert pool["html"].notna().any()  # HTML streamed through
    assert (pool["source"] != "phish360").all()
    held = pq.read_table(out / "heldout_source.parquet").to_pandas()
    assert set(held["source"]) == {"phish360"}
    ts = pq.read_table(out / "time_slice.parquet").to_pandas()
    assert set(ts["origin"]) == {"hf_test"}
    splits = pd.read_parquet(out / "splits.parquet")
    assert len(splits) == len(pool) and set(splits["uid"]) == set(pool["uid"])
    assert [c for c in splits.columns if c.startswith("split_")] == [
        f"split_{k}" for k in range(10)
    ]
    for part in (held, ts):
        assert not set(part["domain"]) & set(pool["domain"])
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["counts"][POOL] == len(pool)
    md = (tmp_path / "reports" / "data_card.md").read_text()
    assert "Depth check on the training pool: PASSED" in md
    assert "Benign inner-page crawl" in md and "robots_disallow_all" in md
    assert (tmp_path / "reports" / "tables" / "depth_pool.csv").exists()
    assert card["crawl"].loc["phiusiil", "success_pct"] == 50.0


def test_pipeline_stops_on_homepage_only_benign(tmp_path, dedup_cfg):
    with pytest.raises(DepthImbalanceError):
        _run(tmp_path, _sources(homepage_only_benign=True), dedup_cfg)
    md = (tmp_path / "reports" / "data_card.md").read_text()
    assert "FAILED" in md  # card written before stopping, so the failure can be inspected
    assert not (tmp_path / "processed" / "pool.parquet").exists()
