"""Look-alike training examples: held-out brands stay out, default off, export guard."""

import pandas as pd
import pytest

from experiments.hybrid_a import LOOKALIKE, VARIANTS
from features.brand_mismatch import BrandMismatch
from features.fit import Fitted
from features.lists import load_lists
from models.export_hybrid import main as export_main
from models.lookalike_aug import split_brands, url_frame, with_lookalikes
from phishdrift.config import load_config

EXP = {**load_config("lookalike_exp"), "aug_fraction": 0.2}


@pytest.fixture(scope="module")
def setup():
    lists = load_lists()
    bm = BrandMismatch.from_lists(min_brand_len=EXP["min_brand_len"])
    urls = [f"https://site{i}.example.org/a/b{i}" for i in range(60)]
    train = url_frame(urls, lists, Fitted(), bm)
    train["label"] = [i % 2 for i in range(60)]
    train["weight"] = 1.0
    train["depth"] = 2
    return lists, train


def test_held_out_brands_never_reach_training(setup):
    lists, train = setup
    for k in (0, 1):
        _, held = split_brands(lists, EXP, k)
        out, aug = with_lookalikes(train, k, lists, Fitted(), set(train["domain"]), EXP)
        assert len(aug) and set(held).isdisjoint({g[6:] for g in aug["domain"]})
        assert len(out) == len(train) + len(aug)
        assert out["domain"].iloc[: len(train)].tolist() == train["domain"].tolist()


def test_rows_are_phishing_lookalikes_and_legitimate_official_domains(setup):
    lists, train = setup
    _, aug = with_lookalikes(train, 0, lists, Fitted(), set(train["domain"]), EXP)
    assert set(aug["label"]) == {0, 1} and (aug["label"].mean() == 0.5)
    bm = BrandMismatch.from_lists(min_brand_len=EXP["min_brand_len"])
    legit = aug[aug["label"] == 0]
    assert all(
        d in bm.official for d in pd.Series([p.domain for p in legit["_parts"]]).drop_duplicates()
    )


def test_augmentation_is_deterministic(setup):
    lists, train = setup
    a = with_lookalikes(train, 2, lists, Fitted(), set(), EXP)[1]["url"].tolist()
    b = with_lookalikes(train, 2, lists, Fitted(), set(), EXP)[1]["url"].tolist()
    assert a == b


def test_default_variants_do_not_augment_and_export_refuses_shipped_paths():
    assert "hybrid2" not in LOOKALIKE and "hybrid" not in LOOKALIKE
    assert set(VARIANTS) >= LOOKALIKE
    with pytest.raises(SystemExit):
        export_main(["--lookalike"])  # default --out is the shipped bundle


def test_natural_frame_drops_used_domains_and_failed_pages(tmp_path, setup):
    from experiments.lookalike_a import natural_frame

    lists, _ = setup
    csv = tmp_path / "n.csv"
    csv.write_text(
        "url,domain,ok\nhttps://a.org/x/y,a.org,True\nhttps://b.org/z,b.org,True\n"
        "https://c.org/q,c.org,False\n"
    )
    bm = BrandMismatch.from_lists()
    out = natural_frame(csv, lists, Fitted(), bm, {"b.org"})
    assert out["domain"].tolist() == ["a.org"] and out["label"].tolist() == [0]
    assert out["depth"].tolist() == [2]
