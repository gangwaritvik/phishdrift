import pandas as pd

from experiments.zone_masking import google_share_links, summarise, verdict

T = {"suspicious": 0.85, "dangerous": 0.99}


def test_google_share_links_are_fixed_and_cover_every_shape():
    a, b = google_share_links(3), google_share_links(3)
    assert a == b
    assert len(a) == 15
    assert {r["set"] for r in a} == {
        "legit_google_drive_file",
        "legit_google_drive_folder",
        "legit_google_docs_document",
        "legit_google_docs_form",
        "legit_google_docs_sheet",
    }


def test_verdict_thresholds():
    assert [verdict(p, T) for p in (0.1, 0.85, 0.99)] == [0, 1, 2]


def test_capped_variant_adds_a_banner_only_at_the_dangerous_threshold():
    rows = pd.DataFrame(
        {
            "set": ["x", "x", "x"],
            "p_plain": [0.1, 0.1, 0.9],
            "p_masked": [0.9, 0.995, 0.1],
        }
    )
    t = summarise(rows, T).iloc[0]
    assert (t["warned_plain"], t["warned_masked"], t["warned_capped"]) == (1, 2, 2)
    assert t["dangerous_masked"] == 1
