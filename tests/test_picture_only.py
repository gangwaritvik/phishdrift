import pandas as pd

from experiments.picture_only import legit_table, phishing_table


def test_legit_table_counts_only_pages_the_page_path_does_not_already_warn():
    visual = pd.DataFrame(
        {
            "url": ["a", "b", "c"],
            "ok": [True, True, True],
            "visual": [
                {"textChars": 10, "fields": 0, "pictures": 1, "largest": 0.5},
                {"textChars": 10, "fields": 0, "pictures": 1, "largest": 0.5},
                {"textChars": 500, "fields": 0, "pictures": 1, "largest": 0.5},
            ],
        }
    )
    probs = pd.DataFrame(
        {
            "url": ["a", "b", "c"],
            "allow": [False, True, False],
            "shortener": [False, False, False],
            "prob": [0.6, 0.9, 0.9],
            "unreadable": [0, 0, 0],
        }
    )
    t = legit_table(visual, probs).set_index(["definition", "allowlist"])
    row = t.loc[("... and a picture element", "on")]
    assert (row["matching"], row["added >=0.5"], row["added >=0.7"]) == (1, 1, 0)
    # without the allowlist the allowlisted page counts too; the text-heavy page never does
    assert t.loc[("... and a picture element", "off")]["matching"] == 2


def test_phishing_table_excludes_addresses_already_warned():
    probs = pd.DataFrame(
        {
            "allow": [False, False, False],
            "shortener": [False, False, False],
            "verdict": [1, 0, 0],
            "unreadable": [1, 0, 0],
            "prob": [0.95, 0.6, 0.2],
        }
    )
    row = phishing_table(probs).iloc[0]
    assert (row["not warned"], row["not warned and >=0.5"], row["not warned and >=0.3"]) == (
        2,
        1,
        1,
    )
