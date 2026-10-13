"""The shipped-verdicts report renders from verdict rows."""

import pandas as pd

from experiments import shipped_verdicts as sv


def _rows():
    return pd.DataFrame(
        {
            "url": ["https://a.com/x", "https://b.com/y", "https://c.com/z", "https://d.com/"],
            "domain": ["a.com", "b.com", "c.com", "d.com"],
            "allowlisted": [True, False, False, False],
            "model": ["suspicious", "suspicious", "dangerous", "safe"],
            "shipped": ["safe", "suspicious", "dangerous", "safe"],
        }
    )


def test_summarise_counts_allowlist_effect():
    r = sv.summarise("set", _rows())
    assert r["allowlisted_urls"] == 1
    assert (r["model_suspicious"], r["model_dangerous"]) == (2, 1)
    assert (r["shipped_suspicious"], r["shipped_dangerous"]) == (1, 1)
    assert r["not_allowlisted_urls"] == 3 and r["not_allowlisted_flagged"] == 2


def test_report_renders():
    d = _rows()
    text = sv.render([sv.summarise("set", d)], d[d["shipped"] != "safe"])
    assert "| set | 4 | 4 | 1 (25.0%)" in text
    assert "b.com" in text and "dangerous" in text
