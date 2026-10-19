"""Pure helpers of experiments/render_gap.py (no browser, no node)."""

from __future__ import annotations

import pandas as pd

from experiments.render_gap import compare, rates, sample_pages, top_changes, transitions


def _side(verdicts, pages, has_html, creds=None):
    n = len(verdicts)
    return pd.DataFrame(
        {
            "url": [f"https://www.site{i}.co.uk/p" for i in range(n)],
            "verdict": verdicts,
            "layer": ["model"] * n,
            "page": pages,
            "probPage": pages,
            "hasHtml": has_html,
            "creds": creds if creds is not None else [False] * n,
            "short": [False] * n,
        }
    )


def test_compare_and_rates():
    raw = _side([0, 1, 0, 2], [0.1, 0.6, None, 0.99], [True, True, False, True])
    ren = _side([1, 0, 0, 2], [0.5, 0.2, 0.3, 0.98], [True, True, True, True], [True, None, 0, 0])
    m = compare(raw, ren)
    assert list(m["change"]) == [1, -1, 0, 0]
    assert m["delta"].round(3).tolist()[:2] == [0.4, -0.4]
    assert pd.isna(m["delta"].iloc[2])
    assert m["creds_ren"].tolist() == [True, False, False, False]
    r = {(x["subset"], x["side"]): x for x in rates(m)}
    assert r[("all rendered pages", "raw HTML")]["warned"] == 2
    assert r[("all rendered pages", "rendered DOM")]["dangerous"] == 1
    assert r[("page model reads both", "raw HTML")]["pages"] == 3
    assert r[("page model reads both", "raw HTML")]["warned_pct"] == 200 / 3


def test_transitions_and_top_changes():
    raw = _side([0, 1, 0], [0.1, 0.6, 0.5], [True] * 3)
    ren = _side([1, 0, 0], [0.5, 0.2, 0.45], [True] * 3)
    m = compare(raw, ren)
    assert transitions(m) == {"safe->suspicious": 1, "suspicious->safe": 1}
    top = top_changes(m, 2)
    assert len(top) == 2
    assert set(top["domain"]) == {"site0.co.uk", "site1.co.uk"}
    assert top["abs_delta"].iloc[0] >= top["abs_delta"].iloc[1]


def test_sample_pages_is_fixed_and_ordered():
    pages = pd.DataFrame({"url": [f"u{i}" for i in range(50)], "html": ["x"] * 50})
    a = sample_pages(pages, 10, seed=3)
    b = sample_pages(pages, 10, seed=3)
    assert a["url"].tolist() == b["url"].tolist()
    assert a["url"].tolist() == sorted(a["url"].tolist(), key=lambda u: int(u[1:]))
    assert len(sample_pages(pages, None)) == 50
    assert len(sample_pages(pages, 500)) == 50
