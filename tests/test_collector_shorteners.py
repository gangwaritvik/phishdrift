"""Learned shorteners: candidate selection, redirect test, decision rule, end to end with a stub."""

import pandas as pd

from collector import shorteners as sh

CFG = {
    "max_token_len": 12, "min_short_urls": 3, "probe_urls": 5, "min_answered": 3,
    "min_redirect_share": 0.8, "max_candidates": 10, "workers": 2, "probe_timeout_s": 1,
}  # fmt: skip


def test_short_link_shape_picks_candidates():
    urls = [f"https://example.com/{c}" for c in ("aB3x", "Zq9", "k2LmN")]
    urls += ["https://blog.example.org/a/b", "https://blog.example.org/post?id=1"]
    urls += [f"https://host.github.io/{c}" for c in ("aaa", "bbb", "ccc")]
    got = sh.short_link_domains(urls, max_token_len=12, min_short_urls=3, skip={"github.io"})
    assert list(got) == ["example.com"]


def test_redirect_must_leave_the_registrable_domain():
    assert sh.redirects_elsewhere("https://s.test/a", 301, "https://other.example/x")
    assert not sh.redirects_elsewhere("https://s.test/a", 302, "/b")
    assert not sh.redirects_elsewhere("https://s.test/a", 200, None)


def test_decision_needs_enough_answers_and_share():
    d = {"min_answered": 3, "min_share": 0.8}
    assert sh.is_shortener([True, True, True, True, None], **d)
    assert not sh.is_shortener([True, True, None, None, None], **d)
    assert not sh.is_shortener([True, False, False, False], **d)


class Stub:
    def head(self, url, timeout_s=None):
        if "fwd.test" in url:
            return 301, "https://elsewhere.example/landing"
        return 200, None


def test_learn_marks_only_the_forwarding_domain():
    urls = [f"https://fwd.test/{i}ab" for i in range(4)] + [
        f"https://page.test/{i}ab" for i in range(4)
    ]
    t = sh.learn(Stub(), urls, CFG).set_index("domain")
    assert bool(t.loc["fwd.test", "shortener"]) and not bool(t.loc["page.test", "shortener"])
    assert isinstance(t, pd.DataFrame)
