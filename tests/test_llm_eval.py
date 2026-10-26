"""LLM eval helpers: sets are built from data, cutoffs come from cached answers."""

import json

import pandas as pd

from experiments import llm_eval as ev

ANSWER = {"brand": "Acme", "brand_domain": "acme.com", "confidence": 0.8, "reason": "x"}


def test_sets_come_from_the_inputs_and_lookalikes_change_the_host():
    legit = [f"https://site{i}.example.com/a" for i in range(5)] + ["https://acmebank.com/"]
    d = ev.build_sets(legit, [f"http://bad{i}.test.org/x" for i in range(10)], 4)
    assert set(d["set"]) >= {"legit", "phishing"} and (d["set"] == "phishing").sum() == 4
    for _, r in d[d["set"].str.startswith("lookalike")].iterrows():
        assert r["host"] != ev.host_of(r["origin"])


def test_raise_needs_a_confident_claim_on_another_domain():
    rec = {"host": "acme-login.xyz", "answer": ANSWER, "error": None}
    assert ev.raised(rec, "acme-login.xyz", 0.7) is True
    assert ev.raised(rec, "acme-login.xyz", 0.9) is False
    assert ev.raised(rec, "www.acme.com", 0.7) is False
    assert ev.raised({"host": "h", "answer": None, "error": "boom"}, "h", 0.7) is None


def test_ask_all_resumes_from_the_cache_and_stops_on_quota(tmp_path):
    cache = tmp_path / "c.jsonl"
    calls = []

    def provider(prompt):
        calls.append(prompt)
        if len(calls) == 3:
            raise RuntimeError("HTTP 429: quota")
        return json.dumps(ANSWER)

    got = ev.ask_all(["a.com", "b.com", "c.com", "d.com"], provider, cache, 10)
    assert len(calls) == 3 and set(got) == {"a.com", "b.com", "c.com"}
    again = ev.ask_all(
        ["a.com", "b.com", "c.com", "d.com"], lambda p: json.dumps(ANSWER), cache, 10
    )
    assert "d.com" in again and again["a.com"]["answer"]["brand"] == "Acme"


def test_summary_counts_by_set_and_cutoff():
    d = pd.DataFrame(
        {"set": ["legit", "legit"], "host": ["x.com", "y.com"], "address_passes": [True, True]}
    )
    cache = {"x.com": {"host": "x.com", "answer": ANSWER, "error": None},
             "y.com": {"host": "y.com", "answer": None, "error": "boom"}}  # fmt: skip
    row = ev.summarise(d, cache).iloc[0]
    assert row["hosts"] == 2 and row["answered"] == 1 and row["failed"] == 1
    assert row["raised@0.7"] == 1 and row["raised@0.9"] == 0
