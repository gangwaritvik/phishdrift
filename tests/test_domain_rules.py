from backend.checks import evaluate
from experiments.domain_rules import suggested, wilson
from phishdrift.config import load_config

CFG = {"high_max_benign_upper": 0.01, "high_min_ratio": 10, "warn_min_ratio": 2}


def test_wilson_bounds():
    lo, hi = wilson(0, 1000)
    assert lo == 0.0 and 0.003 < hi < 0.004
    lo, hi = wilson(50, 100)
    assert lo < 0.5 < hi


def test_suggested_severity():
    assert suggested(13, 140, 0, 1398, CFG) == "high"  # never on legitimate hosts
    assert suggested(31, 140, 307, 1398, CFG) == "info"  # as common on legitimate hosts
    assert suggested(5, 140, 1, 1398, CFG) == "warn"
    assert suggested(0, 140, 0, 1398, CFG) == "n/a"


def test_config_severity_overrides_default():
    rules = load_config("backend")["rules"]
    facts = {"registered": False, "tls_verified": False, "age_days": 3, "cert_free_issuer": True}
    signals, risk = evaluate(facts, rules)
    sev = {s["id"]: s["severity"] for s in signals}
    assert sev["domain_unregistered"] == "info"
    assert sev["tls_unverified"] == "info"
    assert sev["domain_very_young"] == "high"
    assert risk == "high"
    signals, risk = evaluate({"registered": False}, rules | {"severity": {}})
    assert signals[0]["severity"] == "warn" and risk == "elevated"
