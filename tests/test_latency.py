"""The latency report renders from the benchmark's JSON."""

from experiments import latency


def test_latency_report_renders():
    s = {"median_ms": 1.8, "p95_ms": 2.7, "max_ms": 4.6}
    text = latency.render(
        {
            "node": "v22",
            "urls": 272,
            "runs": 5,
            "bundle_mb": 11.7,
            "json_parse_ms": 190.0,
            "model_build_ms": 110.0,
            "score": s,
            "score_with_reasons": s | {"median_ms": 158.0},
        }
    )
    assert "| score one URL (features, text models, trees) | 1.8 ms |" in text
    assert "158.0 ms" in text and "11.7 MB" in text
