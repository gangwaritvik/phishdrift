"""Backend domain rules measured on the first-seen captures (tier C hosts of both classes).

python -m experiments.domain_rules [--info-dir data/interim/domain_info] [--reports reports]

The backend (``backend/checks.py``) turns RDAP / DNS / TLS facts into signals with a severity
and a risk level (low / elevated / high). This script runs exactly that code on the collector's
captures, which hold the same raw records the backend looks up live: each eligible host (same
filters as ``experiments.tier_c``: no hosting platforms, IP hosts, hosts filtered by the PC's
resolver, non-resolving hosts, or hosts captured long after first seen) goes through
``facts_from_raw`` and ``evaluate`` with the capture time as "now".

For every signal it reports how often it fires on phishing and on legitimate hosts, with Wilson
95% intervals, and the severity the data supports under ``rules.severity_from_data`` in
``configs/backend.yaml``: ``high`` needs the legitimate rate's upper bound at or below
``high_max_benign_upper`` and a phishing / legitimate rate ratio of at least ``high_min_ratio``;
``warn`` needs a ratio of at least ``warn_min_ratio``; anything else is ``info``. Ratios use
the upper bound of the legitimate rate, so a signal never seen on legitimate hosts is not
given infinite weight. The backend reads the chosen severities from ``rules.severity`` in the
same file (written by hand from this report, so a change is reviewed).

Counts are hosts (one row per host); domains are reported next to them. The capture covers
few days and few phishing hosts, so every rate here has a wide interval.
"""

from __future__ import annotations

import argparse
import math
from collections import Counter
from pathlib import Path

import pandas as pd

from backend.checks import DEFAULT_SEVERITY, evaluate, facts_from_raw
from experiments.tier_c import eligible
from features.build_c import feature_table, read_records
from features.domain_features import pick_domain_record
from features.lists import load_lists
from phishdrift.config import load_config

Z = 1.96


def wilson(k: int, n: int) -> tuple[float, float]:
    if n == 0:
        return math.nan, math.nan
    p = k / n
    den = 1 + Z * Z / n
    mid = (p + Z * Z / (2 * n)) / den
    half = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / den
    return max(0.0, mid - half), min(1.0, mid + half)


def suggested(k_p: int, n_p: int, k_b: int, n_b: int, cfg: dict) -> str:
    if k_p == 0 and k_b == 0:
        return "n/a"  # never fired: nothing to measure
    rate_p = k_p / n_p if n_p else 0.0
    upper_b = wilson(k_b, n_b)[1]
    ratio = rate_p / upper_b if upper_b else math.inf
    if upper_b <= cfg["high_max_benign_upper"] and ratio >= cfg["high_min_ratio"]:
        return "high"
    if ratio >= cfg["warn_min_ratio"]:
        return "warn"
    return "info"


def host_signals(info_dir: Path, rules: dict, max_lag_h: float | None) -> pd.DataFrame:
    """One row per eligible host: label, domain, risk and the ids of the signals that fired."""
    hosts, domains = read_records(info_dir)
    table = feature_table(hosts, domains, load_lists())
    ok, _ = eligible(table, max_lag_h)
    latest = {}
    for rec in sorted(hosts, key=lambda r: str(r.get("captured_at") or "")):
        latest[str(rec["host"]).lower()] = rec
    picked = {d: pick_domain_record(recs) for d, recs in domains.items()}
    rows = []
    for host, label, domain in zip(ok["host"], ok["label"], ok["domain"], strict=True):
        rec = latest[host]
        drec = picked.get(domain) or {}
        now = pd.Timestamp(rec["captured_at"]).to_pydatetime()
        facts = facts_from_raw(
            drec.get("rdap"),
            drec.get("rdap_error"),
            rec.get("dns"),
            rec.get("tls"),
            now,
            rules["free_issuers"],
        )
        signals, risk = evaluate(facts, rules)
        rows.append(
            {
                "host": host,
                "domain": domain,
                "label": int(label),
                "risk": risk,
                "signals": ",".join(s["id"] for s in signals),
            }
            | {f"fact_{k}": v for k, v in facts.items()}
        )
    return pd.DataFrame(rows)


def signal_table(df: pd.DataFrame, cfg: dict, current: dict) -> pd.DataFrame:
    n_p, n_b = int((df["label"] == 1).sum()), int((df["label"] == 0).sum())
    counts = {0: Counter(), 1: Counter()}
    for label, sig in zip(df["label"], df["signals"], strict=True):
        counts[label].update(s for s in sig.split(",") if s)
    rows = []
    current = DEFAULT_SEVERITY | current
    for sid in sorted(set(counts[0]) | set(counts[1]) | set(current)):
        k_p, k_b = counts[1][sid], counts[0][sid]
        lo_p, hi_p = wilson(k_p, n_p)
        lo_b, hi_b = wilson(k_b, n_b)
        rows.append(
            {
                "signal": sid,
                "phishing_hits": k_p,
                "phishing_rate": k_p / n_p if n_p else math.nan,
                "phishing_lo": lo_p,
                "phishing_hi": hi_p,
                "legit_hits": k_b,
                "legit_rate": k_b / n_b if n_b else math.nan,
                "legit_lo": lo_b,
                "legit_hi": hi_b,
                "severity_now": current.get(sid, ""),
                "severity_data": suggested(k_p, n_p, k_b, n_b, cfg),
            }
        )
    return pd.DataFrame(rows)


def risk_table(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for risk in ("low", "elevated", "high"):
        r = {"risk": risk}
        for label, name in ((1, "phishing"), (0, "legit")):
            sub = df[df["label"] == label]
            k = int((sub["risk"] == risk).sum())
            r[f"{name}_hosts"] = k
            r[f"{name}_rate"] = k / len(sub) if len(sub) else math.nan
        rows.append(r)
    return pd.DataFrame(rows)


def _pct(x: float) -> str:
    return "n/a" if x is None or math.isnan(x) else f"{100 * x:.1f}"


def render(df: pd.DataFrame, sig: pd.DataFrame, risk: pd.DataFrame, cfg: dict) -> str:
    n = df.groupby("label").agg(hosts=("host", "size"), domains=("domain", "nunique"))
    lines = [
        "# Backend domain rules on the first-seen captures",
        "",
        "Generated by `python -m experiments.domain_rules`. Do not edit by hand.",
        "The backend's own rule code (`backend/checks.py`) run on the collector's captures of",
        "eligible hosts (filters of `experiments.tier_c`). Rates in % with Wilson 95% intervals.",
        "",
        f"Eligible hosts: {int(n.loc[1, 'hosts']) if 1 in n.index else 0:,} phishing "
        f"({int(n.loc[1, 'domains']) if 1 in n.index else 0:,} domains), "
        f"{int(n.loc[0, 'hosts']) if 0 in n.index else 0:,} legitimate "
        f"({int(n.loc[0, 'domains']) if 0 in n.index else 0:,} domains).",
        "",
        f"Severity from data: `high` if the legitimate upper bound is at most "
        f"{100 * cfg['high_max_benign_upper']:g}% and phishing rate / legitimate upper bound "
        f">= {cfg['high_min_ratio']:g}; `warn` if that ratio >= {cfg['warn_min_ratio']:g}; "
        "else `info`.",
        "",
        "| signal | phishing hosts | phishing % [95% CI] | legit hosts | legit % [95% CI] "
        "| severity in use | severity from data |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in sig.itertuples():
        lines.append(
            f"| {r.signal} | {r.phishing_hits} | {_pct(r.phishing_rate)} "
            f"[{_pct(r.phishing_lo)}, {_pct(r.phishing_hi)}] | {r.legit_hits} "
            f"| {_pct(r.legit_rate)} [{_pct(r.legit_lo)}, {_pct(r.legit_hi)}] "
            f"| {r.severity_now} | {r.severity_data} |"
        )
    lines += [
        "",
        "`not_resolving` cannot be measured here: non-resolving hosts are not eligible.",
        "",
        "## Risk level the backend returns (with the severities in use)",
        "",
        "| risk | phishing hosts | phishing % | legit hosts | legit % |",
        "|---|---|---|---|---|",
    ]
    for r in risk.itertuples():
        lines.append(
            f"| {r.risk} | {r.phishing_hosts} | {_pct(r.phishing_rate)} | {r.legit_hosts} "
            f"| {_pct(r.legit_rate)} |"
        )
    return "\n".join(lines + [""])


def run(info_dir: Path, reports: Path) -> Path:
    cfg = load_config("backend")["rules"]
    tc = load_config("models")["tier_c"]
    df = host_signals(info_dir, cfg, tc.get("max_capture_lag_h"))
    sig = signal_table(df, cfg["severity_from_data"], cfg.get("severity", {}))
    risk = risk_table(df)
    (reports / "tables").mkdir(parents=True, exist_ok=True)
    sig.to_csv(reports / "tables" / "domain_rules_signals.csv", index=False)
    risk.to_csv(reports / "tables" / "domain_rules_risk.csv", index=False)
    out = reports / "domain_rules.md"
    out.write_text(render(df, sig, risk, cfg["severity_from_data"]), encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.domain_rules")
    ap.add_argument("--info-dir", type=Path, default=Path("data/interim/domain_info"))
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    a = ap.parse_args(argv)
    print(run(a.info_dir, a.reports))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
