"""Shared-host cap: what capping the address model at "suspicious" does on free-hosting platforms.

``python -m experiments.shared_host_cap --umbrella top-1m.csv --feed ACTIVE.txt [--check URL ...]``

Two sets of addresses on hosting platforms (``configs/platforms.yaml``), scored by
``js/bench/shared_hosts.mjs`` (bundled allowlist, tier A model, the extension's combiner; no page,
backend or blocklist), once as the combiner behaved before the cap and once with it:

- tenant hosts in the Cisco Umbrella top 1M (``rank,host`` lines): hosts real resolvers asked for.
  A proxy for ordinary tenant sites, not a clean legitimate set (it holds API and test hosts and
  some abused ones), and popularity is used for evaluation only, never to set a threshold;
- tenant URLs from the Phishing.Database ACTIVE list, a seeded sample.

A platform is reported when it has at least ``--min-feed`` feed URLs and ``--min-umbrella`` Umbrella
hosts. Platforms with more than ``--max-umbrella`` Umbrella hosts are cloud or CDN infrastructure
(amazonaws.com, cloudfront.net ...), not places people publish sites; they are listed but left out
of the pooled row. Writes ``reports/shared_host_cap.md``. Fixed seed.
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd
import yaml

from features.lists import ROOT

BENCH = ROOT / "js" / "bench" / "shared_hosts.mjs"
SEED = 0


def load_platforms() -> set[str]:
    raw = yaml.safe_load((ROOT / "configs" / "platforms.yaml").read_text(encoding="utf-8"))
    items = raw["platforms"] if isinstance(raw, dict) else raw
    return {str(p).lower() for p in items}


def platform_of(host: str, platforms: set[str]) -> str | None:
    parts = host.lower().split(".")
    for i in range(1, len(parts)):
        suffix = ".".join(parts[i:])
        if suffix in platforms:
            return suffix
    return None


def run_bench(urls: list[str]) -> pd.DataFrame:
    subprocess.run(["node", str(ROOT / "extension" / "build.mjs")], check=True, capture_output=True)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write("\n".join(urls))
    out = subprocess.run(
        ["node", str(BENCH), f.name],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    Path(f.name).unlink()
    return pd.DataFrame(json.loads(out.stdout))


def host_of(url: str) -> str:
    return (urlsplit(url if "://" in url else "http://" + url).hostname or "").lower()


def pct(d: pd.DataFrame, col: str, kind: str) -> str:
    if not len(d):
        return "n/a"
    hit = d[col].isin(["suspicious", "dangerous"] if kind == "warned" else ["dangerous"])
    return f"{100 * hit.mean():.1f}"


def table(rows: list[dict]) -> str:
    warn, dang = "warned before / after %", "dangerous before / after %"
    head = f"| platform | Umbrella hosts | {warn} | {dang} | feed URLs | {warn} | {dang} |"
    lines = [head, "|" + " --- |" * 7]
    for r in rows:
        lines.append("| " + " | ".join(str(r[k]) for k in r) + " |")
    return "\n".join(lines)


def summary_row(name: str, u: pd.DataFrame, f: pd.DataFrame) -> dict:
    return {
        "platform": name,
        "umb_n": len(u),
        "umb_warn": f"{pct(u, 'before', 'warned')} / {pct(u, 'after', 'warned')}",
        "umb_dang": f"{pct(u, 'before', 'dangerous')} / {pct(u, 'after', 'dangerous')}",
        "feed_n": len(f),
        "feed_warn": f"{pct(f, 'before', 'warned')} / {pct(f, 'after', 'warned')}",
        "feed_dang": f"{pct(f, 'before', 'dangerous')} / {pct(f, 'after', 'dangerous')}",
    }


def run(a: argparse.Namespace) -> Path:
    platforms = load_platforms()
    umb = [
        line.strip().split(",", 1)[1]
        for line in a.umbrella.read_text(encoding="utf-8").splitlines()
        if "," in line
    ]
    feed = [u.strip() for u in a.feed.read_text(encoding="utf-8").splitlines() if u.strip()]
    u_by = {h: platform_of(h, platforms) for h in umb}
    f_by = {u: platform_of(host_of(u), platforms) for u in feed}
    u_count = pd.Series([p for p in u_by.values() if p]).value_counts()
    f_count = pd.Series([p for p in f_by.values() if p]).value_counts()
    keep = [
        p for p in f_count.index if f_count[p] >= a.min_feed and u_count.get(p, 0) >= a.min_umbrella
    ]
    sites = [p for p in keep if u_count[p] <= a.max_umbrella]

    rng = random.Random(SEED)
    f_urls = [u for u, p in f_by.items() if p in keep]
    rng.shuffle(f_urls)
    f_urls = f_urls[: a.feed_sample]
    u_plat = {f"https://{h}/": p for h, p in u_by.items() if p in keep}
    u_urls = list(u_plat)
    ur = run_bench(u_urls)
    fr = run_bench(f_urls)
    ur["platform"] = [u_plat[x] for x in ur["url"]]
    fr["platform"] = [f_by[x] for x in fr["url"]]

    rows = [summary_row(p, ur[ur["platform"] == p], fr[fr["platform"] == p]) for p in keep]
    u_sites, f_sites = ur[ur["platform"].isin(sites)], fr[fr["platform"].isin(sites)]
    pooled = summary_row("**site platforms pooled**", u_sites, f_sites)
    allowed = int(u_sites["allowlisted"].sum())
    checks = run_bench(a.check) if a.check else pd.DataFrame()

    out = a.reports / "shared_host_cap.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    text = [
        "# Shared-host cap",
        "",
        "Generated by `python -m experiments.shared_host_cap`. Address layers only (bundled",
        'allowlist, tier A model, combiner), no page, backend or blocklist. "Before" is the',
        'combiner without the cap, "after" with it.',
        "",
        f"Sets: {len(u_urls)} Umbrella tenant hosts and {len(f_urls)} sampled Phishing.Database",
        f"ACTIVE tenant URLs on {len(keep)} platforms (at least {a.min_feed} feed URLs and",
        f"{a.min_umbrella} Umbrella hosts each; seed {SEED}). Platforms with more than",
        f"{a.max_umbrella} Umbrella hosts are infrastructure and are left out of the pooled row.",
        f"{allowed} of the pooled Umbrella hosts are on the allowlist.",
        "",
        table(rows + [pooled]),
        "",
        "Umbrella hosts are an imperfect stand-in for ordinary tenant sites (API, test and some",
        "abused hosts are in it): read those columns as a rough false-alarm rate.",
    ]
    if len(checks):
        text += ["", "## Checked addresses", "", "| address | score | before | after |"]
        text += ["| --- | --- | --- | --- |"]
        text += [
            f"| {r.url} | {r.prob:.3f} | {r.before} | {r.after} |" for r in checks.itertuples()
        ]
    out.write_text("\n".join(text) + "\n", encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="experiments.shared_host_cap")
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    ap.add_argument("--umbrella", type=Path, required=True)
    ap.add_argument("--feed", type=Path, required=True)
    ap.add_argument("--feed-sample", type=int, default=8000)
    ap.add_argument("--min-feed", type=int, default=100)
    ap.add_argument("--min-umbrella", type=int, default=20)
    ap.add_argument("--max-umbrella", type=int, default=1000)
    ap.add_argument("--check", nargs="*", default=[])
    print(run(ap.parse_args(argv)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
