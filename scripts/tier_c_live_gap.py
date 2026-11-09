"""Live test of the hosted /api/domain-check against the offline pipeline, on the same domains.

prep    candidates: A = phishing domains captured by this job's own feed poll (offline probability
        known), B = older feed entries (OpenPhish now, a Phishing.Database ACTIVE sample) not in the
        captured set, C = legitimate domains captured earlier.
probe   post one shard of the candidates to the live function (Netlify allows 20 calls a minute per IP).
report  caught rates per group and by domain age / RDAP, and live against offline on group A.
"""

import argparse
import json
import random
import re
import sys
import time
from pathlib import Path

import pandas as pd
import requests

from phishdrift.domains import registered_domain

SUS = 0.11705163777773846  # the shipped suspicious cut-off (js/data/tier_c.json)
ACTIVE = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt"
OPENPHISH = "https://openphish.com/feed.txt"
UA = {"User-Agent": "phishdrift-research-probe"}


def host_of(url: str) -> str:
    return re.sub(r"^[a-z]+://([^/:?#@]*@)?([^/:?#]+).*$", r"\2", url.strip().lower())


def prep(a) -> None:
    lists = json.loads(Path("js/data/lists.json").read_text())
    skip = set(lists["platforms"]) | set(lists["shorteners"])
    df = pd.read_csv(a.scores, sep="\t", low_memory=False)
    df["cap"] = pd.to_datetime(df.captured_at, utc=True, errors="coerce", format="mixed")
    df = df[df.label.isin([0, 1]) & ~df.domain.str.lower().isin(skip)]
    known = set(df.domain.str.lower())
    rng = random.Random(0)
    since = pd.Timestamp(a.since)
    fresh = df[(df.label == 1) & (df.cap >= since)].drop_duplicates("domain")
    fresh = fresh.sample(min(a.n_fresh, len(fresh)), random_state=0)
    cands = [
        {
            "domain": r.domain,
            "group": "A_fresh",
            "source": r.source,
            "offline_prob": r.prob,
            "offline_age": None if pd.isna(r.domain_age_days) else r.domain_age_days,
            "offline_resolves": None if pd.isna(r.resolves) else bool(r.resolves),
        }
        for r in fresh.itertuples()
    ]
    seen = {c["domain"] for c in cands}

    def old(group: str, urls: list[str], n: int) -> None:
        hosts = {}
        for u in urls:
            h = host_of(u)
            d = registered_domain("https://" + h + "/") if h else ""
            ok = d and "." in d and not re.fullmatch(r"[\d.]+", d) and d.lower() not in skip
            if ok and d not in known and d not in seen:
                hosts[d] = u
        pick = rng.sample(sorted(hosts), min(n, len(hosts)))
        for d in pick:
            cands.append({"domain": d, "group": group, "source": group})
            seen.add(d)

    old("B_openphish_now", requests.get(OPENPHISH, timeout=60, headers=UA).text.split(), a.n_old)
    old("B_active_sample", requests.get(ACTIVE, timeout=300, headers=UA).text.split(), a.n_old)
    legit = df[(df.label == 0) & (df.cap < since)].drop_duplicates("domain")
    legit = legit.sample(min(a.n_legit, len(legit)), random_state=0)
    cands += [
        {"domain": r.domain, "group": "C_legit", "source": "tranco", "offline_prob": r.prob}
        for r in legit.itertuples()
    ]
    Path(a.out).write_text(json.dumps(cands))
    print(pd.Series([c["group"] for c in cands]).value_counts().to_string())


def check(url: str, domain: str) -> dict:
    for _ in range(3):
        t = time.time()
        try:
            r = requests.post(url, json={"domain": domain}, timeout=30)
        except Exception as e:  # noqa: BLE001
            return {"http": None, "error": repr(e)[:80]}
        if r.status_code == 429:
            time.sleep(61)
            continue
        try:
            body = r.json()
        except ValueError:
            body = {"raw": r.text[:100]}
        return {"http": r.status_code, "sec": round(time.time() - t, 2), **body}
    return {"http": 429}


def probe(a) -> None:
    cands = json.loads(Path(a.cands).read_text())[a.shard :: a.shards]
    with open(a.out, "w") as f:
        for c in cands:
            f.write(
                json.dumps(
                    {**c, "live": check(a.site.rstrip("/") + "/api/domain-check", c["domain"])}
                )
                + "\n"
            )
            f.flush()
            time.sleep(3.3)


def report(a) -> None:
    rows = []
    for p in a.results:
        for line in Path(p).read_text().splitlines():
            r = json.loads(line)
            lv = r.pop("live")
            f = lv.get("facts") or {}
            rows.append(
                {
                    **r,
                    "http": lv.get("http"),
                    "checked": bool(lv.get("checked")),
                    "reason": lv.get("reason"),
                    "detail": lv.get("detail"),
                    "prob": lv.get("prob"),
                    "verdict": lv.get("verdict"),
                    "age": f.get("domain_age_days"),
                    "resolves": f.get("resolves"),
                    "rdap_error": f.get("rdap_error"),
                    "sec": lv.get("sec"),
                }
            )
    d = pd.DataFrame(rows)
    d["flag"] = d.prob >= SUS
    out = ["# Live /api/domain-check against the offline pipeline", ""]
    out.append("## Per group (live)\n")
    out.append(
        "| group | asked | refused | failed | checked | flagged suspicious+ | flagged % of checked | dangerous |"
    )
    out.append("|---|---|---|---|---|---|---|---|")
    for g, x in d.groupby("group"):
        c = x[x.checked]
        refused = int(
            (
                ~x.checked
                & x.reason.isin(["hosting_platform", "shortener", "ip_address", "local_name"])
            ).sum()
        )
        failed = int((~x.checked).sum()) - refused
        out.append(
            f"| {g} | {len(x)} | {refused} | {failed} | {len(c)} | {int(c.flag.sum())} | {c.flag.mean() * 100:.1f} | {int((c.verdict == 'dangerous').sum())} |"
        )
    c = d[d.checked].copy()
    out.append(
        "\nRefusal / failure reasons: "
        + json.dumps(
            {
                f"{g}/{r}": int(n)
                for (g, r), n in d[~d.checked]
                .groupby(["group", "reason"], dropna=False)
                .size()
                .items()
            },
            default=str,
        )
    )
    if len(c):
        c["age_bin"] = pd.cut(c.age, [-1, 30, 365, 100000]).astype(str)
        c["rdap"] = c.rdap_error.fillna("ok")
        for title, col in (("domain age (days)", "age_bin"), ("RDAP result", "rdap")):
            out.append(f"\n## Flagged by {title}, phishing groups\n")
            out.append(
                c[c.group != "C_legit"]
                .groupby(["group", col])
                .agg(n=("flag", "size"), flagged=("flag", "mean"))
                .round(3)
                .to_string()
            )
    A = c[c.group == "A_fresh"].dropna(subset=["offline_prob", "prob"])
    if len(A):
        off = A.offline_prob >= SUS
        out.append(f"\n## Group A: live vs offline on the same {len(A)} domains\n")
        out.append(
            f"- offline flagged {off.mean() * 100:.1f}%, live flagged {A.flag.mean() * 100:.1f}%"
        )
        out.append(
            f"- same verdict side: {(off == A.flag).mean() * 100:.1f}%; offline flagged but live not: {int((off & ~A.flag).sum())}; live flagged but offline not: {int((~off & A.flag).sum())}"
        )
        out.append(
            f"- median |live - offline| probability {(A.prob - A.offline_prob).abs().median():.4f}; rank correlation {A.prob.rank().corr(A.offline_prob.rank()):.3f}"
        )
        out.append(
            f"- domain resolves live: {A.resolves.mean() * 100:.1f}% (offline {A.offline_resolves.dropna().mean() * 100:.1f}%)"
        )
        miss = A[off & ~A.flag]
        if len(miss):
            out.append(
                "\nOffline flagged, live not (first 12):\n"
                + miss[
                    [
                        "domain",
                        "source",
                        "offline_prob",
                        "prob",
                        "offline_age",
                        "age",
                        "resolves",
                        "rdap_error",
                    ]
                ]
                .head(12)
                .round(3)
                .to_string(index=False)
            )
        out.append(
            "\nBy source (group A): "
            + json.dumps(
                A.assign(off=off)
                .groupby("source")
                .agg(n=("flag", "size"), live=("flag", "mean"), offline=("off", "mean"))
                .round(3)
                .to_dict("index")
            )
        )
    t = d.sec.dropna()
    out.append(
        f"\nResponse time: median {t.median():.2f} s, 95th percentile {t.quantile(0.95):.2f} s; failures by detail: "
        + json.dumps(d[d.detail.notna()].detail.value_counts().to_dict())
    )
    Path(a.out).write_text("\n".join(out) + "\n")
    print("\n".join(out))


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prep")
    p.add_argument("--scores", required=True)
    p.add_argument("--since", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--n-fresh", type=int, default=400)
    p.add_argument("--n-old", type=int, default=180)
    p.add_argument("--n-legit", type=int, default=120)
    q = sub.add_parser("probe")
    q.add_argument("--site", required=True)
    q.add_argument("--cands", required=True)
    q.add_argument("--shard", type=int, required=True)
    q.add_argument("--shards", type=int, required=True)
    q.add_argument("--out", required=True)
    r = sub.add_parser("report")
    r.add_argument("--results", nargs="+", required=True)
    r.add_argument("--out", required=True)
    a = ap.parse_args()
    {"prep": prep, "probe": probe, "report": report}[a.cmd](a)
    return 0


if __name__ == "__main__":
    sys.exit(main())
