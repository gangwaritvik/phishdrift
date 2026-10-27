"""Can a GitHub Actions runner do the tier C capture? Run by .github/workflows/tier-c-probe.yml.

Reaches each source once, then runs the real capture_job on N phishing and N legitimate
hosts and prints counts and timings (RDAP errors by kind, DNS, TLS). Nothing is stored."""

from __future__ import annotations

import collections
import json
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

import requests

from collector import benign, domain_capture, feeds, ood
from phishdrift.config import load_config
from phishdrift.domains import hostname, registered_domain
from phishdrift.http import HttpClient

N = int(sys.argv[1]) if len(sys.argv) > 1 else 100
out: dict = {}


def timed(name: str, fn):
    t = time.monotonic()
    try:
        res = fn()
        out[name] = {"ok": True, "s": round(time.monotonic() - t, 2), **(res or {})}
    except Exception as exc:  # noqa: BLE001
        out[name] = {"ok": False, "s": round(time.monotonic() - t, 2), "error": repr(exc)[:200]}


cfg = load_config("collector")
dc = cfg["domain_capture"]
client = HttpClient.from_config(cfg["http"], Path(".cache/http"))
ua = {"User-Agent": cfg["http"]["user_agent"]}


def get(url, headers=None, **kw):
    r = requests.get(url, timeout=20, headers={**ua, **(headers or {})}, **kw)
    return {"status": r.status_code, "bytes": len(r.content)}


timed("openphish", lambda: get("https://openphish.com/feed.txt"))
timed("phishing_db_new_today", lambda: get(cfg["feeds"]["phishing_database"]["url"]))
timed("rdap_org_example", lambda: get("https://rdap.org/domain/example.com"))
timed("iana_rdap_bootstrap", lambda: get("https://data.iana.org/rdap/dns.json"))
timed("doh_8888", lambda: get("https://8.8.8.8/resolve?name=example.com&type=A"))
timed(
    "doh_1111",
    lambda: get(
        "https://1.1.1.1/dns-query?name=example.com&type=A",
        headers={"Accept": "application/dns-json"},
    ),
)
timed("tls_example", lambda: domain_capture.tls_facts("example.com", 8))

# targets
phish = []
try:
    df = feeds.FETCHERS["openphish"](client, cfg["feeds"]["openphish"])
    platforms = ood.load_platforms()
    for u in df["url"]:
        h, d = hostname(u), registered_domain(u)
        if h and d and d not in platforms and not domain_capture._is_ip(h):
            phish.append(h)
    phish = list(dict.fromkeys(phish))
    out["openphish_hosts_own_domain"] = len(phish)
    out["openphish_urls"] = len(df)
except Exception as exc:  # noqa: BLE001
    out["openphish_fetch_error"] = repr(exc)[:200]
phish = phish[:N]
ranked: list[str] = []
try:
    t = time.monotonic()
    ranked = benign.tranco_domains(11000, Path(".cache/tranco"))
    out["tranco"] = {"n": len(ranked), "s": round(time.monotonic() - t, 1)}
except Exception as exc:  # noqa: BLE001
    out["tranco_error"] = repr(exc)[:200]
legit = [f"www.{d}" for d in ranked[5000 : 5000 + N]]

query = domain_capture.make_query(dc)
jobs = []
seen_d = set()
for label, hosts in ((1, phish), (0, legit)):
    for h in hosts:
        d = registered_domain(f"https://{h}/")
        jobs.append(
            {
                "host": h,
                "domain": d,
                "rdap": d not in seen_d,
                "target": {"url": f"https://{h}/", "label": label, "first_seen": None},
            }
        )
        seen_d.add(d)
t0 = time.monotonic()
res = []
for job, recs in benign.run_parallel(
    jobs,
    lambda j: domain_capture.capture_job(j, client, dc, query, domain_capture.tls_facts),
    dc["workers"],
    dc["job_deadline_s"],
):
    res.append((job, recs))
out["capture_seconds"] = round(time.monotonic() - t0, 1)
stats: dict = {}
for label in (1, 0):
    rd = collections.Counter()
    dns_ok = tls_ok = tls_ver = n = timeout = 0
    for job, recs in res:
        if job["target"]["label"] != label:
            continue
        n += 1
        if recs is None:
            timeout += 1
            continue
        for r in recs:
            if r["kind"] == "domain":
                rd["ok" if r["rdap"] else r["rdap_error"]] += 1
            else:
                dns_ok += bool(r["dns"] and r["dns"]["resolves"])
                tls_ok += bool(r["tls"] and r["tls"]["ok"])
                tls_ver += bool(r["tls"] and r["tls"].get("verified"))
    stats["phishing" if label else "legit"] = {
        "hosts": n,
        "abandoned": timeout,
        "rdap": dict(rd),
        "dns_resolves": dns_ok,
        "tls_ok": tls_ok,
        "tls_verified": tls_ver,
    }
out["capture"] = stats
print(json.dumps(out, indent=1, default=str))
print("now", datetime.now(UTC).isoformat())
