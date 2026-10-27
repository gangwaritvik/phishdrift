"""Which fresh phishing feeds can a runner read, how big are they, and how fast can RDAP be
asked straight at the registries (IANA bootstrap) instead of through rdap.org?"""

from __future__ import annotations

import io
import json
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor

import requests

UA = {
    "User-Agent": "PhishDrift-research-collector/0.2 (academic project; https://github.com/gangwaritvik/phishdrift)"
}
FEEDS = {
    "openphish": "https://openphish.com/feed.txt",
    "phishdb_links_new_today": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-NEW-today.txt",
    "phishdb_domains_new_today": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-NEW-today.txt",
    "phishdb_domains_active": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "phishdb_links_active": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "phishtank_nokey": "http://data.phishtank.com/data/online-valid.csv",
    "phishstats_csv": "https://phishstats.info/phish_score.csv",
    "phishstats_api": "https://api.phishstats.info/api/phishing?_sort=-date&_size=100",
    "phishunt": "https://phishunt.io/feed.txt",
    "certpl": "https://hole.cert.pl/domains/v2/domains.txt",
    "phishing_army": "https://phishing.army/download/phishing_army_blocklist.txt",
    "urlhaus_recent": "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "tranco_zip": "https://tranco-list.eu/top-1m.csv.zip",
}
for name, url in FEEDS.items():
    t = time.monotonic()
    try:
        r = requests.get(url, timeout=60, headers=UA)
        lines = r.text.count("\n")
        head = "|".join(r.text[:600].splitlines()[:3])[:240].replace("\n", " ")
        print(
            json.dumps(
                {
                    "feed": name,
                    "status": r.status_code,
                    "bytes": len(r.content),
                    "lines": lines,
                    "s": round(time.monotonic() - t, 1),
                    "head": head,
                }
            )
        )
    except Exception as exc:  # noqa: BLE001
        print(json.dumps({"feed": name, "error": repr(exc)[:160]}))

# RDAP straight at the registries
boot = requests.get("https://data.iana.org/rdap/dns.json", timeout=30).json()
tld_base = {}
for tlds, urls in boot["services"]:
    for tld in tlds:
        tld_base[tld.lower()] = urls[0] if urls else None
print("bootstrap tlds:", len(tld_base), "com:", tld_base.get("com"), "xyz:", tld_base.get("xyz"))

z = requests.get("https://tranco-list.eu/top-1m.csv.zip", timeout=120).content
rows = zipfile.ZipFile(io.BytesIO(z)).read("top-1m.csv").decode().splitlines()
doms = [r.split(",")[1] for r in rows[200000:200400]]


def rdap(d):
    tld = d.rsplit(".", 1)[-1]
    base = tld_base.get(tld)
    if not base:
        return d, "no_server", 0
    t = time.monotonic()
    try:
        r = requests.get(
            base.rstrip("/") + "/domain/" + d,
            timeout=20,
            headers={**UA, "Accept": "application/rdap+json"},
        )
        return d, r.status_code, round(time.monotonic() - t, 2)
    except Exception as exc:  # noqa: BLE001
        return d, type(exc).__name__, round(time.monotonic() - t, 2)


for workers in (8, 24):
    t0 = time.monotonic()
    sample = doms[:200] if workers == 8 else doms[200:400]
    with ThreadPoolExecutor(workers) as ex:
        res = list(ex.map(rdap, sample))
    codes = {}
    for _, c, _ in res:
        codes[str(c)] = codes.get(str(c), 0) + 1
    print(
        json.dumps(
            {
                "rdap_direct_workers": workers,
                "n": len(res),
                "s": round(time.monotonic() - t0, 1),
                "codes": codes,
            }
        )
    )
