"""Live test of the hosted /api/domain-check: legitimate domains and fresh OpenPhish domains.
Usage: python scripts/domain_check_probe.py SITE_URL. Netlify allows 20 calls a minute per IP, so calls are spaced."""
import json
import re
import sys
import time
import requests

site = sys.argv[1].rstrip("/")
url = site + "/api/domain-check"
LEGIT = ["google.com", "wikipedia.org", "github.com", "bbc.co.uk", "sbi.co.in", "paypal.com", "netflix.com",
         "stackoverflow.com", "hdfcbank.com", "irctc.co.in", "mujtoppers.in", "ycombinator.com"]


def check(domain):
    for _ in range(3):
        t = time.time()
        try:
            r = requests.post(url, json={"domain": domain}, timeout=30)
        except Exception as e:
            return {"domain": domain, "http": None, "error": repr(e)[:100]}
        if r.status_code == 429:
            time.sleep(61)
            continue
        try:
            body = r.json()
        except ValueError:
            body = {"raw": r.text[:150]}
        return {"http": r.status_code, "sec": round(time.time() - t, 2), **body}
    return {"domain": domain, "http": 429}


def show(tag, o):
    f = o.get("facts") or {}
    print(tag, o.get("domain"), o.get("http"), o.get("sec"), o.get("verdict") or o.get("reason") or o.get("error"),
          o.get("prob"), "age", f.get("domain_age_days"), "resolves", f.get("resolves"), "rdap_err", f.get("rdap_error"),
          "|", "; ".join(o.get("reasons") or [])[:160], "| detail", o.get("detail"))


r = requests.get(site + "/", timeout=30)
print("site / HTTP", r.status_code)
first = check("example.org")
print("first call:", json.dumps(first)[:300])
if first.get("http") != 200:
    sys.exit("endpoint not live")

feed = requests.get("https://openphish.com/feed.txt", timeout=60, headers={"User-Agent": "phishdrift-research-probe"}).text.split()
hosts, seen = [], set()
for u in feed:
    h = re.sub(r"^https?://([^/:?#]+).*$", r"\1", u).lower()
    if h not in seen and h.count(".") <= 2:
        seen.add(h)
        hosts.append(h)
print("feed urls", len(feed), "candidate hosts", len(hosts))
legit, phish = [], []
for d in LEGIT:
    o = check(d)
    legit.append(o)
    show("LEGIT", o)
    time.sleep(3.2)
for h in hosts[:40]:
    if sum(1 for p in phish if p.get("checked")) >= 15:
        break
    o = check(h)
    phish.append(o)
    show("PHISH", o)
    time.sleep(3.2)
again = check(LEGIT[0]); show("AGAIN(cache)", again)
for name, rows in (("legit", legit), ("phish", phish)):
    c = [x for x in rows if x.get("checked")]
    v = {}
    for x in c:
        v[x["verdict"]] = v.get(x["verdict"], 0) + 1
    print("SUMMARY", name, "asked", len(rows), "checked", len(c), "verdicts", v,
          "median sec", sorted(x.get("sec", 0) for x in rows)[len(rows) // 2] if rows else None)
