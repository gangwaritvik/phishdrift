"""How often candidate brand names appear in phishing URLs, and inside which longer words.

python -m experiments.brand_evidence --phishing FILE [FILE ...] \
    [--names configs/lists/brand_additions.txt] [--extra NAME ...] [--benign-csv FILE ...]

Evidence for ``configs/lists/brand_additions.txt``: a name earns a place when phishers use it now,
not when it is popular. For each name it counts the distinct registrable domains whose host + path
contains it (the same substring test the tier A brand features use) in the phishing URL lists,
and lists the most frequent words that contain it, so a hit inside an unrelated word shows up
("revolut" inside "revolution"). ``--benign-csv`` (a CSV with a ``url`` column, e.g. the natural
legitimate pages) adds the same count on legitimate URLs, leaving out the brand's own domain.

Writes ``reports/tables/brand_evidence.csv``. No model, no training.
"""

from __future__ import annotations

import argparse
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

from phishdrift.domains import registered_domain

_WORD = re.compile(r"[a-z0-9]+")


def url_parts(url: str) -> tuple[str, str] | None:
    """(host + path, registrable domain) in lower case, or None for an unparsable URL."""
    url = url.strip()
    if "://" not in url:
        url = "http://" + url
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if not host:
        return None
    return host + parts.path.lower(), registered_domain(host) or host


def read_names(files: list[Path], extra: list[str]) -> list[str]:
    names: list[str] = []
    for path in files:
        for line in path.read_text(encoding="utf-8").splitlines():
            token = line.split("#", 1)[0].strip().lower()
            if token:
                names.append(token)
    names += [e.lower() for e in extra]
    return list(dict.fromkeys(names))


def evidence(names: list[str], phishing: list[str], benign: list[str]) -> pd.DataFrame:
    phish_dom: dict[str, set[str]] = defaultdict(set)
    words: dict[str, Counter] = defaultdict(Counter)
    for url in phishing:
        got = url_parts(url)
        if got is None:
            continue
        text, dom = got
        for name in names:
            if name in text:
                phish_dom[name].add(dom)
                words[name].update(w for w in set(_WORD.findall(text)) if name in w)
    ben_dom: dict[str, set[str]] = defaultdict(set)
    for url in benign:
        got = url_parts(url)
        if got is None:
            continue
        text, dom = got
        for name in names:
            if name in text and not dom.startswith(name + "."):
                ben_dom[name].add(dom)
    rows = []
    for name in names:
        total = sum(words[name].values())
        rows.append(
            {
                "name": name,
                "phishing_domains": len(phish_dom[name]),
                "exact_word_share": round(words[name][name] / total, 3) if total else 0.0,
                "top_words": " ".join(f"{w}:{n}" for w, n in words[name].most_common(5)),
                "benign_domains": len(ben_dom[name]),
                "benign_examples": " ".join(sorted(ben_dom[name])[:5]),
            }
        )
    return pd.DataFrame(rows)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--phishing", type=Path, nargs="+", required=True)
    ap.add_argument(
        "--names", type=Path, nargs="*", default=[Path("configs/lists/brand_additions.txt")]
    )
    ap.add_argument("--extra", nargs="*", default=[])
    ap.add_argument("--benign-csv", type=Path, nargs="*", default=[])
    ap.add_argument("--reports", type=Path, default=Path("reports"))
    a = ap.parse_args(argv)
    names = read_names(a.names, a.extra)
    phishing = [
        ln for f in a.phishing for ln in f.read_text(errors="replace").splitlines() if ln.strip()
    ]
    benign = [u for f in a.benign_csv for u in pd.read_csv(f)["url"].astype(str)]
    table = evidence(names, phishing, benign)
    out = a.reports / "tables" / "brand_evidence.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    table.to_csv(out, index=False)
    print(f"{len(phishing)} phishing URLs, {len(benign)} legitimate URLs, {len(names)} names")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
