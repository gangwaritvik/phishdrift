"""Picture-only rule: false alarms on natural legitimate pages and address-side reach on phishing.

``python -m experiments.picture_only --pages data/raw/ood_html/pages --cache DIR [--phishing-urls FILE]``

The rule (``extension/src/pagefacts.js`` ``isPictureOnly``, ``combine.js``): a page with next to no
text, no input fields and one picture covering a good part of the window is raised from safe to
suspicious when the address model already gives the address at least ``PICTURE_MIN_PROB``.

Legitimate side: each natural legitimate page with stored HTML is rendered offline in headless
Chromium (``js/bench/picture_facts.mjs``: the stored HTML at its real address, every other request
aborted, so images and styles never load and picture sizes are a lower bound) and the content script's
``visualFacts`` are read from the live DOM. Counted three ways, from loosest to strictest: no text
and no fields; plus at least one picture element (upper bound for the real rule, which also needs a
picture covering ``PICTURE_MIN_AREA`` of the window); plus the area rule on the sizes the offline
render could measure. Each is then split by the address layer (bundled allowlist; address score at
or above each gate), with ``js/bench/address_probs.mjs``.

Phishing side: no phishing HTML is available, so only the address half is measured: of a fixed-seed
sample of ``--phishing-urls`` (one URL per line), how many the address model passes (safe) and how
many of those score at or above each gate, i.e. would be raised if their page were picture-only.

Writes ``reports/picture_only.md`` and ``reports/tables/picture_only_*.csv``. The gate was chosen
on these same two sets, so the numbers are not independent of the choice.
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
from pathlib import Path

import pandas as pd

from experiments.page_fixes_fpr import load_pages

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "js" / "bench"
GATES = (0.3, 0.4, 0.5, 0.6, 0.7, 0.8)
MAX_TEXT = 100
MIN_AREA = 0.1
SEED = 0


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def read_jsonl(path: Path) -> pd.DataFrame:
    with path.open(encoding="utf-8") as f:
        return pd.DataFrame([json.loads(line) for line in f if line.strip()])


def address_probs(dist: Path, urls: Path, out: Path) -> pd.DataFrame:
    with out.open("w", encoding="utf-8") as f:
        subprocess.run(
            ["node", str(BENCH / "address_probs.mjs"), str(dist), str(urls)],
            check=True,
            stdout=f,
            timeout=3600,
        )
    return read_jsonl(out)


def legit_table(visual: pd.DataFrame, probs: pd.DataFrame) -> pd.DataFrame:
    """One row per (definition, allowlist, gate): pages the rule would raise."""
    ok = visual[visual["ok"]].copy()
    v = pd.json_normalize(ok["visual"]).set_index(ok["url"])
    d = v.join(probs.set_index("url")[["allow", "shortener", "prob", "unreadable"]], how="inner")
    base = (d["textChars"] < MAX_TEXT) & (d["fields"] == 0)
    defs = {
        "no text, no fields": base,
        "... and a picture element": base & (d["pictures"] >= 1),
        f"... and a picture over {MIN_AREA:.0%} of the window (measurable offline)": base
        & (d["largest"] >= MIN_AREA),
    }
    rows = []
    for name, mask in defs.items():
        for allow in ("on", "off"):
            keep = mask & ~d["shortener"]
            scored = d[keep & ~d["allow"]] if allow == "on" else d[keep]
            row = {"definition": name, "allowlist": allow, "pages": len(d), "matching": len(scored)}
            # the rule adds a warning only where the page path would not already give one
            added = scored[scored["unreadable"] == 0]
            row["already warned"] = len(scored) - len(added)
            for g in GATES:
                row[f"added >={g}"] = int((added["prob"] >= g).sum())
            rows.append(row)
    return pd.DataFrame(rows)


def phishing_table(probs: pd.DataFrame) -> pd.DataFrame:
    scored = probs[~probs["allow"] & ~probs["shortener"]]
    safe = scored[scored["unreadable"] == 0]
    row = {
        "urls": len(probs),
        "scored": len(scored),
        "address warns": int((scored["verdict"] >= 1).sum()),
        "page path warns an unreadable page": int((scored["unreadable"] >= 1).sum()),
        "not warned": len(safe),
    }
    for g in GATES:
        row[f"not warned and >={g}"] = int((safe["prob"] >= g).sum())
    return pd.DataFrame([row])


def md(df: pd.DataFrame) -> str:
    head = "| " + " | ".join(df.columns) + " |"
    sep = "|" + "---|" * len(df.columns)
    body = ["| " + " | ".join(str(x) for x in r) + " |" for r in df.itertuples(index=False)]
    return "\n".join([head, sep, *body])


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pages", type=Path, required=True, help="parquet file or dir (url, html)")
    ap.add_argument("--cache", type=Path, required=True)
    ap.add_argument("--phishing-urls", type=Path, default=None)
    ap.add_argument("--phishing-sample", type=int, default=5000)
    ap.add_argument("--dist", type=Path, default=ROOT / "extension" / "dist")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--reports", type=Path, default=ROOT / "reports")
    a = ap.parse_args()
    a.cache.mkdir(parents=True, exist_ok=True)

    pages = load_pages(a.pages)
    pages_jl = a.cache / "pages.jsonl"
    write_jsonl(pages_jl, [{"url": u, "html": h} for u, h in zip(pages["url"], pages["html"], strict=True)])
    visual_jl = a.cache / "visual.jsonl"
    subprocess.run(
        ["node", str(BENCH / "picture_facts.mjs"), str(pages_jl), str(visual_jl), "--workers", str(a.workers)],
        check=True,
        timeout=6 * 3600,
    )
    visual = read_jsonl(visual_jl)
    urls_jl = a.cache / "urls.jsonl"
    write_jsonl(urls_jl, [{"url": u} for u in pages["url"]])
    legit = legit_table(visual, address_probs(a.dist, urls_jl, a.cache / "legit_probs.jsonl"))

    lines = [
        "# Picture-only rule: false alarms and reach",
        "",
        f"Natural legitimate pages with stored HTML: {len(pages):,}; rendered offline: "
        f"{int(visual['ok'].sum()):,} (failed {int((~visual['ok']).sum())}). Window 1280x720, images and "
        "styles never load, so picture sizes are a lower bound and picture counts an upper bound.",
        "",
        f"Definition: fewer than {MAX_TEXT} readable characters, no input fields (the area rule needs "
        f"a picture covering at least {MIN_AREA:.0%} of the window). Cells: pages that would be raised "
        "at each address-score gate (address layer: bundled allowlist, then the address model; "
        "shortener addresses are never raised).",
        "",
        md(legit),
        "",
    ]
    legit.to_csv(a.reports / "tables" / "picture_only_legit.csv", index=False)

    if a.phishing_urls:
        urls = [u for u in a.phishing_urls.read_text(encoding="utf-8", errors="ignore").split() if u.startswith("http")]
        random.Random(SEED).shuffle(urls)
        sample = urls[: a.phishing_sample]
        ph_jl = a.cache / "phishing.jsonl"
        write_jsonl(ph_jl, [{"url": u} for u in sample])
        ph = phishing_table(address_probs(a.dist, ph_jl, a.cache / "phishing_probs.jsonl"))
        ph.to_csv(a.reports / "tables" / "picture_only_phishing.csv", index=False)
        lines += [
            f"## Phishing addresses (address side only; no phishing HTML in this environment)",
            "",
            f"Fixed-seed sample of {len(sample):,} URLs from `{a.phishing_urls.name}`.",
            "'address safe' = the address model passes them; the other columns are how many of those "
            "would be raised if their page were picture-only.",
            "",
            md(ph),
            "",
        ]
    (a.reports / "picture_only.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
