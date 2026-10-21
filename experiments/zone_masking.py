"""Would masking learned open-hosting zones help the address model? (lists gap 8)

``python -m experiments.zone_masking --cases CASES.json`` (needs ``node extension/build.mjs``)

Learned open-hosting zones (``sites.google.com``, ``cloudapp.azure.com``, ``telegra.ph``; the
bundled allowlist's ``open_hosting``) are unknown to the URL features, which mask only
platform-list domains, so the address model reads ``sites.google.com/view/x`` as Google's own
address. This scores every case URL inside a zone as it is and with the zone part of the host
replaced by the platform token (``js/bench/zone_masking.mjs``), at the shipped thresholds.
CASES.json: ``{"urls": [{"set", "url"}]}`` (the list test cases). Legitimate Google Drive and
Docs share links with random ids (fixed seed) are added, since those zones are the riskiest.
Writes ``reports/zone_masking.md`` and the per-set counts in ``reports/tables/zone_masking.csv``.
Per-URL scores go only to ``--rows-out`` when given: the cases are live phishing URLs (with
per-victim tokens), which are not published in the repository.
"""

from __future__ import annotations

import argparse
import json
import random
import string
import subprocess
import tempfile
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "js" / "bench" / "zone_masking.mjs"
SEED = 1


def google_share_links(n: int, seed: int = SEED) -> list[dict[str, str]]:
    """Legitimate-shaped Google Drive and Docs share links with random ids."""
    rng = random.Random(seed)
    alphabet = string.ascii_letters + string.digits + "-_"

    def rid(k: int) -> str:
        return "".join(rng.choice(alphabet) for _ in range(k))

    shapes = {
        "drive_file": lambda: f"https://drive.google.com/file/d/1{rid(32)}/view?usp=sharing",
        "drive_folder": lambda: f"https://drive.google.com/drive/folders/1{rid(32)}?usp=sharing",
        "docs_document": lambda: f"https://docs.google.com/document/d/1{rid(43)}/edit?usp=sharing",
        "docs_form": lambda: f"https://docs.google.com/forms/d/e/1FAIpQL{rid(49)}/viewform",
        "docs_sheet": lambda: f"https://docs.google.com/spreadsheets/d/1{rid(43)}/edit",
    }
    return [
        {"set": f"legit_google_{k}", "url": make()} for k, make in shapes.items() for _ in range(n)
    ]


def verdict(p: float, t: dict[str, float]) -> int:
    return 2 if p >= t["dangerous"] else 1 if p >= t["suspicious"] else 0


def summarise(rows: pd.DataFrame, t: dict[str, float]) -> pd.DataFrame:
    d = rows.assign(
        plain=[verdict(p, t) for p in rows["p_plain"]],
        masked=[verdict(p, t) for p in rows["p_masked"]],
    )
    # the conservative variant: masking can add a banner (never more) when the masked score
    # reaches the dangerous threshold
    d["capped"] = d["plain"].where(d["plain"] >= 1, (d["p_masked"] >= t["dangerous"]).astype(int))
    g = d.groupby("set")
    return pd.DataFrame(
        {
            "urls": g.size(),
            "warned_plain": g["plain"].apply(lambda s: (s > 0).sum()),
            "warned_masked": g["masked"].apply(lambda s: (s > 0).sum()),
            "dangerous_plain": g["plain"].apply(lambda s: (s == 2).sum()),
            "dangerous_masked": g["masked"].apply(lambda s: (s == 2).sum()),
            "warned_capped": g["capped"].apply(lambda s: (s > 0).sum()),
        }
    ).reset_index()


def md_table(df: pd.DataFrame) -> list[str]:
    head = "| " + " | ".join(df.columns) + " |"
    rule = "|" + "---|" * len(df.columns)
    body = ("| " + " | ".join(str(v) for v in r) + " |" for r in df.itertuples(index=False))
    return [head, rule, *body]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cases", type=Path, required=True)
    ap.add_argument("--google-n", type=int, default=20)
    ap.add_argument("--reports", type=Path, default=ROOT / "reports")
    ap.add_argument("--rows-out", type=Path, default=None)
    a = ap.parse_args()

    cases = json.loads(a.cases.read_text())["urls"]
    cases = [{"set": c["set"], "url": c["url"]} for c in cases] + google_share_links(a.google_n)
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / "cases.json"
        f.write_text(json.dumps(cases))
        cmd = ["node", str(BENCH), str(f)]
        out = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=1800)
    res = json.loads(out.stdout)
    rows = pd.DataFrame(res["rows"])
    table = summarise(rows, res["thresholds"])

    (a.reports / "tables").mkdir(parents=True, exist_ok=True)
    table.to_csv(a.reports / "tables" / "zone_masking.csv", index=False)
    if a.rows_out:
        rows.to_csv(a.rows_out, index=False)
    t = res["thresholds"]
    phish = table[table["set"].str.startswith("named:")]
    legit = table[~table["set"].str.startswith(("named:", "openphish"))]

    def warned(d: pd.DataFrame) -> str:
        return ", ".join(f"{k} {d[f'warned_{k}'].sum()}" for k in ("plain", "masked", "capped"))

    lines = [
        "# Masking learned open-hosting zones in the address model",
        "",
        f"Generated by `python -m experiments.zone_masking --cases {a.cases.name}`. "
        "Address model only (no page, backend or blocklist), shipped thresholds "
        f"(suspicious {t['suspicious']:.4f}, dangerous {t['dangerous']:.4f}). "
        f"Only case URLs inside a learned zone are scored: {len(rows)} of {len(cases)}. "
        "`named:*` sets are phishing tenant URLs, the rest legitimate. "
        f"`legit_google_*` are generated share links with random ids (seed {SEED}), "
        "not observed URLs.",
        "",
        "`plain`: as shipped. `masked`: zone part of the host replaced by the platform token. "
        "`capped`: as shipped, plus a banner when the masked score reaches the dangerous "
        "threshold.",
        "",
        *md_table(table),
        "",
        f"Phishing tenant URLs warned ({phish['urls'].sum()}): {warned(phish)}. "
        f"Legitimate URLs warned ({legit['urls'].sum()}): {warned(legit)}.",
        "",
    ]
    (a.reports / "zone_masking.md").write_text("\n".join(lines))
    print("\n".join(lines))


if __name__ == "__main__":
    main()
