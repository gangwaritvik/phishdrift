"""How the Gemini brand check behaves: false alarms on legitimate hosts, rescue of phishing the
address model passes, and look-alikes made from the legitimate hosts.

``GEMINI_API_KEY=... python -m experiments.llm_eval --ood data/raw/ood/ood_urls.csv \\
    --phishing phishing-links-ACTIVE.txt [--max-calls 400]``

No address is typed here: legitimate hosts are the natural pages of the OOD set, phishing hosts are
a seeded sample of a feed file, and look-alikes come from ``attacks`` (homoglyph, brand injection,
TLD swap) applied to the legitimate URLs. The address layer is ``js/bench/verdicts.mjs``. Every
provider answer is cached in ``--cache`` (jsonl), so a stopped or quota-limited run resumes and a
new confidence cutoff needs no new calls. Writes ``reports/llm_eval.md`` and
``reports/tables/llm_eval.csv``.
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

from attacks.transforms import apply_family
from backend.llm import GeminiProvider, build_prompt, judge, parse
from features.lists import load_lists
from phishdrift.config import load_config

FAMILIES = ("homoglyph", "tld")  # "brand" only changes the path, and only hosts are sent
CUTOFFS = (0.5, 0.7, 0.8, 0.9)
SEED = 0


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def build_sets(
    ood_urls: list[str], phishing_urls: list[str], n_phishing: int, n_lookalike: int = 150
) -> pd.DataFrame:
    lists = load_lists()
    legit = sorted(set(ood_urls))
    rows = [("legit", u, u) for u in legit]
    for fam in FAMILIES:
        made = [(apply_family(fam, u, lists, SEED), u) for u in legit]
        made = [(v, u) for v, u in made if v and host_of(v) != host_of(u)]
        rows += [
            (f"lookalike_{fam}", v, u)
            for v, u in random.Random(SEED).sample(made, min(n_lookalike, len(made)))
        ]
    sample = random.Random(SEED).sample(
        sorted(set(phishing_urls)), min(n_phishing, len(phishing_urls))
    )
    rows += [("phishing", u, u) for u in sample]
    d = pd.DataFrame(rows, columns=["set", "url", "origin"])
    d["host"] = d["url"].map(host_of)
    return d[d["host"].str.contains(".", regex=False)].drop_duplicates(["set", "host"])


def ask_all(hosts: list[str], provider, cache_path: Path, max_calls: int) -> dict[str, dict]:
    cache: dict[str, dict] = {}
    if cache_path.exists():
        for line in cache_path.read_text(encoding="utf-8").splitlines():
            rec = json.loads(line)
            cache[rec["host"]] = rec
    todo = [h for h in hosts if h not in cache][:max_calls]
    with cache_path.open("a", encoding="utf-8") as fh:
        for h in todo:
            try:
                text = provider(build_prompt(h, []))
                rec = {"host": h, "answer": parse(text), "error": None}
            except Exception as exc:  # noqa: BLE001 - a quota or network error ends this host only
                rec = {
                    "host": h,
                    "answer": None,
                    "error": f"{type(exc).__name__}: {str(exc)[:120]}",
                }
            cache[h] = rec
            fh.write(json.dumps(rec) + "\n")
            fh.flush()
            if rec["error"] and "429" in rec["error"]:
                break  # quota: stop, the cache keeps what was asked
    return cache


def raised(
    rec: dict | None, host: str, cutoff: float, phishing_min: float | None = None
) -> bool | None:
    """None = not asked or the provider failed (no opinion)."""
    if rec is None or rec["error"]:
        return None
    return judge(host, rec["answer"], cutoff, phishing_min)["raise"]


def summarise(d: pd.DataFrame, cache: dict) -> pd.DataFrame:
    rows = []
    for (name, _passes), grp in d.groupby(["set", "address_passes"]):
        asked = [(h, cache.get(h)) for h in grp["host"]]
        answered = [(h, r) for h, r in asked if r and not r["error"]]
        row = {"set": name, "address_passes": grp["address_passes"].iloc[0], "hosts": len(grp),
               "answered": len(answered), "failed": sum(1 for _, r in asked if r and r["error"]),
               "not_asked": sum(1 for _, r in asked if r is None)}  # fmt: skip
        for c in CUTOFFS:
            hit = sum(bool(raised(r, h, c)) for h, r in answered)
            row[f"raised@{c}"] = hit
            row[f"rate@{c}"] = round(hit / len(answered), 4) if answered else None
        for c in CUTOFFS:  # brand claim or phishing probability, both at the same cutoff
            hit = sum(bool(raised(r, h, c, c)) for h, r in answered)
            row[f"any@{c}"] = round(hit / len(answered), 4) if answered else None
        rows.append(row)
    return pd.DataFrame(rows)


def address_layer(urls: list[str]) -> dict[str, str]:
    from experiments.shipped_verdicts import run_node

    out = run_node(urls)
    return dict(zip(out["url"], out["shipped"], strict=True))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ood", required=True)
    ap.add_argument("--phishing", required=True, help="feed file, one URL per line")
    ap.add_argument("--n-phishing", type=int, default=300)
    ap.add_argument("--max-calls", type=int, default=400)
    ap.add_argument("--cache", default="data/interim/llm_eval_cache.jsonl")
    ap.add_argument("--out", default="reports")
    a = ap.parse_args(argv)

    ood = pd.read_csv(a.ood)
    ood = ood[ood["ok"].astype(str).str.lower() == "true"]
    phish = [u.strip() for u in Path(a.phishing).read_text(encoding="utf-8").splitlines()]
    d = build_sets(ood["url"].tolist(), [u for u in phish if u.startswith("http")], a.n_phishing)
    verdict = address_layer(d["url"].tolist())
    d["address_passes"] = d["url"].map(lambda u: verdict[u] == "safe")

    cfg = load_config("backend")["llm"]
    provider = GeminiProvider(cfg)
    if not provider.available:
        raise SystemExit(f"{cfg['api_key_env']} is not set: nothing was asked")
    Path(a.cache).parent.mkdir(parents=True, exist_ok=True)
    # Ask the sets in order of importance so a quota stop keeps the most useful answers.
    order = {
        "legit": 0,
        "phishing": 1,
        "lookalike_homoglyph": 2,
        "lookalike_brand": 3,
        "lookalike_tld": 4,
    }
    hosts = d.sort_values("set", key=lambda s: s.map(order))["host"].drop_duplicates().tolist()
    cache = ask_all(hosts, provider, Path(a.cache), a.max_calls)

    table = summarise(d, cache)
    out = Path(a.out)
    (out / "tables").mkdir(parents=True, exist_ok=True)
    table.to_csv(out / "tables" / "llm_eval.csv", index=False)
    note = (
        "# Gemini brand check\n\nRaise rate by set and cutoff. `raised@`/`rate@` = confident brand "
        "claim on a host that is not the brand's own; `any@` = that or a phishing probability "
        "at or above the same cutoff (the shipped check uses both). `address_passes` = the address model and "
        "allowlist say safe. `legit` rows are false alarms; `phishing` and `lookalike_*` rows are "
        "catches.\n\n"
    )
    head = "| " + " | ".join(table.columns) + " |\n|" + "---|" * len(table.columns) + "\n"
    body = "".join("| " + " | ".join(map(str, r)) + " |\n" for r in table.itertuples(index=False))
    tail = (
        f"\nModel: {cfg['model']}. Answers cached: {len(cache)}. "
        f"Not asked: {int(table['not_asked'].sum())} (call limit or quota).\n"
    )
    (out / "llm_eval.md").write_text(note + head + body + tail, encoding="utf-8")
    print(table.to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
