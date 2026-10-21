# ruff: noqa: E501
"""Second condition for Q2, Q4 and the interaction check: populations built without the cleaning.

Declared in advance in ``docs/PHISHGUARD_SENSITIVITY_PLAN.md`` (commit 729ccec). Populations come from
the per-source interim files: no per-domain cap, no removal of domains shared by phishing sources, no
depth balancing. Only exact duplicates inside a population and URLs labelled both ways are removed, and
each population is sampled to at most ``cap_per_class`` URLs. Everything else (features, models, splits,
bootstrap, "holds" rule, cut-offs) is the frozen study's.

    python -m phishguard.sensitivity all --interim data/interim --out data/interim/phishguard_uncleaned
"""

from __future__ import annotations

import argparse
import os
from multiprocessing import Pool
from pathlib import Path

os.environ.setdefault("PHISHDRIFT_THREADS", "1")

import pandas as pd
import yaml

from features.lists import Lists, load_lists
from phishdrift.domains import url_depth, url_key
from phishguard import analyze, data, run
from phishguard.masking import _md, load_source

QUESTIONS = ("F1", "F2", "F3", "F4", "H5")
LABEL = {"F1": "Q1", "F2": "Q2", "F3": "Q3", "F4": "Q4", "H5": "interaction"}
BENIGN_SOURCES = (
    "phreshphish",
    "phiusiil",
    "urlphish",
    "phishstorm",
)  # the crawl cannot be rebuilt


def condition_cfg(cfg: dict) -> dict:
    """The frozen config with only what the declared condition changes or skips."""
    c = dict(cfg)
    c["benign"] = [b for b in cfg["benign"] if b in BENIGN_SOURCES]
    c.update(phishing_b=[], benign_b=[], transfer_models=[], control_models=[], masking_models=[])
    return c


def build_populations(frames: dict[str, pd.DataFrame], cfg: dict) -> pd.DataFrame:
    """One population per source and class, sampled but never capped per domain or depth-balanced."""
    allrows = pd.concat(frames.values(), ignore_index=True)
    allrows["_key"] = allrows["url"].map(url_key)
    both = allrows.groupby("_key")["label"].nunique()
    conflicting = set(both.index[both > 1])
    out = []
    for name, df in frames.items():
        df = df.assign(_key=df["url"].map(url_key))
        df = df[~df["_key"].isin(conflicting)]
        for label in (0, 1):
            sub = df[df["label"] == label].drop_duplicates("_key")
            wanted = (name in cfg["phishing"]) if label == 1 else (name in cfg["benign"])
            if not wanted or sub.empty:
                continue
            sub = sub.sample(n=min(len(sub), cfg["cap_per_class"]), random_state=cfg["seed"])
            pop = f"{'phish' if label else 'benign'}:{name}"
            out.append(sub.assign(pop=pop, part="A", uid=[f"{pop}_{i}" for i in range(len(sub))]))
    pops = pd.concat(out, ignore_index=True)
    pops["depth"] = [url_depth(u) for u in pops["url"]]
    return pops[["uid", "url", "domain", "label", "depth", "pop", "part", "_key"]]


def prepare(interim: Path, out: Path, cfg: dict, lists: Lists, workers: int) -> pd.DataFrame:
    names = sorted((set(cfg["phishing"]) | set(cfg["benign"])) - {"crawl"})
    frames = {}
    for n in names:
        try:
            frames[n] = load_source(interim, n)
        except (FileNotFoundError, OSError, KeyError) as e:
            print(f"skip source {n}: {e}", flush=True)
    pops = build_populations(frames, cfg)
    counts = (
        pops.groupby("pop").agg(urls=("uid", "size"), domains=("domain", "nunique")).reset_index()
    )
    print(counts.to_string(index=False), flush=True)
    data.write_features(pops, out, lists, workers)
    return counts


def run_cells(out: Path, cfg: dict, lists: Lists, workers: int) -> int:
    todo = [
        j
        for j in run.jobs(out, cfg)
        if j[0] == "A"
        and j[1][0].split(":")[1] in cfg["phishing"]
        and j[1][1].split(":")[1] in cfg["benign"]
    ]
    failed = 0
    with Pool(
        workers, initializer=run._init, initargs=(str(out), cfg, lists), maxtasksperchild=40
    ) as pool:
        for i, msg in enumerate(pool.imap_unordered(run._run, todo), 1):
            failed += msg.startswith("FAILED")
            print(f"[{i}/{len(todo)}] {msg}", flush=True)
    return failed


def verdict_table(results: list[dict], cfg: dict) -> tuple[pd.DataFrame, dict]:
    analyze.CFG.update(cfg)
    tables, _ = analyze.findings_a(results, cfg)
    s = analyze.summary(tables).set_index("finding")
    return s.loc[list(QUESTIONS)], tables


def analyse(out: Path, frozen: Path, cfg: dict, reports: Path) -> Path:
    cfg_b = condition_cfg(cfg)
    res_b = analyze.load(out, "A")
    cells_b = {r["cell"] for r in res_b}
    res_a = [r for r in analyze.load(frozen, "A") if r["cell"] in cells_b]
    va, ta = verdict_table(res_a, cfg)
    vb, tb = verdict_table(res_b, cfg_b)
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "tables").mkdir(exist_ok=True)
    rows = []
    for q in QUESTIONS:
        rows.append(
            {
                "question": LABEL[q],
                "cleaned: settings": int(va.loc[q, "settings"]),
                "cleaned: hold": int(va.loc[q, "hold"]),
                "cleaned: share": va.loc[q, "share"],
                "cleaned: verdict": va.loc[q, "verdict"],
                "uncleaned: settings": int(vb.loc[q, "settings"]),
                "uncleaned: hold": int(vb.loc[q, "hold"]),
                "uncleaned: share": vb.loc[q, "share"],
                "uncleaned: verdict": vb.loc[q, "verdict"],
            }
        )
    side = pd.DataFrame(rows)
    side.to_csv(reports / "tables" / "sensitivity_verdicts.csv", index=False)
    lad = {}
    for tag, t in (("cleaned", ta), ("uncleaned", tb)):
        r = t["runs"]
        lad[tag] = (
            r[r["rep"].isin(["R1", "R2", "R4"])]
            .pivot_table(index="cell", columns="rep", values="roc_auc")
            .add_prefix(f"{tag} ")
        )
    ladder = pd.concat(lad.values(), axis=1).reset_index().round(3)
    ladder.to_csv(reports / "tables" / "sensitivity_ladder.csv", index=False)
    share = {
        tag: float(t["F2"]["median"].median()) if len(t["F2"]) else float("nan")
        for tag, t in (("cleaned", ta), ("uncleaned", tb))
    }
    sd = {
        tag: (float(t["F4"]["sd_R4"].median()), float(t["F4"]["sd_R1"].median()))
        for tag, t in (("cleaned", ta), ("uncleaned", tb))
        if len(t["F4"])
    }
    md = [
        "# Uncleaned-data condition for Q2, Q4 and the interaction check",
        "",
        "Declared in `docs/PHISHGUARD_SENSITIVITY_PLAN.md` before the run. Same cells, models, splits and cut-offs in both columns; "
        "the only difference is whether the populations were cleaned (per-domain cap, shared-domain removal, depth balancing).",
        f"Cells compared: {len(cells_b)} ({', '.join(sorted(cells_b))}).",
        "",
        _md(side),
        f"Median host-and-subdomain share of the R1 to R4 drop: cleaned {share['cleaned']:.2f}, uncleaned {share['uncleaned']:.2f}.",
        "Median SD across splits (R4 / R1): "
        + "; ".join(f"{k} {v[0]:.3f} / {v[1]:.3f}" for k, v in sd.items())
        + ".",
        "",
        "## Representation ladder, median ROC-AUC per cell",
        "",
        _md(ladder),
    ]
    path = reports / "sensitivity_uncleaned.md"
    path.write_text("\n".join(md) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="phishguard.sensitivity")
    ap.add_argument("step", choices=["prepare", "run", "analyze", "all"])
    ap.add_argument("--interim", type=Path, default=Path("data/interim"))
    ap.add_argument("--out", type=Path, default=Path("data/interim/phishguard_uncleaned"))
    ap.add_argument("--frozen", type=Path, default=Path("data/interim/phishguard"))
    ap.add_argument("--reports", type=Path, default=Path("reports/phishguard"))
    ap.add_argument("--config", type=Path, default=Path("configs/phishguard.yaml"))
    ap.add_argument("--workers", type=int, default=3)
    a = ap.parse_args(argv)
    cfg = yaml.safe_load(a.config.read_text(encoding="utf-8"))
    cfg_b = condition_cfg(cfg)
    lists = load_lists()
    if a.step in ("prepare", "all"):
        prepare(a.interim, a.out, cfg_b, lists, a.workers)
    if a.step in ("run", "all") and run_cells(a.out, cfg_b, lists, a.workers):
        print("some jobs failed; rerun the same command to retry them", flush=True)
        return 1
    if a.step in ("analyze", "all"):
        print(analyse(a.out, a.frozen, cfg, a.reports), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
