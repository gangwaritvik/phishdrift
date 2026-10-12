"""Tier C feature table from the first-seen captures (``collector/domain_capture.py``).

python -m features build --tier C [--info-dir DIR] [--out FILE]

Reads every ``*.jsonl`` in the capture directory (default ``paths.domain_info_dir`` of
``configs/collector.yaml``), joins each host record to its registrable domain's record (the
latest one with RDAP data, else the latest) and writes one row per host: bookkeeping columns
(host, domain, label, first_seen, captured_at, is_hosting_platform, is_ip, resolves, filtered)
plus every ``NAMES_C`` feature as float32. Bookkeeping columns are never model features; the
experiment uses them to filter rows. A line cut off by a stopped collector run is skipped.

A host can have several host records: one whose DNS answer came from the collector PC's
filtering resolver (sinkhole addresses) is captured again on a later run. The latest record per
host is used; if it is still filtered, ``filtered`` is True, ``resolves`` is False and its DNS
and TLS features are NaN.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pandas as pd

from features.domain_features import compute_c, host_flags, pick_domain_record
from features.lists import Lists, load_lists
from features.registry import NAMES_C
from phishdrift.config import load_config, resolve

log = logging.getLogger(__name__)
META = (
    "host",
    "domain",
    "label",
    "first_seen",
    "captured_at",
    "is_hosting_platform",
    "is_ip",
    "resolves",
    "filtered",
)


def default_paths() -> tuple[Path, Path]:
    info_dir = resolve(load_config("collector")["paths"]["domain_info_dir"])
    processed = resolve(load_config("datasets")["paths"]["processed_dir"])
    return info_dir, processed / "features_c.parquet"


def read_records(info_dir: Path) -> tuple[list[dict], dict[str, list[dict]]]:
    """(host records, domain records by domain) from every JSONL file in ``info_dir``."""
    hosts: list[dict] = []
    domains: dict[str, list[dict]] = {}
    for path in sorted(Path(info_dir).glob("*.jsonl")):
        for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except ValueError:  # cut off by a stopped run
                log.warning("%s line %d: unreadable, skipped", path.name, i)
                continue
            if rec.get("kind") == "host" and rec.get("host"):
                hosts.append(rec)
            elif rec.get("kind") == "domain" and rec.get("domain"):
                domains.setdefault(str(rec["domain"]).lower(), []).append(rec)
    return hosts, domains


def feature_table(hosts: list[dict], domains: dict[str, list[dict]], lists: Lists) -> pd.DataFrame:
    """One row per host, from its latest host record."""
    latest: dict[str, dict] = {}
    for rec in sorted(hosts, key=lambda r: str(r.get("captured_at") or "")):
        latest[str(rec["host"]).lower()] = rec
    picked = {d: pick_domain_record(recs) for d, recs in domains.items()}
    rows = []
    for host, rec in latest.items():
        domain = str(rec.get("domain") or "").lower()
        rows.append(
            {
                "host": host,
                "domain": domain,
                "label": rec.get("label"),
                "first_seen": rec.get("first_seen"),
                "captured_at": rec.get("captured_at"),
                **host_flags(rec, lists),
                **compute_c(rec, picked.get(domain), lists),
            }
        )
    df = pd.DataFrame(rows, columns=list(META) + list(NAMES_C))
    df["label"] = pd.to_numeric(df["label"], errors="coerce").astype("Int64")
    for col in ("first_seen", "captured_at"):
        df[col] = pd.to_datetime(df[col], utc=True, errors="coerce", format="mixed")
    for col in ("is_hosting_platform", "is_ip", "filtered"):
        df[col] = df[col].astype(bool)
    df["resolves"] = df["resolves"].astype("boolean")
    df[list(NAMES_C)] = df[list(NAMES_C)].astype("float32")
    return df


def counts_by_label(df: pd.DataFrame) -> pd.DataFrame:
    """Hosts, registrable domains, platform hosts, IP hosts, hosts filtered by the PC's resolver
    and non-resolving hosts per label. Non-resolving = not filtered, not an IP host, and
    ``resolves`` is not True; the counts overlap only through ``platform_hosts``."""
    dead = ~df["resolves"].fillna(False).astype(bool) & ~df["filtered"] & ~df["is_ip"]
    df = df.assign(_dead=dead)
    g = df.groupby(df["label"].astype("string").fillna("missing"), dropna=False)
    return pd.DataFrame(
        {
            "hosts": g.size(),
            "domains": g["domain"].nunique(),
            "platform_hosts": g["is_hosting_platform"].sum(),
            "ip_hosts": g["is_ip"].sum(),
            "filtered_by_pc_resolver": g["filtered"].sum(),
            "non_resolving_hosts": g["_dead"].sum(),
        }
    ).astype(int)


def build_c(info_dir: Path | None = None, out: Path | None = None) -> tuple[Path, pd.DataFrame]:
    default_info, default_out = default_paths()
    info_dir, out = Path(info_dir or default_info), Path(out or default_out)
    hosts, domains = read_records(info_dir)
    df = feature_table(hosts, domains, load_lists())
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".tmp.parquet")
    df.to_parquet(tmp, index=False)
    tmp.replace(out)
    log.info("%d hosts from %s -> %s", len(df), info_dir, out)
    return out, counts_by_label(df)
