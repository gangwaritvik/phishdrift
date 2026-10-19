"""Remote config the extension fetches from ``GET /config`` (no extension release needed).

The file (``configs/remote_config.yaml`` by default) is validated as a whole when the app starts;
any problem raises one ValueError listing every problem, so a bad file is never served, not even
in part. The served body is canonical JSON (sorted keys, no spaces) plus ``sha256``: the hex digest
of the canonical JSON of the same document without ``sha256``, so a client can check integrity by
dropping that field, re-serialising canonically and hashing.

Keys: ``version`` (int >= 1), ``thresholds`` (``address`` and ``page``, each ``suspicious`` and
``dangerous``: a float inside the configured bounds, or null for the model's bundled threshold),
``never_warn`` (registrable domains, never a hosting platform), ``list_sync_minutes`` and
``notes`` (ASCII text, so every JSON serialiser produces the same bytes).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

from phishdrift.domains import split_host

MODELS = ("address", "page")
LEVELS = ("suspicious", "dangerous")
KEYS = {"version", "thresholds", "never_warn", "list_sync_minutes", "notes"}
DEFAULT_SYNC_MINUTES = 60


def canonical(doc: dict) -> str:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def validate(raw: Any, cfg: dict, platforms: Iterable[str]) -> dict:
    """The normalised config, or ValueError naming every problem. ``cfg`` is ``remote_config``
    from ``configs/backend.yaml``."""
    from backend.app import clean_domain  # local import: backend.app imports this module

    if not isinstance(raw, dict):
        raise ValueError("remote config: the document must be a mapping")
    problems: list[str] = []
    lo, hi = float(cfg["bounds"]["min"]), float(cfg["bounds"]["max"])
    sync_lo, sync_hi = cfg["list_sync_minutes"]["min"], cfg["list_sync_minutes"]["max"]
    platform_set = frozenset(platforms)

    for key in sorted(set(raw) - KEYS):
        problems.append(f"unknown key {key!r}")

    version = raw.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        problems.append("version must be an integer >= 1")

    thresholds: dict[str, dict[str, float | None]] = {}
    raw_thr = raw.get("thresholds")
    if not isinstance(raw_thr, dict):
        problems.append("thresholds must be a mapping with keys address and page")
        raw_thr = {}
    for key in sorted(set(raw_thr) - set(MODELS)):
        problems.append(f"thresholds: unknown model {key!r}")
    for model in MODELS:
        block = raw_thr.get(model)
        if not isinstance(block, dict):
            if raw_thr:
                problems.append(f"thresholds.{model} must be a mapping with suspicious, dangerous")
            continue
        for key in sorted(set(block) - set(LEVELS)):
            problems.append(f"thresholds.{model}: unknown key {key!r}")
        values: dict[str, float | None] = {}
        for level in LEVELS:
            value = block.get(level)
            where = f"thresholds.{model}.{level}"
            if level not in block:
                problems.append(f"{where} is missing (use null for the bundled threshold)")
            elif value is None:
                values[level] = None
            elif not _is_number(value):
                problems.append(f"{where} must be a number or null")
            elif not lo <= float(value) <= hi:
                problems.append(f"{where} = {value} is outside [{lo}, {hi}]")
            else:
                values[level] = float(value)
        sus, dan = values.get("suspicious"), values.get("dangerous")
        if sus is not None and dan is not None and not sus < dan:
            problems.append(
                f"thresholds.{model}: suspicious ({sus}) must be below dangerous ({dan})"
            )
        thresholds[model] = {level: values.get(level) for level in LEVELS}

    never_warn: list[str] = []
    raw_nw = raw.get("never_warn", [])
    if raw_nw is None:
        raw_nw = []
    if not isinstance(raw_nw, list):
        problems.append("never_warn must be a list of registrable domains")
        raw_nw = []
    if len(raw_nw) > cfg["max_never_warn"]:
        problems.append(f"never_warn has {len(raw_nw)} entries; at most {cfg['max_never_warn']}")
    seen: set[str] = set()
    for item in raw_nw:
        where = f"never_warn entry {item!r}"
        if not isinstance(item, str):
            problems.append(f"{where} must be a string")
            continue
        try:
            domain = clean_domain(item.strip())
        except ValueError:
            problems.append(f"{where} is not a bare hostname")
            continue
        sub, label, suffix = split_host(domain)
        if not suffix or sub or f"{label}.{suffix}" != domain:
            problems.append(f"{where} is not a registrable domain (no subdomains, known suffix)")
        elif domain in platform_set:
            problems.append(
                f"{where} is a shared host (hosting platform, open-hosting zone or shortener)"
            )
        elif domain in seen:
            problems.append(f"{where} is listed twice")
        else:
            seen.add(domain)
            never_warn.append(domain)

    sync = raw.get("list_sync_minutes", DEFAULT_SYNC_MINUTES)
    if not isinstance(sync, int) or isinstance(sync, bool) or not sync_lo <= sync <= sync_hi:
        problems.append(f"list_sync_minutes must be an integer in [{sync_lo}, {sync_hi}]")

    notes = raw.get("notes", "")
    if notes is None:
        notes = ""
    if not isinstance(notes, str) or not notes.isascii():
        problems.append("notes must be ASCII text")

    if problems:
        raise ValueError("invalid remote config:\n- " + "\n- ".join(problems))
    return {
        "version": version,
        "thresholds": thresholds,
        "never_warn": sorted(never_warn),
        "list_sync_minutes": sync,
        "notes": notes,
    }


def served(doc: dict) -> bytes:
    """Canonical JSON of ``doc`` plus its ``sha256``, as served by ``GET /config``."""
    digest = hashlib.sha256(canonical(doc).encode("utf-8")).hexdigest()
    return canonical({**doc, "sha256": digest}).encode("utf-8")


def load(path: Path, cfg: dict, platforms: Iterable[str]) -> bytes:
    """Read, validate and serialise the remote config file. Raises ValueError if invalid."""
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"remote config {path} cannot be read: {exc}") from exc
    return served(validate(raw, cfg, platforms))
