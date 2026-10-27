"""Fresh phishing feeds for tier C capture.

Tier C needs domains captured within hours of their listing, so this module polls several
feeds more often than the 12 h training collector and hands the new domains to
``domain_capture.capture``. It is separate from the training index (``store.update_index``):
nothing here becomes tier A/B training data.

First-seen time of a domain:
- feeds that carry their own time (PhishTank ``submission_time``, PhishStats ``date``): that time,
  and only entries newer than ``backlog_hours`` count as fresh;
- feeds without one: the poll time. Lists that hold weeks of entries (``baseline: true``) are
  read once without emitting anything, so only domains added after that first poll are new.

State (``state_dir``): ``polls.json`` (last poll per feed) and ``seen_<feed>.txt`` (append-only
domains already seen in a baseline feed). Both live on the data branch.
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import requests

from collector import feeds
from phishdrift.domains import registered_domain
from phishdrift.http import HttpClient

log = logging.getLogger(__name__)


def parse_domain_list(text: str) -> list[str]:
    """One host per line; ``#`` comments and blank lines skipped."""
    return [
        ln.strip().lower()
        for ln in text.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#") and " " not in ln.strip()
    ]


def parse_phishstats(body: bytes) -> list[tuple[str, pd.Timestamp]]:
    """(url, time) from the PhishStats JSON API (``date`` is the listing time)."""
    out = []
    for row in json.loads(body):
        t = pd.to_datetime(row.get("date"), utc=True, errors="coerce")
        if row.get("url") and not pd.isna(t):
            out.append((str(row["url"]), t))
    return out


def _target(url: str, first_seen: pd.Timestamp, source: str) -> dict:
    return {"url": url, "label": 1, "first_seen": first_seen, "source": source}


def _read_seen(path: Path) -> set[str]:
    return set(path.read_text(encoding="utf-8").split()) if path.exists() else set()


def _append_seen(path: Path, domains: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write("".join(d + "\n" for d in domains))


def _fresh(times: list[pd.Timestamp], now: datetime, hours: float) -> list[bool]:
    cut = pd.Timestamp(now) - timedelta(hours=hours)
    return [t >= cut for t in times]


def _get_plain(url: str, user_agent: str, timeout_s: float, attempts: int = 3) -> bytes:
    error: Exception | None = None
    for i in range(attempts):
        try:
            resp = requests.get(url, timeout=timeout_s, headers={"User-Agent": user_agent})
            resp.raise_for_status()
            return resp.content
        except requests.RequestException as exc:
            error = exc
            time.sleep(2 * (i + 1))
    raise RuntimeError(f"{url}: {error}")


def fetch_feed(
    client: HttpClient, name: str, fcfg: dict, now: datetime, hours: float
) -> list[tuple[str, pd.Timestamp | None]]:
    """(url, listing time or None) of the entries a feed currently lists. Entries with a time
    older than ``hours`` are dropped here."""
    kind, url = fcfg["kind"], fcfg["url"]
    timeout = fcfg.get("timeout_s")
    if kind == "phishstats_api":
        out: list[tuple[str, pd.Timestamp]] = []
        for page in range(int(fcfg.get("pages", 10))):
            # plain requests, not the client's streamed download: this API cuts its replies short
            body = _get_plain(
                f"{url}?_sort=-date&_size={int(fcfg.get('page_size', 100))}&_p={page}",
                client.user_agent,
                timeout or 60,
            )
            rows = parse_phishstats(body)
            if not rows:
                break
            out += [
                r
                for r, ok in zip(rows, _fresh([t for _, t in rows], now, hours), strict=True)
                if ok
            ]
            if min(t for _, t in rows) < pd.Timestamp(now) - timedelta(hours=hours):
                break
        return out  # type: ignore[return-value]
    body = client.get(url, timeout_s=timeout)
    if kind == "phishtank_csv":
        df = feeds.parse_phishtank(body)
        times = list(pd.to_datetime(df["feed_time"], utc=True, errors="coerce"))
        keep = [(u, t) for u, t in zip(df["url"], times, strict=True) if not pd.isna(t)]
        flags = _fresh([t for _, t in keep], now, hours)
        return [k for k, ok in zip(keep, flags, strict=True) if ok]
    text = body.decode("utf-8", errors="replace")
    if kind == "domain_list":
        return [(f"https://{d}/", None) for d in parse_domain_list(text)]
    if kind == "url_list":
        df = feeds.parse_url_list(text, name)
        return [(u, None) for u in df["url"]]
    raise ValueError(f"unknown capture feed kind {kind!r} for {name}")


def poll(client: HttpClient, cfg: dict, now: datetime) -> tuple[list[dict], dict[str, int]]:
    """New capture targets from every feed that is due, newest listing first, and the number
    of new targets per feed. A failing feed is logged and skipped."""
    state_dir = Path(cfg["state_dir"])
    polls_path = state_dir / "polls.json"
    polls = json.loads(polls_path.read_text()) if polls_path.exists() else {}
    hours = cfg["backlog_hours"]
    targets: list[dict] = []
    counts: dict[str, int] = {}
    for name, fcfg in cfg["feeds"].items():
        if not fcfg.get("enabled", True):
            continue
        last = pd.to_datetime(polls.get(name), utc=True) if polls.get(name) else None
        due = last is None or pd.Timestamp(now) - last >= timedelta(hours=fcfg["min_interval_h"])
        if not due:
            continue
        try:
            rows = fetch_feed(client, name, fcfg, now, hours)
        except Exception as exc:  # noqa: BLE001 - one bad feed must not stop the others
            log.error("capture feed %s: failed: %s", name, exc)
            continue
        polls[name] = pd.Timestamp(now).isoformat()
        stamp = pd.Timestamp(now)
        if fcfg.get("baseline"):
            seen_path = state_dir / f"seen_{name}.txt"
            first = not seen_path.exists()
            seen = _read_seen(seen_path)
            doms = list(dict.fromkeys(d for u, _ in rows if (d := registered_domain(u))))
            new = [d for d in doms if d not in seen]
            _append_seen(seen_path, new)
            rows = [] if first else [(f"https://{d}/", None) for d in new]
            log.info(
                "capture feed %s: %d domains listed, %d new%s",
                name,
                len(doms),
                len(new),
                " (baseline, none emitted)" if first else "",
            )
        targets += [_target(u, t if t is not None else stamp, name) for u, t in rows]
        counts[name] = len(rows)
        log.info("capture feed %s: %d targets", name, len(rows))
    polls_path.parent.mkdir(parents=True, exist_ok=True)
    polls_path.write_text(json.dumps(polls, indent=1), encoding="utf-8")
    targets.sort(key=lambda t: t["first_seen"], reverse=True)
    return targets, counts
