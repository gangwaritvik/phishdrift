"""Live feeds. Parsers are pure functions (tested with fixtures); fetchers wrap them with
the cached, rate-limited HTTP client. Each feed's ``role`` in configs/collector.yaml says
whether it supplies training data (``training``) or only blocklist entries (``blocklist``).

Every fetcher returns a frame with columns: url, source, threat, label, feed_time, target.
"""

from __future__ import annotations

import csv
import io
import logging
import os

import pandas as pd

from phishdrift.http import HttpClient

log = logging.getLogger(__name__)

FEED_COLUMNS = ["url", "source", "threat", "label", "feed_time", "target"]

URLHAUS_COLUMNS = [
    "id",
    "dateadded",
    "url",
    "url_status",
    "last_online",
    "threat",
    "tags",
    "urlhaus_link",
    "reporter",
]


def _frame(urls, source, threat, label, feed_time=None, target=None) -> pd.DataFrame:
    urls = pd.Series(list(urls), dtype=str)
    n = len(urls)
    return pd.DataFrame(
        {
            "url": urls,
            "source": source,
            "threat": threat,
            "label": pd.Series([label] * n, dtype="int8"),
            "feed_time": pd.to_datetime(
                pd.Series(feed_time if feed_time is not None else [None] * n),
                utc=True,
                errors="coerce",
            ),
            "target": pd.Series(target if target is not None else [None] * n, dtype=object),
        }
    )[FEED_COLUMNS]


def parse_openphish(text: str) -> pd.DataFrame:
    urls = [ln.strip() for ln in text.splitlines() if ln.strip().lower().startswith("http")]
    return _frame(urls, "openphish", "phishing", 1)


def parse_url_list(text: str, source: str) -> pd.DataFrame:
    """One URL per line; blank lines and ``#`` comments skipped (Phishing.Database lists)."""
    urls = [
        ln.strip()
        for ln in text.splitlines()
        if ln.strip() and not ln.lstrip().startswith("#") and "." in ln
    ]
    return _frame(urls, source, "phishing", 1)


def parse_phishtank(csv_bytes: bytes) -> pd.DataFrame:
    df = pd.read_csv(io.BytesIO(csv_bytes), dtype=str)
    df = df[df["url"].notna()]
    if "verified" in df.columns:
        df = df[df["verified"].str.lower().isin(["yes", "true", "1"])]
    return _frame(
        df["url"],
        "phishtank",
        "phishing",
        1,
        feed_time=df.get("submission_time"),
        target=df.get("target"),
    )


def parse_urlhaus(text: str) -> pd.DataFrame:
    rows = csv.reader(ln for ln in text.splitlines() if ln and not ln.startswith("#"))
    df = pd.DataFrame([r for r in rows if len(r) == len(URLHAUS_COLUMNS)], columns=URLHAUS_COLUMNS)
    return _frame(df["url"], "urlhaus", "malware", 1, feed_time=df["dateadded"])


def fetch_openphish(client: HttpClient, cfg: dict) -> pd.DataFrame:
    body = client.get(cfg["url"], cache_ttl_s=cfg["cache_ttl_s"])
    return parse_openphish(body.decode("utf-8", errors="replace"))


def fetch_phishing_database(client: HttpClient, cfg: dict) -> pd.DataFrame:
    body = client.get(cfg["url"], cache_ttl_s=cfg["cache_ttl_s"])
    return parse_url_list(body.decode("utf-8", errors="replace"), "phishing_database")


def fetch_phishtank(client: HttpClient, cfg: dict) -> pd.DataFrame | None:
    key = os.environ.get(cfg["key_env"])
    if not key:
        log.warning("phishtank: %s not set, skipping (PhishTank needs an app key)", cfg["key_env"])
        return None
    body = client.get(cfg["url_with_key"].format(key=key), cache_ttl_s=cfg["cache_ttl_s"])
    return parse_phishtank(body)


def fetch_urlhaus(client: HttpClient, cfg: dict) -> pd.DataFrame:
    key = os.environ.get(cfg["auth_key_env"])
    headers = {"Auth-Key": key} if key else None
    if not key:
        log.info("urlhaus: %s not set, trying without Auth-Key", cfg["auth_key_env"])
    body = client.get(cfg["url"], cache_ttl_s=cfg["cache_ttl_s"], headers=headers)
    return parse_urlhaus(body.decode("utf-8", errors="replace"))


FETCHERS = {
    "openphish": fetch_openphish,
    "phishing_database": fetch_phishing_database,
    "phishtank": fetch_phishtank,
    "urlhaus": fetch_urlhaus,
}
