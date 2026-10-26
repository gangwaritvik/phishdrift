"""HTTP client for feeds and crawling: timeouts, retries with backoff, an on-disk cache
and a per-host minimum interval between requests."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)


def _atomic_write(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` so a reader (or a run stopped half-way) never sees a partial
    file. The temporary name is unique per process and thread."""
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    tmp.write_bytes(data)
    os.replace(tmp, path)


@dataclass
class HttpClient:
    cache_dir: Path
    timeout_s: float = 20
    retries: int = 3
    backoff_factor: float = 2.0
    user_agent: str = "PhishDrift-research-collector/0.1"
    default_min_interval_s: float = 1.0
    max_download_s: float | None = None  # wall-clock cap for one response body
    connect_timeout_s: float | None = None  # shorter wait for the connection itself
    _last_request: dict[str, float] = field(default_factory=dict, init=False)
    _session: requests.Session = field(init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def __post_init__(self) -> None:
        self.cache_dir = Path(self.cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        retry = Retry(
            total=self.retries,
            backoff_factor=self.backoff_factor,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "HEAD"),
            respect_retry_after_header=True,
        )
        self._session = requests.Session()
        self._session.headers["User-Agent"] = self.user_agent
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    @classmethod
    def from_config(cls, http_cfg: dict, cache_dir: Path) -> HttpClient:
        return cls(
            cache_dir=cache_dir,
            timeout_s=http_cfg["timeout_s"],
            retries=http_cfg["retries"],
            backoff_factor=http_cfg["backoff_factor"],
            user_agent=http_cfg["user_agent"],
            default_min_interval_s=http_cfg["default_min_interval_s"],
            max_download_s=http_cfg.get("max_download_s"),
            connect_timeout_s=http_cfg.get("connect_timeout_s"),
        )

    def _cache_paths(self, url: str) -> tuple[Path, Path]:
        key = hashlib.sha256(url.encode()).hexdigest()
        return self.cache_dir / f"{key}.body", self.cache_dir / f"{key}.json"

    def _wait_for_host(self, url: str, min_interval_s: float) -> None:
        """Reserve the next request slot for this host (thread-safe), then sleep until it."""
        host = urlsplit(url).hostname or ""
        with self._lock:
            now = time.monotonic()
            last = self._last_request.get(host)
            slot = now if last is None else max(now, last + min_interval_s)
            self._last_request[host] = slot
        if slot > now:
            time.sleep(slot - now)

    def _timeout(self, timeout_s: float | None) -> float | tuple[float, float]:
        read = timeout_s or self.timeout_s
        return (self.connect_timeout_s, read) if self.connect_timeout_s else read

    def get(
        self,
        url: str,
        *,
        cache_ttl_s: float = 0,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
        min_interval_s: float | None = None,
        timeout_s: float | None = None,
    ) -> bytes:
        """GET ``url``. Serves from disk cache when younger than ``cache_ttl_s``.

        The cache key is the URL only, so pass secrets in ``headers`` rather than the URL
        when possible. ``min_interval_s`` overrides the per-host politeness delay (e.g. a
        site's robots.txt Crawl-delay). Raises ``requests.HTTPError`` on a non-2xx final
        response. ``timeout_s`` overrides the client's read timeout for slow endpoints.
        """
        body_path, meta_path = self._cache_paths(url)
        if cache_ttl_s > 0:
            cached = self._read_cache(body_path, meta_path, cache_ttl_s)
            if cached is not None:
                log.debug("cache hit %s", url)
                return cached

        interval = self.default_min_interval_s
        if min_interval_s is not None:
            interval = max(interval, min_interval_s)
        self._wait_for_host(url, interval)
        with self._session.get(
            url, timeout=self._timeout(timeout_s), headers=headers, stream=True
        ) as resp:
            resp.raise_for_status()
            chunks, size = [], 0
            started = time.monotonic()
            for chunk in resp.iter_content(64 * 1024):
                if self.max_download_s and time.monotonic() - started > self.max_download_s:
                    raise requests.Timeout(f"download of {url} exceeded {self.max_download_s}s")
                chunks.append(chunk)
                size += len(chunk)
                if max_bytes is not None and size >= max_bytes:
                    break
            body = b"".join(chunks)

        if cache_ttl_s > 0:
            # Body first, then metadata, each replaced atomically: a run stopped half-way
            # leaves either the old entry or no entry, never a cut-off file the next run trusts.
            # No URL in the metadata: it may hold an API key.
            _atomic_write(body_path, body)
            _atomic_write(meta_path, json.dumps({"fetched_at": time.time()}).encode())
        return body

    def head(self, url: str, *, timeout_s: float | None = None) -> tuple[int, str | None]:
        """HEAD ``url`` without following redirects: (status, Location). No body is ever read."""
        self._wait_for_host(url, self.default_min_interval_s)
        resp = self._session.head(url, timeout=self._timeout(timeout_s), allow_redirects=False)
        return resp.status_code, resp.headers.get("Location")

    @staticmethod
    def _read_cache(body_path: Path, meta_path: Path, cache_ttl_s: float) -> bytes | None:
        """The cached body if it is younger than ``cache_ttl_s``; None on a miss or when the
        cache entry is unreadable (treated as a miss, then overwritten by the fresh fetch)."""
        try:
            meta = json.loads(meta_path.read_text())
            if time.time() - meta["fetched_at"] < cache_ttl_s:
                return body_path.read_bytes()
        except (OSError, ValueError, KeyError, TypeError):
            return None
        return None

    def last_fetch_time(self, url: str) -> float | None:
        """Epoch seconds of the last cached fetch of ``url`` (None if never)."""
        _, meta_path = self._cache_paths(url)
        try:
            return json.loads(meta_path.read_text())["fetched_at"]
        except (OSError, ValueError, KeyError, TypeError):
            return None
