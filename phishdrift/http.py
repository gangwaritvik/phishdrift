"""HTTP client for feeds and crawling: timeouts, retries with backoff, an on-disk cache
and a per-host minimum interval between requests."""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

log = logging.getLogger(__name__)


@dataclass
class HttpClient:
    cache_dir: Path
    timeout_s: float = 20
    retries: int = 3
    backoff_factor: float = 2.0
    user_agent: str = "PhishDrift-research-collector/0.1"
    default_min_interval_s: float = 1.0
    _last_request: dict[str, float] = field(default_factory=dict, init=False)
    _session: requests.Session = field(init=False)

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
        )

    def _cache_paths(self, url: str) -> tuple[Path, Path]:
        key = hashlib.sha256(url.encode()).hexdigest()
        return self.cache_dir / f"{key}.body", self.cache_dir / f"{key}.json"

    def _wait_for_host(self, url: str, min_interval_s: float) -> None:
        host = urlsplit(url).hostname or ""
        last = self._last_request.get(host)
        if last is not None:
            delay = min_interval_s - (time.monotonic() - last)
            if delay > 0:
                time.sleep(delay)
        self._last_request[host] = time.monotonic()

    def get(
        self,
        url: str,
        *,
        cache_ttl_s: float = 0,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
        min_interval_s: float | None = None,
    ) -> bytes:
        """GET ``url``. Serves from disk cache when younger than ``cache_ttl_s``.

        The cache key is the URL only, so pass secrets in ``headers`` rather than the URL
        when possible. ``min_interval_s`` overrides the per-host politeness delay (e.g. a
        site's robots.txt Crawl-delay). Raises ``requests.HTTPError`` on a non-2xx final
        response.
        """
        body_path, meta_path = self._cache_paths(url)
        if cache_ttl_s > 0 and meta_path.exists() and body_path.exists():
            meta = json.loads(meta_path.read_text())
            if time.time() - meta["fetched_at"] < cache_ttl_s:
                log.debug("cache hit %s", url)
                return body_path.read_bytes()

        interval = self.default_min_interval_s
        if min_interval_s is not None:
            interval = max(interval, min_interval_s)
        self._wait_for_host(url, interval)
        with self._session.get(url, timeout=self.timeout_s, headers=headers, stream=True) as resp:
            resp.raise_for_status()
            chunks, size = [], 0
            for chunk in resp.iter_content(64 * 1024):
                chunks.append(chunk)
                size += len(chunk)
                if max_bytes is not None and size >= max_bytes:
                    break
            body = b"".join(chunks)

        if cache_ttl_s > 0:
            body_path.write_bytes(body)
            # No URL in the metadata: it may hold an API key.
            meta_path.write_text(json.dumps({"fetched_at": time.time()}))
        return body

    def last_fetch_time(self, url: str) -> float | None:
        """Epoch seconds of the last cached fetch of ``url`` (None if never)."""
        _, meta_path = self._cache_paths(url)
        if not meta_path.exists():
            return None
        return json.loads(meta_path.read_text())["fetched_at"]
