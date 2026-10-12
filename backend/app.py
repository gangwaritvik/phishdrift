"""FastAPI app: domain checks, feedback and the hashed lists the extension syncs.

Run: ``uvicorn backend.app:create_app --factory``.

Privacy: the API accepts a bare hostname only (never a URL, path or page content), unknown
request fields are rejected, and feedback lines hold exactly domain, kind, verdict, timestamp.

The signals and risk returned by ``/score`` and ``/domain-info`` come from placeholder
threshold rules (``backend/checks.py``), not a trained tier C model, and are not validated.
Every lookup fails soft: on an error or timeout the answer is risk "low" with ``error`` set.
"""

from __future__ import annotations

import json
import logging
import math
import re
import threading
import time
from collections.abc import AsyncIterator, Callable
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, field_validator

from backend.checks import FACT_KEYS, Checker, LiveChecker, empty_facts, evaluate
from backend.limits import RateLimiter, TTLCache
from backend.settings import Settings

log = logging.getLogger(__name__)

_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")
_MAX_HOST_LEN = 253

LISTS_MISSING = "The lists have not been built yet; run `python -m backend build-lists`."


def clean_domain(value: str) -> str:
    """Lowercase a bare hostname (one trailing dot allowed) or raise ValueError."""
    host = value.lower()
    if host.endswith("."):
        host = host[:-1]
    if len(host) > _MAX_HOST_LEN or not _HOSTNAME_RE.match(host):
        raise ValueError("domain must be a bare hostname such as example.com")
    return host


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DomainIn(_Strict):
    domain: str

    @field_validator("domain")
    @classmethod
    def _domain(cls, v: str) -> str:
        return clean_domain(v)


class ScoreIn(DomainIn):
    local_verdict: Literal[0, 1, 2]


class FeedbackIn(DomainIn):
    kind: Literal["false_positive", "missed_phish"]
    verdict: Literal[0, 1, 2]


def create_app(
    settings: Settings | None = None,
    checker: Checker | None = None,
    *,
    monotonic: Callable[[], float] = time.monotonic,
    utcnow: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> FastAPI:
    settings = settings or Settings.load()
    cfg = settings.cfg
    checker = checker or LiveChecker(settings)
    cache: TTLCache[dict] = TTLCache(cfg["cache"]["ttl_s"], cfg["cache"]["max_entries"], monotonic)
    rl = cfg["rate_limit"]
    limiter = RateLimiter(rl["capacity"], rl["refill_per_s"], rl["max_clients"], monotonic)
    pool = ThreadPoolExecutor(max_workers=cfg["lookup"]["workers"], thread_name_prefix="check")
    feedback_lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        pool.shutdown(wait=False, cancel_futures=True)

    app = FastAPI(title="PhishDrift backend", version="0.1.0", lifespan=lifespan)

    def rate_limit(request: Request) -> None:
        client = request.client.host if request.client else "unknown"
        allowed, retry = limiter.allow(client)
        if not allowed:
            raise HTTPException(
                status_code=429,
                detail="Too many requests",
                headers={"Retry-After": str(max(1, math.ceil(retry)))},
            )

    def lookup(domain: str) -> tuple[dict, bool]:
        """Checked entry for ``domain`` and whether it came from the cache. Never raises."""
        hit = cache.get(domain)
        if hit is not None:
            return hit, True
        error = None
        facts = empty_facts()
        try:
            raw = pool.submit(checker, domain).result(timeout=cfg["lookup"]["overall_timeout_s"])
            facts = {k: raw.get(k) for k in FACT_KEYS}
        except FutureTimeout:
            error = "timeout"
        except Exception as exc:  # noqa: BLE001 - fail soft: any lookup problem means "low"
            log.warning("domain check failed: %s", type(exc).__name__)
            error = "lookup_failed"
        if error is not None:
            return {"facts": facts, "signals": [], "risk": "low", "error": error}, False
        signals, risk = evaluate(facts, cfg["rules"])
        entry = {"facts": facts, "signals": signals, "risk": risk, "error": None}
        cache.put(domain, entry)
        return entry, False

    @app.get("/health")
    def health() -> dict[str, bool]:
        return {"ok": True}

    @app.post("/domain-info", dependencies=[Depends(rate_limit)])
    def domain_info(body: DomainIn) -> dict[str, Any]:
        entry, cached = lookup(body.domain)
        return {"domain": body.domain, "cached": cached, **entry}

    @app.post("/score", dependencies=[Depends(rate_limit)])
    def score(body: ScoreIn) -> dict[str, Any]:
        # local_verdict is accepted for the future combiner; the placeholder rules ignore it.
        entry, cached = lookup(body.domain)
        return {
            "domain": body.domain,
            "risk": entry["risk"],
            "signals": entry["signals"],
            "tier_c_model": False,
            "cached": cached,
        }

    @app.post("/feedback", dependencies=[Depends(rate_limit)])
    def feedback(body: FeedbackIn) -> dict[str, bool]:
        now = utcnow().astimezone(UTC)
        line = json.dumps(
            {
                "domain": body.domain,
                "kind": body.kind,
                "verdict": body.verdict,
                "timestamp": now.isoformat(timespec="seconds"),
            }
        )
        path = settings.feedback_dir / f"{now:%Y-%m-%d}.jsonl"
        try:
            with feedback_lock:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except OSError as exc:
            log.error("feedback not stored: %s", type(exc).__name__)
            return {"ok": False}
        return {"ok": True}

    def list_file(name: str) -> Response:
        path = settings.lists_dir / f"{name}.json"
        if not path.exists():
            raise HTTPException(status_code=404, detail=LISTS_MISSING)
        return Response(content=path.read_bytes(), media_type="application/json")

    @app.get("/lists/manifest", dependencies=[Depends(rate_limit)])
    def lists_manifest() -> Response:
        return list_file("manifest")

    @app.get("/lists/blocklist.json", dependencies=[Depends(rate_limit)])
    def lists_blocklist() -> Response:
        return list_file("blocklist")

    @app.get("/lists/allowlist.json", dependencies=[Depends(rate_limit)])
    def lists_allowlist() -> Response:
        return list_file("allowlist")

    return app
