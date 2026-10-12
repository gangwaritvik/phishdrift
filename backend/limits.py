"""Small in-memory building blocks: a TTL cache and a per-client token bucket."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Generic, TypeVar

T = TypeVar("T")
Clock = Callable[[], float]


class TTLCache(Generic[T]):
    """Thread-safe cache with a time-to-live and a maximum size (oldest entry evicted)."""

    def __init__(self, ttl_s: float, max_entries: int, clock: Clock = time.monotonic) -> None:
        self.ttl_s = ttl_s
        self.max_entries = max_entries
        self._clock = clock
        self._items: OrderedDict[str, tuple[float, T]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> T | None:
        with self._lock:
            hit = self._items.get(key)
            if hit is None:
                return None
            stored_at, value = hit
            if self._clock() - stored_at >= self.ttl_s:
                del self._items[key]
                return None
            return value

    def put(self, key: str, value: T) -> None:
        with self._lock:
            self._items[key] = (self._clock(), value)
            self._items.move_to_end(key)
            while len(self._items) > self.max_entries:
                self._items.popitem(last=False)

    def __len__(self) -> int:
        with self._lock:
            return len(self._items)


class RateLimiter:
    """Token bucket per client key. ``allow`` returns ``(allowed, retry_after_s)``."""

    def __init__(
        self, capacity: float, refill_per_s: float, max_clients: int, clock: Clock = time.monotonic
    ) -> None:
        self.capacity = capacity
        self.refill_per_s = refill_per_s
        self.max_clients = max_clients
        self._clock = clock
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, client: str) -> tuple[bool, float]:
        with self._lock:
            now = self._clock()
            tokens, last = self._buckets.pop(client, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_s)
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            self._buckets[client] = (tokens, now)
            while len(self._buckets) > self.max_clients:
                self._buckets.popitem(last=False)
            retry = 0.0 if allowed else (1.0 - tokens) / self.refill_per_s
            return allowed, retry
