"""Google Safe Browsing (Update API v4): local hash prefixes plus full-hash confirmation.

``update()`` keeps the prefix sets of the configured threat types in sync with Google
(``threatListUpdates:fetch``, RAW compression, checksum verified) and writes one file for the
extension: the sorted, de-duplicated 4-byte prefixes of all of them. ``full_hashes()`` answers
``fullHashes:find`` for one prefix. The key stays on this machine; the extension sends a 4-byte
hash prefix, never a URL or a domain.

Run an update round with ``python -m backend safebrowsing-update`` (repeat it at the pace of
``minimumWaitDuration``, about every 30 minutes). Terms: non-commercial use only.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import requests

log = logging.getLogger(__name__)

API = "https://safebrowsing.googleapis.com/v4"
PREFIX_BYTES = 4
FILE_NAME = "safebrowsing.bin"


def _b64(data: str) -> bytes:
    return base64.b64decode(data)


class SafeBrowsing:
    """``cfg`` is the ``safebrowsing`` block of backend.yaml. ``post(url, body)`` returns the
    parsed JSON of a POST (tests pass a stub; the default uses ``requests``)."""

    def __init__(
        self,
        cfg: dict[str, Any],
        api_key: str,
        state_dir: Path,
        post: Callable[[str, dict], dict] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.cfg = cfg
        self.key = api_key
        self.state_dir = Path(state_dir)
        self._post = post or self._http_post
        self._clock = monotonic
        self._cache: dict[bytes, tuple[float, list[bytes]]] = {}
        self._lock = threading.Lock()

    # --- transport ---------------------------------------------------------------------

    def _http_post(self, url: str, body: dict) -> dict:
        res = requests.post(url, params={"key": self.key}, json=body, timeout=self.cfg["timeout_s"])
        res.raise_for_status()
        return res.json()

    def _client(self) -> dict:
        return {"clientId": self.cfg["client_id"], "clientVersion": self.cfg["client_version"]}

    # --- update ------------------------------------------------------------------------

    def _load(self, threat: str) -> tuple[str, list[bytes]]:
        path = self.state_dir / f"{threat}.json"
        if not path.exists():
            return "", []
        doc = json.loads(path.read_text(encoding="utf-8"))
        return doc["state"], [bytes.fromhex(h) for h in doc["prefixes"]]

    def _save(self, threat: str, state: str, prefixes: list[bytes]) -> None:
        path = self.state_dir / f"{threat}.json"
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"state": state, "prefixes": [p.hex() for p in prefixes]}))
        os.replace(tmp, path)

    def _apply(self, upd: dict, prefixes: list[bytes]) -> list[bytes]:
        """Prefix list after one ``listUpdateResponse``; raises ValueError on an unsupported
        encoding or a checksum mismatch (the caller then drops its state and starts over)."""
        if upd["responseType"] == "FULL_UPDATE":
            prefixes = []
        for rem in upd.get("removals", []):
            if rem["compressionType"] != "RAW":
                raise ValueError("unsupported removal compression")
            drop = set(rem["rawIndices"].get("indices", []))
            prefixes = [p for i, p in enumerate(prefixes) if i not in drop]
        got = set(prefixes)
        for add in upd.get("additions", []):
            if add["compressionType"] != "RAW":
                raise ValueError("unsupported addition compression")
            raw, size = _b64(add["rawHashes"]["rawHashes"]), add["rawHashes"]["prefixSize"]
            got.update(raw[i : i + size] for i in range(0, len(raw), size))
        out = sorted(got)
        want = _b64(upd["checksum"]["sha256"])
        if hashlib.sha256(b"".join(out)).digest() != want:
            raise ValueError("checksum mismatch")
        return out

    def update(self) -> dict[str, int]:
        """One update round for every configured threat type; returns prefix counts. A threat
        type that fails keeps its previous prefixes (and, after a checksum mismatch, restarts from
        a full update next round)."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        threats = self.cfg["threat_types"]
        loaded = {t: self._load(t) for t in threats}
        body = {
            "client": self._client(),
            "listUpdateRequests": [
                {
                    "threatType": t,
                    "platformType": "ANY_PLATFORM",
                    "threatEntryType": "URL",
                    **({"state": loaded[t][0]} if loaded[t][0] else {}),
                    "constraints": {"supportedCompressions": ["RAW"]},
                }
                for t in threats
            ],
        }
        reply = self._post(f"{API}/threatListUpdates:fetch", body)
        for upd in reply.get("listUpdateResponses", []):
            threat = upd["threatType"]
            try:
                prefixes = self._apply(upd, loaded[threat][1])
            except ValueError as exc:
                log.warning("safe browsing %s: %s; restarting from a full update", threat, exc)
                loaded[threat] = ("", [])
                self._save(threat, "", [])
                continue
            loaded[threat] = (upd["newClientState"], prefixes)
            self._save(threat, upd["newClientState"], prefixes)
        merged = sorted({p[:PREFIX_BYTES] for _, prefixes in loaded.values() for p in prefixes})
        self.write_file(merged)
        return {t: len(loaded[t][1]) for t in threats}

    def write_file(self, merged: list[bytes], out_dir: Path | None = None) -> Path:
        path = (out_dir or self.state_dir) / FILE_NAME
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(b"".join(merged))
        os.replace(tmp, path)
        return path

    # --- full hashes -------------------------------------------------------------------

    def full_hashes(self, prefix: bytes) -> list[bytes]:
        """Full 32-byte hashes Google lists under ``prefix`` (cached for the duration Google
        gives, capped by ``cache_s``)."""
        with self._lock:
            hit = self._cache.get(prefix)
            if hit and self._clock() < hit[0]:
                return hit[1]
        states = [self._load(t)[0] for t in self.cfg["threat_types"]]
        reply = self._post(
            f"{API}/fullHashes:find",
            {
                "client": self._client(),
                "clientStates": [s for s in states if s],
                "threatInfo": {
                    "threatTypes": self.cfg["threat_types"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"hash": base64.b64encode(prefix).decode()}],
                },
            },
        )
        hashes = sorted({_b64(m["threat"]["hash"]) for m in reply.get("matches", [])})
        with self._lock:
            if len(self._cache) >= self.cfg["cache_max"]:
                self._cache.pop(next(iter(self._cache)))
            self._cache[prefix] = (self._clock() + self.cfg["cache_s"], hashes)
        return hashes
