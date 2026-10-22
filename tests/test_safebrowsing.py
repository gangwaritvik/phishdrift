"""Safe Browsing: update rounds against a stub of Google's API, and the two backend endpoints."""

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.safebrowsing import FILE_NAME, SafeBrowsing
from backend.settings import Settings


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def update_reply(threat, kind, prefixes, state, removals=(), all_prefixes=None):
    """A listUpdateResponse; the checksum covers the list after the update."""
    final = sorted(all_prefixes if all_prefixes is not None else prefixes)
    return {
        "threatType": threat,
        "responseType": kind,
        "additions": [
            {
                "compressionType": "RAW",
                "rawHashes": {"prefixSize": 4, "rawHashes": b64(b"".join(sorted(prefixes)))},
            }
        ],
        "removals": [{"compressionType": "RAW", "rawIndices": {"indices": list(removals)}}]
        if removals
        else [],
        "newClientState": state,
        "checksum": {"sha256": b64(hashlib.sha256(b"".join(final)).digest())},
    }


@pytest.fixture
def cfg() -> dict:
    return {
        **Settings.load().cfg["safebrowsing"],
        "threat_types": ["SOCIAL_ENGINEERING", "MALWARE"],
    }


def test_full_then_partial_update_writes_the_merged_file(tmp_path, cfg):
    a, b, c, d = b"\x01\x00\x00\x00", b"\x02\x00\x00\x00", b"\x03\x00\x00\x00", b"\x04\x00\x00\x00"
    sent = []
    replies = [
        {
            "listUpdateResponses": [
                update_reply("SOCIAL_ENGINEERING", "FULL_UPDATE", [a, b, c], "s1"),
                update_reply("MALWARE", "FULL_UPDATE", [c, d], "m1"),
            ]
        },
        {  # remove index 0 (a) of the sorted social-engineering list, add d
            "listUpdateResponses": [
                update_reply(
                    "SOCIAL_ENGINEERING", "PARTIAL_UPDATE", [d], "s2", [0], all_prefixes=[b, c, d]
                )
            ]
        },
    ]

    def post(url, body):
        sent.append(body)
        return replies.pop(0)

    sb = SafeBrowsing(cfg, "key", tmp_path, post=post)
    assert sb.update() == {"SOCIAL_ENGINEERING": 3, "MALWARE": 2}
    assert (tmp_path / FILE_NAME).read_bytes() == a + b + c + d
    assert "state" not in sent[0]["listUpdateRequests"][0]
    assert sb.update() == {"SOCIAL_ENGINEERING": 3, "MALWARE": 2}
    assert sent[1]["listUpdateRequests"][0]["state"] == "s1"
    # social engineering is now b, c, d and malware c, d: the union has lost a
    assert (tmp_path / FILE_NAME).read_bytes() == b + c + d


def test_checksum_mismatch_restarts_from_a_full_update(tmp_path, cfg):
    cfg = {**cfg, "threat_types": ["MALWARE"]}
    bad = update_reply("MALWARE", "FULL_UPDATE", [b"\x01\x00\x00\x00"], "m1")
    bad["checksum"]["sha256"] = b64(b"\x00" * 32)
    sb = SafeBrowsing(cfg, "key", tmp_path, post=lambda *_: {"listUpdateResponses": [bad]})
    assert sb.update() == {"MALWARE": 0}
    assert (tmp_path / FILE_NAME).read_bytes() == b""
    assert sb._load("MALWARE") == ("", [])


def test_full_hashes_are_cached(tmp_path, cfg):
    full = hashlib.sha256(b"evil.example/").digest()
    calls = []

    def post(url, body):
        calls.append(body)
        return {"matches": [{"threat": {"hash": b64(full)}}]}

    now = [0.0]
    sb = SafeBrowsing(cfg, "key", tmp_path, post=post, monotonic=lambda: now[0])
    assert sb.full_hashes(full[:4]) == [full]
    assert sb.full_hashes(full[:4]) == [full]
    assert len(calls) == 1
    assert calls[0]["threatInfo"]["threatEntries"] == [{"hash": b64(full[:4])}]
    now[0] += cfg["cache_s"] + 1
    sb.full_hashes(full[:4])
    assert len(calls) == 2


def client(tmp_path, sb):
    settings = Settings.load(
        {
            "feedback": {"dir": str(tmp_path / "feedback")},
            "lists": {"out_dir": str(tmp_path / "lists")},
            "safebrowsing": {"dir": str(tmp_path / "sb")},
            "rate_limit": {"capacity": 1000},
        }
    )
    return TestClient(create_app(settings, checker=lambda d: {}, safebrowsing=sb)), settings


def test_endpoints(tmp_path, cfg):
    full = hashlib.sha256(b"evil.example/").digest()
    sb = SafeBrowsing(
        cfg, "key", tmp_path, post=lambda *_: {"matches": [{"threat": {"hash": b64(full)}}]}
    )
    http, settings = client(tmp_path, sb)
    assert http.get("/lists/safebrowsing.bin").status_code == 404
    settings.safebrowsing_dir.mkdir(parents=True)
    (settings.safebrowsing_dir / FILE_NAME).write_bytes(full[:4])
    got = http.get("/lists/safebrowsing.bin")
    assert got.content == full[:4]
    assert (
        http.get(
            "/lists/safebrowsing.bin", headers={"If-None-Match": got.headers["ETag"]}
        ).status_code
        == 304
    )
    ok = http.post("/safebrowsing/confirm", json={"prefix": full[:4].hex()})
    assert ok.json() == {"hashes": [full.hex()]}
    # only a bare 4-byte prefix is accepted: no URL, no domain, no longer hash
    assert http.post("/safebrowsing/confirm", json={"prefix": "evil.example"}).status_code == 422
    assert http.post("/safebrowsing/confirm", json={"prefix": full.hex()}).status_code == 422


def test_confirm_without_a_key_or_when_google_fails(tmp_path, cfg, monkeypatch):
    monkeypatch.delenv(Settings.load().cfg["safebrowsing"]["api_key_env"], raising=False)
    http, _ = client(tmp_path, None)
    assert http.post("/safebrowsing/confirm", json={"prefix": "00000000"}).status_code == 404

    def boom(*_):
        raise RuntimeError("google down")

    http, _ = client(tmp_path, SafeBrowsing(cfg, "key", tmp_path, post=boom))
    assert http.post("/safebrowsing/confirm", json={"prefix": "00000000"}).status_code == 503
