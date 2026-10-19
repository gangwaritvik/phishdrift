"""Feedback tokens (/register), per-install daily cap, dedupe and the stored reporter key."""

import hashlib
import json
import os
import stat
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.checks import empty_facts
from backend.feedback_auth import TokenSigner, load_secret, reporter_key
from backend.limits import DailyCounter
from backend.settings import Settings

ENV = "PHISHDRIFT_FEEDBACK_SECRET"
BODY = {"domain": "shop.example.com", "kind": "false_positive", "verdict": 2}


@pytest.fixture(autouse=True)
def no_env_secret(monkeypatch):
    monkeypatch.delenv(ENV, raising=False)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings.load(
        {
            "feedback": {"dir": str(tmp_path / "feedback")},
            "lists": {"out_dir": str(tmp_path / "lists")},
            "rate_limit": {"capacity": 1000},
        }
    )


class Clock:
    def __init__(self) -> None:
        self.mono = 0.0
        self.now = datetime(2026, 10, 12, 12, 0, 0, tzinfo=UTC)

    def advance(self, seconds: float) -> None:
        self.mono += seconds
        self.now += timedelta(seconds=seconds)


def make(settings, clock: Clock | None = None) -> TestClient:
    clock = clock or Clock()
    app = create_app(
        settings,
        lambda d: empty_facts(),
        monotonic=lambda: clock.mono,
        utcnow=lambda: clock.now,
    )
    return TestClient(app)


def register(client) -> dict[str, str]:
    resp = client.post("/register")
    assert resp.status_code == 200
    return {"X-PhishDrift-Token": resp.json()["token"]}


def rows(settings, day="2026-10-12") -> list[dict]:
    path = settings.feedback_dir / f"{day}.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines()]


# --- token format and signing -----------------------------------------------------------


def test_token_format_and_verify():
    signer = TokenSigner(b"x" * 32)
    token = signer.issue()
    install_id, mac = token.split(".")
    assert len(install_id) == 22 and len(mac) == 22
    assert set(token) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.")
    assert signer.verify(token) == install_id
    assert signer.issue() != token  # random install ids


@pytest.mark.parametrize(
    "bad",
    [None, "", "abc", "a.b.c", "x" * 22 + "." + "y" * 21, "x" * 22 + "." + "y" * 22, "x" * 45],
)
def test_malformed_or_forged_tokens_fail(bad):
    assert TokenSigner(b"x" * 32).verify(bad) is None


def test_tampered_token_and_wrong_secret_fail():
    token = TokenSigner(b"x" * 32).issue()
    install_id, mac = token.split(".")
    flipped = ("A" if mac[0] != "A" else "B") + mac[1:]
    assert TokenSigner(b"x" * 32).verify(f"{install_id}.{flipped}") is None
    assert TokenSigner(b"y" * 32).verify(token) is None


def test_secret_file_created_0600_and_reused(tmp_path):
    first = load_secret(ENV, tmp_path / "fb")
    path = tmp_path / "fb" / ".secret"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert load_secret(ENV, tmp_path / "fb") == first
    assert len(first) >= 32


def test_secret_file_permissions_are_tightened(tmp_path):
    path = tmp_path / ".secret"
    path.write_text("z" * 64)
    os.chmod(path, 0o644)
    assert load_secret(ENV, tmp_path) == b"z" * 64
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_secret_from_env_wins_and_short_one_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV, "s" * 40)
    assert load_secret(ENV, tmp_path) == b"s" * 40
    assert not (tmp_path / ".secret").exists()
    monkeypatch.setenv(ENV, "short")
    with pytest.raises(ValueError, match=ENV):
        load_secret(ENV, tmp_path)


def test_empty_secret_file_is_an_error(tmp_path):
    (tmp_path / ".secret").write_text("")
    os.chmod(tmp_path / ".secret", 0o600)
    with pytest.raises(ValueError, match="too short"):
        load_secret(ENV, tmp_path)


def test_tokens_survive_restart(settings):
    headers = register(make(settings))
    assert make(settings).post("/feedback", json=BODY, headers=headers).json() == {"ok": True}


def test_token_from_another_secret_is_rejected(settings, tmp_path, monkeypatch):
    other = Settings.load({"feedback": {"dir": str(tmp_path / "other")}})
    headers = register(make(other))
    assert make(settings).post("/feedback", json=BODY, headers=headers).status_code == 401
    monkeypatch.setenv(ENV, "e" * 40)  # env secret replaces the file secret
    assert make(other).post("/feedback", json=BODY, headers=headers).status_code == 401


# --- endpoints --------------------------------------------------------------------------


def test_register_returns_only_a_token(settings):
    data = make(settings).post("/register").json()
    assert set(data) == {"token"}


def test_feedback_needs_a_valid_token(settings):
    client = make(settings)
    assert client.post("/feedback", json=BODY).status_code == 401
    bad = {"X-PhishDrift-Token": "x" * 22 + "." + "y" * 22}
    assert client.post("/feedback", json=BODY, headers=bad).status_code == 401
    good = register(client)
    assert client.post("/feedback", json=BODY, headers=good).json() == {"ok": True}
    assert len(rows(settings)) == 1


def test_invalid_body_is_422_before_auth(settings):
    client = make(settings)
    assert client.post("/feedback", json={"domain": "x.example"}).status_code == 422


def test_register_rate_limit_per_ip(settings):
    clock = Clock()
    client = make(settings, clock)
    codes = [client.post("/register").status_code for _ in range(5)]
    assert codes == [200, 200, 200, 429, 429]
    limited = client.post("/register")
    assert int(limited.headers["Retry-After"]) >= 1
    clock.advance(3600)
    assert client.post("/register").status_code == 200


def test_register_bucket_is_separate_from_general_limit(settings):
    settings.cfg["rate_limit"].update(capacity=1, refill_per_s=0.0001)
    client = make(settings)
    assert client.post("/register").status_code == 200
    assert client.post("/register").status_code == 200  # general bucket not used by /register


def test_per_ip_limit_still_applies_to_feedback(settings):
    settings.cfg["rate_limit"].update(capacity=2, refill_per_s=0.0001)
    client = make(settings)
    headers = register(client)
    codes = [
        client.post("/feedback", json={**BODY, "domain": f"d{i}.example"}, headers=headers)
        for i in range(3)
    ]
    assert [c.status_code for c in codes] == [200, 200, 429]


def test_daily_cap_per_install_and_reset_at_utc_midnight(settings):
    settings.cfg["feedback"]["max_per_install_per_day"] = 3
    clock = Clock()
    clock.now = datetime(2026, 10, 12, 23, 0, 0, tzinfo=UTC)
    client = make(settings, clock)
    a, b = register(client), register(client)
    codes = [
        client.post("/feedback", json={**BODY, "domain": f"d{i}.example"}, headers=a).status_code
        for i in range(5)
    ]
    assert codes == [200, 200, 200, 429, 429]
    over = client.post("/feedback", json={**BODY, "domain": "z.example"}, headers=a)
    assert 1 <= int(over.headers["Retry-After"]) <= 3600  # until 00:00 UTC
    assert client.post("/feedback", json=BODY, headers=b).status_code == 200  # other install
    assert len(rows(settings)) == 4
    clock.advance(3600)  # new UTC day
    assert client.post("/feedback", json={**BODY, "domain": "n.example"}, headers=a).json() == {
        "ok": True
    }
    assert len(rows(settings, "2026-10-13")) == 1


def test_duplicate_is_acknowledged_not_stored(settings):
    settings.cfg["feedback"]["dedupe_window_s"] = 100
    clock = Clock()
    client = make(settings, clock)
    a, b = register(client), register(client)
    assert client.post("/feedback", json=BODY, headers=a).json() == {"ok": True}
    assert client.post("/feedback", json=BODY, headers=a).json() == {"ok": True, "duplicate": True}
    # a different kind, domain or install is not a duplicate
    other_kind = {**BODY, "kind": "missed_phish"}
    assert client.post("/feedback", json=other_kind, headers=a).json() == {"ok": True}
    other_domain = {**BODY, "domain": "x.example"}
    assert client.post("/feedback", json=other_domain, headers=a).json() == {"ok": True}
    assert client.post("/feedback", json=BODY, headers=b).json() == {"ok": True}
    assert len(rows(settings)) == 4
    clock.advance(100)  # window over: stored again
    assert client.post("/feedback", json=BODY, headers=a).json() == {"ok": True}
    assert len(rows(settings)) == 5


def test_duplicates_do_not_use_the_daily_cap(settings):
    settings.cfg["feedback"]["max_per_install_per_day"] = 1
    client = make(settings)
    a = register(client)
    assert client.post("/feedback", json=BODY, headers=a).json() == {"ok": True}
    for _ in range(3):
        assert client.post("/feedback", json=BODY, headers=a).json()["duplicate"] is True
    other = client.post("/feedback", json={**BODY, "domain": "y.example"}, headers=a)
    assert other.status_code == 429


def test_stored_line_has_reporter_key_and_never_the_token(settings):
    client = make(settings)
    headers = register(client)
    token = headers["X-PhishDrift-Token"]
    install_id, mac = token.split(".")
    client.post("/feedback", json=BODY, headers=headers)
    client.post("/feedback", json={**BODY, "domain": "x.example"}, headers=headers)
    stored = rows(settings)
    assert all(set(r) == {"domain", "kind", "verdict", "timestamp", "reporter"} for r in stored)
    expected = hashlib.sha256(install_id.encode()).hexdigest()[:16]
    assert {r["reporter"] for r in stored} == {expected} == {reporter_key(install_id)}
    text = "".join(p.read_text() for p in settings.feedback_dir.glob("*.jsonl"))
    assert install_id not in text and mac not in text and token not in text


def test_distinct_installs_have_distinct_reporter_keys(settings):
    client = make(settings)
    for _ in range(2):
        client.post("/feedback", json=BODY, headers=register(client))
    assert len({r["reporter"] for r in rows(settings)}) == 2


def test_failed_write_is_not_counted(settings):
    settings.cfg["feedback"]["max_per_install_per_day"] = 1
    client = make(settings)
    headers = register(client)
    target = settings.feedback_dir / "2026-10-12.jsonl"
    target.mkdir(parents=True)  # a directory where the file should be: open() fails
    assert client.post("/feedback", json=BODY, headers=headers).json() == {"ok": False}
    target.rmdir()
    assert client.post("/feedback", json=BODY, headers=headers).json() == {"ok": True}


# --- bounded memory ---------------------------------------------------------------------


def test_daily_counter_is_bounded_and_resets_per_day():
    counter = DailyCounter(max_keys=2)
    assert counter.increment("a", 1) == 1
    assert counter.increment("a", 1) == 2
    assert counter.get("a", 2) == 0
    assert counter.increment("a", 2) == 1
    counter.increment("b", 2)
    counter.increment("c", 2)  # evicts "a", the least recently used
    assert len(counter) == 2
    assert counter.get("a", 2) == 0


def test_per_install_state_is_capped(settings):
    settings.cfg["feedback"]["max_installs"] = 3
    settings.cfg["feedback"]["register_rate"]["capacity"] = 100
    clock = Clock()
    app = create_app(
        settings, lambda d: empty_facts(), monotonic=lambda: clock.mono, utcnow=lambda: clock.now
    )
    client = TestClient(app)
    for _ in range(10):
        client.post("/feedback", json=BODY, headers=register(client))
    assert len(rows(settings)) == 10
    # the counters are closure state; reach them through the endpoint's closure cells
    endpoint = next(r.endpoint for r in app.routes if getattr(r, "path", "") == "/feedback")
    cells = {
        type(c.cell_contents).__name__: c.cell_contents
        for c in endpoint.__closure__
        if type(c.cell_contents).__name__ in ("DailyCounter", "TTLCache")
    }
    assert set(cells) == {"DailyCounter", "TTLCache"}
    assert all(len(obj) <= 3 for obj in cells.values())
