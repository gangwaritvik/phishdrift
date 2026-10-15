"""Remote config: validation rules, canonical body + sha256, and the /config endpoint."""

import copy
import hashlib
import json

import pytest
import yaml
from fastapi.testclient import TestClient

from backend import remote_config as rc
from backend.app import create_app
from backend.checks import empty_facts
from backend.settings import Settings

PLATFORMS = frozenset({"github.io", "web.app", "blogspot.com"})


@pytest.fixture(autouse=True)
def no_env_secret(monkeypatch):
    monkeypatch.delenv("PHISHDRIFT_FEEDBACK_SECRET", raising=False)


@pytest.fixture
def cfg() -> dict:
    return copy.deepcopy(Settings.load().cfg["remote_config"])


def good() -> dict:
    return {
        "version": 3,
        "thresholds": {
            "address": {"suspicious": 0.9, "dangerous": 0.99},
            "page": {"suspicious": None, "dangerous": None},
        },
        "never_warn": ["example.com", "bank.co.uk"],
        "list_sync_minutes": 60,
        "notes": "two reviewed false positives",
    }


def problems(raw, cfg, platforms=PLATFORMS) -> str:
    with pytest.raises(ValueError) as err:
        rc.validate(raw, cfg, platforms)
    return str(err.value)


# --- validation -------------------------------------------------------------------------


def test_valid_config_is_normalised(cfg):
    doc = rc.validate(good(), cfg, PLATFORMS)
    assert doc["never_warn"] == ["bank.co.uk", "example.com"]  # sorted
    assert doc["thresholds"]["address"] == {"suspicious": 0.9, "dangerous": 0.99}
    assert doc["thresholds"]["page"] == {"suspicious": None, "dangerous": None}
    assert set(doc) == {"version", "thresholds", "never_warn", "list_sync_minutes", "notes"}


def test_shipped_file_is_valid_and_neutral():
    settings = Settings.load()
    from features.lists import read_platforms

    raw = yaml.safe_load(settings.remote_config_path.read_text())
    doc = rc.validate(raw, settings.cfg["remote_config"], read_platforms(settings.platforms_file))
    assert doc["never_warn"] == []
    assert doc["list_sync_minutes"] == 60
    assert all(v is None for m in doc["thresholds"].values() for v in m.values())


def test_defaults_for_optional_keys(cfg):
    raw = good()
    del raw["list_sync_minutes"], raw["notes"], raw["never_warn"]
    doc = rc.validate(raw, cfg, PLATFORMS)
    assert (doc["list_sync_minutes"], doc["notes"], doc["never_warn"]) == (60, "", [])


@pytest.mark.parametrize("value", [0.4999, 1.0, 1.5, -0.1])
def test_threshold_out_of_bounds(cfg, value):
    raw = good()
    raw["thresholds"]["page"]["suspicious"] = value
    assert "thresholds.page.suspicious" in problems(raw, cfg)


def test_bounds_come_from_config(cfg):
    cfg["bounds"] = {"min": 0.95, "max": 0.999}
    assert "thresholds.address.suspicious = 0.9 is outside" in problems(good(), cfg)


@pytest.mark.parametrize("value", ["0.9", True, [0.9]])
def test_threshold_must_be_number_or_null(cfg, value):
    raw = good()
    raw["thresholds"]["address"]["dangerous"] = value
    assert "thresholds.address.dangerous must be a number or null" in problems(raw, cfg)


@pytest.mark.parametrize(("sus", "dan"), [(0.99, 0.9), (0.95, 0.95)])
def test_suspicious_must_be_below_dangerous(cfg, sus, dan):
    raw = good()
    raw["thresholds"]["address"] = {"suspicious": sus, "dangerous": dan}
    assert "suspicious (" in problems(raw, cfg)


def test_one_threshold_set_other_null_is_fine(cfg):
    raw = good()
    raw["thresholds"]["page"] = {"suspicious": None, "dangerous": 0.6}
    assert rc.validate(raw, cfg, PLATFORMS)["thresholds"]["page"]["dangerous"] == 0.6


def test_threshold_structure_errors(cfg):
    raw = good()
    raw["thresholds"]["extra"] = {}
    raw["thresholds"]["address"]["warn"] = 0.9
    del raw["thresholds"]["page"]["dangerous"]
    msg = problems(raw, cfg)
    assert "unknown model 'extra'" in msg
    assert "thresholds.address: unknown key 'warn'" in msg
    assert "thresholds.page.dangerous is missing" in msg
    raw = good()
    raw["thresholds"] = None
    assert "thresholds must be a mapping" in problems(raw, cfg)
    raw = good()
    raw["thresholds"]["page"] = 0.9
    assert "thresholds.page must be a mapping" in problems(raw, cfg)


@pytest.mark.parametrize("domain", ["https://example.com", "exa mple.com", "example.com/x", "", 7])
def test_never_warn_rejects_non_hostnames(cfg, domain):
    raw = good()
    raw["never_warn"] = [domain]
    assert "never_warn entry" in problems(raw, cfg)


@pytest.mark.parametrize("domain", ["www.example.com", "login.bank.co.uk", "co.uk", "localhost.x"])
def test_never_warn_must_be_registrable(cfg, domain):
    raw = good()
    raw["never_warn"] = [domain]
    msg = problems(raw, cfg)
    assert "never_warn entry" in msg
    assert "registrable" in msg or "bare hostname" in msg


def test_never_warn_normalises_case_and_dot(cfg):
    raw = good()
    raw["never_warn"] = ["Example.COM."]
    assert rc.validate(raw, cfg, PLATFORMS)["never_warn"] == ["example.com"]


def test_never_warn_rejects_platforms(cfg):
    raw = good()
    raw["never_warn"] = ["github.io", "web.app"]
    msg = problems(raw, cfg)
    assert msg.count("hosting platform") == 2


def test_never_warn_rejects_real_platform_list():
    settings = Settings.load()
    from features.lists import read_platforms

    platforms = read_platforms(settings.platforms_file)
    assert "github.io" in platforms
    raw = good()
    raw["never_warn"] = ["github.io"]
    assert "hosting platform" in problems(raw, settings.cfg["remote_config"], platforms)


def test_never_warn_duplicates_and_cap(cfg):
    raw = good()
    raw["never_warn"] = ["example.com", "EXAMPLE.com"]
    assert "listed twice" in problems(raw, cfg)
    cfg["max_never_warn"] = 2
    raw["never_warn"] = ["a.com", "b.com", "c.com"]
    assert "never_warn has 3 entries; at most 2" in problems(raw, cfg)
    raw["never_warn"] = "example.com"
    assert "never_warn must be a list" in problems(raw, cfg)


@pytest.mark.parametrize("value", [14, 1441, 0, "60", 60.0, True])
def test_list_sync_minutes_bounds(cfg, value):
    raw = good()
    raw["list_sync_minutes"] = value
    assert "list_sync_minutes must be an integer in [15, 1440]" in problems(raw, cfg)


@pytest.mark.parametrize("value", [15, 1440])
def test_list_sync_minutes_edges_ok(cfg, value):
    raw = good()
    raw["list_sync_minutes"] = value
    assert rc.validate(raw, cfg, PLATFORMS)["list_sync_minutes"] == value


@pytest.mark.parametrize("value", [0, -1, "1", 1.0, True, None])
def test_version_must_be_positive_int(cfg, value):
    raw = good()
    raw["version"] = value
    assert "version must be an integer >= 1" in problems(raw, cfg)


def test_unknown_key_notes_type_and_non_mapping(cfg):
    raw = good()
    raw["enable_llm"] = True
    assert "unknown key 'enable_llm'" in problems(raw, cfg)
    raw = good()
    raw["notes"] = "café"
    assert "notes must be ASCII text" in problems(raw, cfg)
    raw["notes"] = 5
    assert "notes must be ASCII text" in problems(raw, cfg)
    assert "must be a mapping" in problems([1, 2], cfg)


def test_every_problem_is_listed_at_once(cfg):
    raw = {
        "version": 0,
        "thresholds": {
            "address": {"suspicious": 0.2, "dangerous": 0.99},
            "page": {"suspicious": 0.99, "dangerous": 0.9},
        },
        "never_warn": ["www.example.com", "github.io"],
        "list_sync_minutes": 5,
        "notes": 1,
    }
    msg = problems(raw, cfg)
    for part in (
        "version",
        "thresholds.address.suspicious",
        "thresholds.page: suspicious",
        "'www.example.com'",
        "'github.io'",
        "list_sync_minutes",
        "notes",
    ):
        assert part in msg
    assert msg.count("\n- ") == 7


# --- served body ------------------------------------------------------------------------


def test_served_body_is_canonical_with_matching_sha256(cfg):
    body = rc.served(rc.validate(good(), cfg, PLATFORMS))
    doc = json.loads(body)
    digest = doc.pop("sha256")
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(canonical.encode()).hexdigest() == digest
    assert body.decode() == json.dumps(
        {**doc, "sha256": digest}, sort_keys=True, separators=(",", ":")
    )
    assert b" " not in body.replace(b"two reviewed false positives", b"")


def test_load_reads_yaml_and_reports_unreadable_files(cfg, tmp_path):
    path = tmp_path / "rc.yaml"
    path.write_text(yaml.safe_dump(good()))
    assert json.loads(rc.load(path, cfg, PLATFORMS))["version"] == 3
    with pytest.raises(ValueError, match="cannot be read"):
        rc.load(tmp_path / "missing.yaml", cfg, PLATFORMS)
    path.write_text("version: [unclosed")
    with pytest.raises(ValueError, match="cannot be read"):
        rc.load(path, cfg, PLATFORMS)


# --- endpoint ---------------------------------------------------------------------------


def app_settings(tmp_path, raw) -> Settings:
    path = tmp_path / "remote_config.yaml"
    path.write_text(yaml.safe_dump(raw))
    return Settings.load(
        {
            "feedback": {"dir": str(tmp_path / "feedback")},
            "remote_config": {"path": str(path)},
            "rate_limit": {"capacity": 3, "refill_per_s": 0.0001},
        }
    )


def test_config_endpoint_serves_the_validated_body(tmp_path):
    settings = app_settings(tmp_path, good())
    client = TestClient(create_app(settings, lambda d: empty_facts()))
    resp = client.get("/config")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/json")
    doc = resp.json()
    digest = doc.pop("sha256")
    assert doc == rc.validate(good(), settings.cfg["remote_config"], PLATFORMS)
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(canonical).hexdigest() == digest


def test_config_endpoint_is_rate_limited(tmp_path):
    client = TestClient(create_app(app_settings(tmp_path, good()), lambda d: empty_facts()))
    assert [client.get("/config").status_code for _ in range(4)] == [200, 200, 200, 429]


def test_app_refuses_to_start_with_a_bad_config(tmp_path):
    raw = good()
    raw["thresholds"]["address"]["suspicious"] = 0.1
    with pytest.raises(ValueError, match="invalid remote config"):
        create_app(app_settings(tmp_path, raw), lambda d: empty_facts())


def test_default_app_serves_the_shipped_config(tmp_path):
    settings = Settings.load({"feedback": {"dir": str(tmp_path / "feedback")}})
    client = TestClient(create_app(settings, lambda d: empty_facts()))
    doc = client.get("/config").json()
    assert doc["version"] == 1 and doc["never_warn"] == []
