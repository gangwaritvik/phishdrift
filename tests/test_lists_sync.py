"""Blocklist URL expressions, tenant learning, longer hashes, signed manifests and deltas."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import lists
from backend.app import create_app
from backend.checks import empty_facts
from backend.settings import Settings

SYNC_FIXTURE = Path(__file__).parent / "fixtures" / "list_sync_fixture.json"


def _model(urls, cands=(), shared=frozenset(), **kw):
    kw = {"min_tenant_children": 3, "min_children_per_url": 0.5, "min_children_whole": 20, **kw}
    return lists.learn_zones(urls, set(cands), shared=shared, **kw)


def test_expressions_cover_the_exact_key_and_prefixes():
    url = "https://www.X.web.app/a/b/c/d?t=1#f"
    exprs = lists.list_url_expressions(url)
    assert exprs[0] == "x.web.app"
    assert lists.list_url_key(url) in exprs
    assert "x.web.app/a/b/c/d" in exprs and "x.web.app/a/b/c" in exprs
    assert "web.app" in exprs  # parent suffixes are looked up; the builder never lists them
    assert len(lists.list_url_expressions("https://a.b.c.d.e.f.g.example.com/" + "x/" * 9)) <= 30


def test_generic_first_segments_and_path_tenants():
    urls = [f"https://ipfs.io/ipfs/cid{i}" for i in range(6)]
    generic, counts = lists._path_tenants([lists._segments(lists._split(u)[2], 2) for u in urls], 3)
    assert generic == {"ipfs"} and len(counts) == 6
    model = _model(urls, cands=["ipfs.io"])
    assert model.zones == {"ipfs.io": "path"}
    assert lists.path_tenant_prefix("/ipfs/cid9/x", model.path_hosts["ipfs.io"]) == "/ipfs/cid9"
    # a big site's own open redirect does not make it a path tenant host
    redirect = [f"https://www.google.com/url?q=https://evil{i}.test" for i in range(5)]
    assert "google.com" not in _model(redirect, cands=["google.com"]).zones


def test_tenant_hosts_need_one_tenant_per_subdomain():
    web = [f"https://t{i}.web.app/login" for i in range(5)]
    model = _model(web, shared=frozenset({"web.app"}))
    assert "web.app" in model.tenant_domains
    keys = lists.block_url_keys("https://t1.web.app/login?victim=42", model, {"web.app"})
    assert keys == ["t1.web.app/login?victim=42", "t1.web.app", "t1.web.app/login"]
    # storage.googleapis.com is a PSL private suffix tenant but shared by every bucket
    gcs = [f"https://storage.googleapis.com/bucket{i}/p.html" for i in range(5)]
    gmodel = _model(gcs, shared=frozenset({"googleapis.com"}))
    keys = lists.block_url_keys(gcs[0] + "?x=1", gmodel, {"googleapis.com"})
    assert "storage.googleapis.com" not in keys
    assert "storage.googleapis.com/bucket0" in keys  # its path tenant
    # an owner host with no tenant structure keeps exact URLs, plus specific paths only
    drive = ["https://drive.google.com/open?id=abc", "https://drive.google.com/open?id=def"]
    dmodel = _model(drive, cands=["google.com"])
    assert lists.block_url_keys(drive[0], dmodel, {"google.com"}) == [
        "drive.google.com/open?id=abc"
    ]
    form = "https://docs.google.com/forms/d/e/1FAIpQLSdXyZ0123456789/viewform?usp=sf"
    keys = lists.block_url_keys(form, _model([form], cands=["google.com"]), {"google.com"})
    assert keys == [
        lists.list_url_key(form),
        "docs.google.com/forms/d/e/1FAIpQLSdXyZ0123456789/viewform",
    ]


def test_token_variants_match_after_build():
    feed = [f"https://t{i}.web.app/signin?session=s{i}" for i in range(6)]
    docs = lists.build_lists(feed, [], frozenset({"web.app"}), 8)
    urls = set(docs["blocklist"]["urls"])

    def hit(url):
        return any(lists.list_hash(k, 8) in urls for k in lists.list_url_expressions(url))

    assert hit("https://t3.web.app/signin?session=OTHER")
    assert hit("https://t3.web.app/other/page")
    assert not hit("https://t99.web.app/signin?session=s3")
    assert not hit("https://web.app/")


def test_allowlist_prefix_and_top_sentinels():
    docs = lists.build_lists(
        [], ["a.com", "b.com", "c.com"], frozenset(), 8, allow_prefix_bytes=16, sentinel_top_n=2
    )
    allow = docs["allowlist"]
    assert allow["prefix_bytes"] == 16 and all(len(h) == 32 for h in allow["domains"])
    assert allow["top"] == [lists.list_hash("a.com", 16), lists.list_hash("b.com", 16)]
    assert (
        docs["manifest"]["sha256"]["allowlist"]
        == lists.hashlib.sha256(lists._canonical(allow)).hexdigest()
    )


def test_signed_manifest_history_and_delta(tmp_path):
    lists.make_signing_key(tmp_path / "k.pem", [tmp_path / "pub.js"])
    pem = (tmp_path / "k.pem").read_bytes()
    assert (tmp_path / "k.pem").stat().st_mode & 0o777 == 0o600
    assert "ECDSA-P256-SHA256" in (tmp_path / "pub.js").read_text()
    with pytest.raises(FileExistsError):
        lists.make_signing_key(tmp_path / "k.pem", [])
    old = lists.build_lists(["http://bad1.test/x"], ["a.com"], frozenset(), 8)
    new = lists.build_lists(["http://bad2.test/x"], ["a.com"], frozenset(), 8)
    out = tmp_path / "lists"
    lists.write_lists(old, out, pem)
    lists.write_lists(new, out, pem)
    manifest = json.loads((out / "manifest.json").read_text())
    pub = (tmp_path / "pub.js").read_text()
    spki = json.loads(pub[pub.index("{") : pub.rindex("}") + 1])["spki"]
    body = {k: v for k, v in manifest.items() if k != "signature"}
    assert lists.verify_body(lists._canonical(body), manifest["signature"], spki)
    body["counts"]["blocklist_domains"] = 0
    assert not lists.verify_body(lists._canonical(body), manifest["signature"], spki)
    delta = lists.list_delta(out, old["manifest"]["version"])
    assert delta["blocklist"]["domains"] == {
        "add": [lists.list_hash("bad2.test", 8)],
        "del": [lists.list_hash("bad1.test", 8)],
    }
    assert lists.list_delta(out, "0" * 12) is None and lists.list_delta(out, "../../etc") is None
    for i in range(5):
        lists.write_lists(
            lists.build_lists([f"http://b{i}.test/"], [], frozenset(), 8), out, None, 3
        )
    assert len(list((out / "history").glob("*.json"))) == 3


def test_python_fixture_signatures_verify():
    fx = json.loads(SYNC_FIXTURE.read_text(encoding="utf-8"))
    spki = fx["pubkey"]["spki"]
    body = {k: v for k, v in fx["manifest"].items() if k != "signature"}
    assert lists.verify_body(lists._canonical(body), fx["manifest"]["signature"], spki)
    cfg = {k: v for k, v in fx["config"].items() if k != "signature"}
    served = json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode()
    assert lists.verify_body(served, fx["config"]["signature"], spki)
    assert not lists.verify_body(served, base64.b64encode(b"x" * 64).decode(), spki)


def test_delta_endpoint_and_signed_config(tmp_path):
    key = tmp_path / "keys" / "k.pem"
    lists.make_signing_key(key, [])
    settings = Settings.load(
        {
            "feedback": {"dir": str(tmp_path / "feedback")},
            "lists": {"out_dir": str(tmp_path / "lists"), "signing_key": str(key)},
        }
    )
    client = TestClient(create_app(settings, lambda d: empty_facts()))
    old = lists.build_lists(["http://bad1.test/x"], ["a.com"], frozenset(), 8)
    lists.write_lists(old, settings.lists_dir, key.read_bytes())
    lists.write_lists(lists.build_lists([], ["a.com"], frozenset(), 8), settings.lists_dir)
    resp = client.get("/lists/delta", params={"from": old["manifest"]["version"]})
    assert resp.status_code == 200 and resp.json()["blocklist"]["domains"]["del"]
    assert client.get("/lists/delta", params={"from": "nope"}).status_code == 404
    doc = client.get("/config").json()
    sig = doc.pop("signature")
    served = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    from cryptography.hazmat.primitives import serialization

    priv = serialization.load_pem_private_key(key.read_bytes(), password=None)
    spki = base64.b64encode(
        priv.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()
    assert lists.verify_body(served, sig, spki)
