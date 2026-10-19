// List sync safety: signatures, file hashes, deltas, sanity limits and remote config.
// tests/fixtures/list_sync_fixture.json is written by backend/make_fixture.py (Python signs it).

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { listUrlExpressions } from "../dist/keys.js";
import { applyDelta, checkConfig, checkLists, fetchConfig, sha256Hex, syncLists, verifySignature } from "../dist/listsync.js";

const fx = JSON.parse(readFileSync(new URL("../../tests/fixtures/list_sync_fixture.json", import.meta.url), "utf8"));
const parity = JSON.parse(readFileSync(new URL("../../tests/fixtures/list_key_parity.json", import.meta.url), "utf8"));
const BLOCK = JSON.parse(fx.blocklist_text);
const ALLOW = JSON.parse(fx.allowlist_text);
const BUNDLED = fx.old.allowlist; // what ships with the extension: carries the trusted `top` hashes

// A fake backend: `routes` maps a path to a body (object -> JSON, string -> text) or a status code.
function backend(routes) {
  const calls = [];
  const fetchFn = async (url) => {
    const path = url.replace("http://b", "");
    calls.push(path);
    const body = routes[path];
    if (body === undefined || typeof body === "number") return { ok: false, status: body ?? 404 };
    const text = typeof body === "string" ? body : JSON.stringify(body);
    return { ok: true, status: 200, text: async () => text, json: async () => JSON.parse(text) };
  };
  return { fetchFn, calls };
}

const full = {
  "/lists/manifest": fx.manifest,
  "/lists/blocklist.json": fx.blocklist_text,
  "/lists/allowlist.json": fx.allowlist_text,
};
const base = { backendUrl: "http://b", bundled: BUNDLED, pubkey: fx.pubkey };

test("blocklist expressions equal Python's", () => {
  for (const c of parity.cases) assert.deepEqual(listUrlExpressions(c.url), c.expressions, c.url);
});

test("a signed manifest verifies; a changed one does not", async () => {
  assert.ok(await verifySignature(fx.manifest, fx.pubkey));
  const tampered = { ...fx.manifest, counts: { ...fx.manifest.counts, allowlist_domains: 1 } };
  assert.equal(await verifySignature(tampered, fx.pubkey), false);
  assert.equal(await verifySignature({ ...fx.manifest, signature: undefined }, fx.pubkey), false);
});

test("full sync checks file hashes and applies good lists", async () => {
  const { fetchFn } = backend(full);
  const res = await syncLists({ ...base, fetchFn, stored: null });
  assert.equal(res.status, "updated");
  assert.equal(res.via, "full");
  assert.deepEqual(res.lists.blocklist, BLOCK);
  assert.equal(res.lists.version, fx.manifest.version);
});

test("an unchanged version downloads nothing more", async () => {
  const { fetchFn, calls } = backend(full);
  const res = await syncLists({ ...base, fetchFn, stored: { version: fx.manifest.version } });
  assert.equal(res.status, "unchanged");
  assert.deepEqual(calls, ["/lists/manifest"]);
});

test("a delta rebuilds byte-identical lists", async () => {
  const rebuilt = applyDelta(fx.old, fx.delta);
  assert.equal(JSON.stringify(rebuilt.blocklist), fx.blocklist_text);
  assert.equal(JSON.stringify(rebuilt.allowlist), fx.allowlist_text);
  const { fetchFn, calls } = backend({ ...full, [`/lists/delta?from=${fx.old.version}`]: fx.delta });
  const res = await syncLists({ ...base, fetchFn, stored: fx.old });
  assert.equal(res.status, "updated");
  assert.equal(res.via, "delta");
  assert.ok(!calls.includes("/lists/blocklist.json"));
});

test("a bad delta falls back to the full download", async () => {
  const bad = structuredClone(fx.delta);
  bad.blocklist.domains.add.push("ff".repeat(8));
  const { fetchFn, calls } = backend({ ...full, [`/lists/delta?from=${fx.old.version}`]: bad });
  const res = await syncLists({ ...base, fetchFn, stored: fx.old });
  assert.equal(res.via, "full");
  assert.ok(calls.includes("/lists/blocklist.json"));
});

test("poisoned syncs are rejected", async () => {
  // a list file that does not match the signed manifest (the one-domain blocklist attack)
  const oneDomain = JSON.stringify({ ...BLOCK, domains: [BUNDLED.top[0].slice(0, 16)] });
  let res = await syncLists({ ...base, fetchFn: backend({ ...full, "/lists/blocklist.json": oneDomain }).fetchFn });
  assert.equal(res.status, "rejected");
  // a manifest whose signature does not verify (re-hashed to match a poisoned file)
  const forged = { ...fx.manifest, sha256: { ...fx.manifest.sha256, blocklist: await sha256Hex(oneDomain) } };
  res = await syncLists({ ...base, fetchFn: backend({ ...full, "/lists/manifest": forged, "/lists/blocklist.json": oneDomain }).fetchFn });
  assert.deepEqual([res.status, res.problems], ["rejected", ["manifest signature does not verify"]]);
});

test("sanity limits hold even for a correctly signed list", () => {
  const ok = { blocklist: BLOCK, allowlist: ALLOW };
  assert.deepEqual(checkLists(ok, { bundled: BUNDLED }), []);
  // blocks a top site by domain
  const topBlocked = { ...ok, blocklist: { ...BLOCK, domains: [...BLOCK.domains, BUNDLED.top[3].slice(0, 16)].sort() } };
  assert.match(checkLists(topBlocked, { bundled: BUNDLED }).join(), /most visited/);
  // allowlist shrunk to 10 entries
  const tiny = { ...ok, allowlist: { ...ALLOW, domains: ALLOW.domains.slice(0, 10) } };
  assert.match(checkLists(tiny, { bundled: BUNDLED }).join(), /allowlist shrank/);
  // blocklist lost most of its entries
  const stored = { blocklist: { ...BLOCK, urls: Array.from({ length: 200 }, (_, i) => i.toString(16).padStart(16, "0")) } };
  assert.match(checkLists(ok, { stored, bundled: BUNDLED }).join(), /blocklist shrank/);
  // malformed hashes
  const bad = { ...ok, blocklist: { ...BLOCK, urls: ["xyz"] } };
  assert.match(checkLists(bad, { bundled: BUNDLED }).join(), /malformed/);
});

test("without a bundled key, hash and sanity checks still apply", async () => {
  const oneDomain = JSON.stringify({ ...BLOCK, domains: [BUNDLED.top[0].slice(0, 16)] });
  const forged = { ...fx.manifest, sha256: { ...fx.manifest.sha256, blocklist: await sha256Hex(oneDomain) } };
  const { fetchFn } = backend({ ...full, "/lists/manifest": forged, "/lists/blocklist.json": oneDomain });
  const res = await syncLists({ ...base, pubkey: null, fetchFn });
  assert.equal(res.status, "rejected");
  assert.match(res.problems.join(), /most visited/);
});

test("backend down: failed, nothing applied", async () => {
  const res = await syncLists({ ...base, fetchFn: async () => { throw new Error("offline"); } });
  assert.equal(res.status, "failed");
});

test("remote config: signed, hashed and range-checked", async () => {
  let res = await fetchConfig({ ...base, fetchFn: backend({ "/config": fx.config }).fetchFn });
  assert.equal(res.status, "updated");
  assert.equal(res.config.thresholds.address.dangerous, 0.99);
  const edited = { ...fx.config, never_warn: ["paypal-login.com"] };
  res = await fetchConfig({ ...base, fetchFn: backend({ "/config": edited }).fetchFn });
  assert.equal(res.status, "rejected");
  res = await fetchConfig({ ...base, pubkey: null, fetchFn: backend({ "/config": edited }).fetchFn });
  assert.deepEqual(res.problems, ["config sha256 does not match"]);
  const cfg = { version: 1, list_sync_minutes: 60, never_warn: [], thresholds: { address: { suspicious: 0.95, dangerous: 0.9 }, page: { suspicious: null, dangerous: null } } };
  assert.match(checkConfig(cfg).join(), /below dangerous/);
  assert.match(checkConfig({ ...cfg, thresholds: { ...cfg.thresholds, address: { suspicious: 0.1, dangerous: null } }, list_sync_minutes: 1 }).join(), /list_sync_minutes/);
});
