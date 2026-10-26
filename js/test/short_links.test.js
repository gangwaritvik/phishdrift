import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { handle, isPublicIp, isShortener, request } from "../../netlify/functions/expand.mjs";
import { expand, metaRefresh } from "../src/short_links.js";

const cfg = JSON.parse(readFileSync(new URL("../data/short_links.json", import.meta.url), "utf8"));

// url -> { status, location, body } for HEAD and GET alike unless keyed "GET url"
function fake(table, calls = []) {
  return async (url, method) => {
    calls.push(`${method} ${url}`);
    const r = table[`${method} ${url}`] ?? table[url];
    if (!r) throw new Error("unexpected request");
    return { location: null, body: "", ...r };
  };
}

test("follows shortener hops and never requests the destination", async () => {
  const calls = [];
  const req = fake({ "https://bit.ly/a": { status: 301, location: "https://tinyurl.com/b" }, "https://tinyurl.com/b": { status: 302, location: "/x?y=1" }, "https://tinyurl.com/x?y=1": { status: 302, location: "https://evil.example/login" } }, calls);
  const r = await expand("https://bit.ly/a", { isShortener, request: req, cfg });
  assert.equal(r.final, "https://evil.example/login");
  assert.equal(r.complete, true);
  assert.equal(r.hops.length, 3);
  assert.ok(calls.every((c) => !c.includes("evil.example")));
});

test("HEAD without a redirect falls back to GET and reads a meta refresh", async () => {
  const req = fake({ "HEAD https://bit.ly/m": { status: 405 }, "GET https://bit.ly/m": { status: 200, body: '<html><meta http-equiv="refresh" content="0; url=https://dest.example/p?a=1&amp;b=2">' } });
  const r = await expand("https://bit.ly/m", { isShortener, request: req, cfg });
  assert.deepEqual([r.final, r.complete], ["https://dest.example/p?a=1&b=2", true]);
  assert.equal(metaRefresh("<p>nothing</p>"), null);
});

test("stops at the hop limit, on a page that does not redirect, and on errors", async () => {
  const loop = fake({ "https://bit.ly/1": { status: 301, location: "https://bit.ly/1" } });
  assert.equal((await expand("https://bit.ly/1", { isShortener, request: loop, cfg })).error, "too_many_hops");
  const page = fake({ "https://bit.ly/p": { status: 200, body: "<p>hello</p>" } });
  assert.deepEqual(await expand("https://bit.ly/p", { isShortener, request: page, cfg }).then((r) => [r.complete, r.error, r.final]), [false, "no_redirect", "https://bit.ly/p"]);
  const bad = fake({ "https://bit.ly/j": { status: 302, location: "javascript:alert(1)" } });
  assert.equal((await expand("https://bit.ly/j", { isShortener, request: bad, cfg })).error, "bad_redirect");
  const dead = async () => {
    throw new Error("not_public_address");
  };
  assert.equal((await expand("https://bit.ly/d", { isShortener, request: dead, cfg })).error, "not_public_address");
});

test("whole chain shares one time limit", async () => {
  let t = 0;
  const slow = async (url) => {
    t += cfg.timeout_ms;
    return { status: 302, location: `${url}x`, body: "" };
  };
  const r = await expand("https://bit.ly/s", { isShortener, request: slow, cfg, now: () => t });
  assert.equal(r.error, "timeout");
});

test("private and reserved addresses are refused; public ones allowed", async () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "192.168.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1"]) assert.equal(isPublicIp(ip), false, ip);
  for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]) assert.equal(isPublicIp(ip), true, ip);
  await assert.rejects(request("http://localhost/", "HEAD", 2000), /not_public_address/);
  await assert.rejects(request("http://localhost:8080/", "HEAD", 2000), /port_not_allowed/);
});

const post = (body) => new Request("https://site.example/api/expand", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

test("function only expands shortener addresses", async () => {
  assert.equal((await handle(post({ url: "https://example.com/a" }))).status, 422);
  assert.equal((await handle(post({ url: "file:///etc/passwd" }))).status, 422);
  assert.equal((await handle(post({ url: "http://127.0.0.1/" }))).status, 422);
  assert.equal(isShortener("https://www.bit.ly/x"), true);
  const res = await handle(post({ url: "https://bit.ly/zz" }), { requestFn: fake({ "https://bit.ly/zz": { status: 301, location: "https://dest.example/" } }) });
  const body = await res.json();
  assert.deepEqual([res.status, body.final, body.complete, body.cached], [200, "https://dest.example/", true, false]);
  const again = await (await handle(post({ url: "https://bit.ly/zz" }), { requestFn: async () => assert.fail("cached") })).json();
  assert.equal(again.cached, true);
});
