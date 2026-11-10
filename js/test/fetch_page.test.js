// The hosted page fetch (netlify/functions/fetch-page.mjs): what it refuses, how it follows redirects,
// and the real request() against a local server (gzip, size cap, redirects not followed by request()).

import assert from "node:assert/strict";
import http from "node:http";
import { gzipSync } from "node:zlib";
import { test } from "node:test";

import served, { RATE, fetchPage, handle, overLimit, request } from "../../netlify/functions/fetch-page.mjs";

const html = (body = "<p>hello</p>") => ({ status: 200, location: null, contentType: "text/html; charset=utf-8", body: Buffer.from(body), truncated: false });
const post = (body) => new Request("https://x.example/api/fetch-page", { method: "POST", body: typeof body === "string" ? body : JSON.stringify(body) });
const answer = async (body, deps) => (await handle(post(body), deps)).json();

test("a plain page comes back with its text", async () => {
  const r = await fetchPage("https://example.com/a", { requestFn: async () => html("<title>Hi</title>") });
  assert.equal(r.ok, true);
  assert.equal(r.html, "<title>Hi</title>");
  assert.equal(r.final, "https://example.com/a");
  assert.deepEqual(r.redirects, []);
});

test("the character set in the header is used", async () => {
  const latin = { ...html(), contentType: "text/html; charset=iso-8859-1", body: Buffer.from([0x63, 0x61, 0x66, 0xe9]) };
  assert.equal((await fetchPage("https://example.com/", { requestFn: async () => latin })).html, "café");
});

test("a redirect is followed, and every hop is checked again", async () => {
  const seen = [];
  const requestFn = async (url) => {
    seen.push(url);
    return url.endsWith("/a") ? { status: 302, location: "/b", contentType: "", body: Buffer.alloc(0) } : html();
  };
  const r = await fetchPage("https://example.com/a", { requestFn });
  assert.deepEqual(seen, ["https://example.com/a", "https://example.com/b"]);
  assert.equal(r.final, "https://example.com/b");
  assert.equal(r.redirects.length, 1);

  const toPrivate = async () => ({ status: 302, location: "http://169.254.169.254/latest/meta-data/", contentType: "", body: Buffer.alloc(0) });
  const blocked = await fetchPage("https://example.com/a", { requestFn: toPrivate });
  assert.equal(blocked.ok, false);
  assert.equal(blocked.error, "not_public_address");
});

test("a redirect loop stops", async () => {
  const loop = async (url) => ({ status: 302, location: `${url}x`, contentType: "", body: Buffer.alloc(0) });
  const r = await fetchPage("https://example.com/a", { requestFn: loop });
  assert.equal(r.error, "too_many_redirects");
});

test("only an HTML answer is returned", async () => {
  const pdf = async () => ({ ...html(), contentType: "application/pdf" });
  const r = await fetchPage("https://example.com/a.pdf", { requestFn: pdf });
  assert.equal(r.ok, false);
  assert.equal(r.error, "not_html");
});

test("a failed request is reported, not thrown", async () => {
  const r = await fetchPage("https://example.com/", { requestFn: async () => Promise.reject(Object.assign(new Error("x"), { code: "ENOTFOUND" })) });
  assert.deepEqual([r.ok, r.error], [false, "ENOTFOUND"]);
});

test("the time limit covers the whole fetch", async () => {
  let t = 0;
  const now = () => t;
  const slow = async (url) => {
    t += 20_000;
    return { status: 302, location: `${url}x`, contentType: "", body: Buffer.alloc(0) };
  };
  assert.equal((await fetchPage("https://example.com/a", { requestFn: slow, now })).error, "timeout");
});

test("private, local and odd addresses are refused before any request", async () => {
  const never = async () => assert.fail("a request was made");
  for (const url of [
    "http://127.0.0.1/", "http://10.0.0.5/admin", "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/", "http://[fd00::1]/", "http://2130706433/", "http://0x7f.1/", "https://example.com:8443/", "http://example.com:22/",
  ]) {
    const r = await fetchPage(url, { requestFn: never });
    assert.equal(r.ok, false, url);
    assert.match(r.error, /not_public_address|port_not_allowed/, url);
  }
});

test("a name that resolves to this machine is refused when the connection is made", async () => {
  const r = await fetchPage("http://localhost/", {});
  assert.equal(r.ok, false);
  assert.match(r.error, /not_public_address|ECONN|ENOTFOUND/);
});

test("bad input is turned away", async () => {
  assert.equal((await handle(new Request("https://x.example/", { method: "GET" }))).status, 405);
  assert.equal((await handle(post("not json"))).status, 422);
  assert.equal((await handle(post({ url: "ftp://example.com/" }))).status, 422);
  assert.equal((await handle(post({ url: "x".repeat(5000) }))).status, 413);
  assert.equal((await handle(new Request("https://x.example/", { method: "OPTIONS" }))).status, 204);
});

test("the wrapper returns the same fields", async () => {
  const r = await answer({ url: "https://example.com/" }, { requestFn: async () => html() });
  assert.deepEqual([r.ok, r.status, r.html], [true, 200, "<p>hello</p>"]);
});

// the real request() against a server on this machine (fetchPage would refuse the address; request() does not look at it)
function server(handler) {
  return new Promise((resolve) => {
    const s = http.createServer(handler).listen(0, "127.0.0.1", () => resolve({ s, url: `http://127.0.0.1:${s.address().port}/` }));
  });
}

test("request(): gzip is decoded, a redirect is returned and not followed", async () => {
  const { s, url } = await server((req, res) => {
    if (req.url === "/go") return res.writeHead(302, { Location: "http://169.254.169.254/" }).end();
    res.writeHead(200, { "Content-Type": "text/html", "Content-Encoding": "gzip" }).end(gzipSync("<p>zipped</p>"));
  });
  try {
    const page = await request(url, 2000);
    assert.equal(page.body.toString(), "<p>zipped</p>");
    const redirect = await request(`${url}go`, 2000);
    assert.equal(redirect.location, "http://169.254.169.254/");
    assert.equal(redirect.body.length, 0);
  } finally {
    s.close();
  }
});

test("request(): a huge answer is cut at the size cap, also when compressed", async () => {
  const big = "a".repeat(3_000_000);
  const { s, url } = await server((req, res) => {
    if (req.url === "/gz") return res.writeHead(200, { "Content-Type": "text/html", "Content-Encoding": "gzip" }).end(gzipSync(big));
    res.writeHead(200, { "Content-Type": "text/html" }).end(big);
  });
  try {
    for (const path of ["", "gz"]) {
      const r = await request(`${url}${path}`, 5000);
      assert.equal(r.truncated, true, path);
      assert.equal(r.body.length, 1_500_000, path);
    }
  } finally {
    s.close();
  }
});

test("request(): a slow server is cut off at the time limit", async () => {
  const { s, url } = await server(() => {}); // never answers
  try {
    await assert.rejects(request(url, 200), /timeout/);
  } finally {
    s.closeAllConnections();
    s.close();
  }
});

test("the per-address counter allows RATE.limit fetches a minute, then refuses until the minute has passed", () => {
  const seen = new Map();
  for (let i = 0; i < RATE.limit; i++) assert.equal(overLimit("1.2.3.4", 1000 + i, seen), false);
  assert.equal(overLimit("1.2.3.4", 2000, seen), true);
  assert.equal(overLimit("5.6.7.8", 2000, seen), false); // another address has its own count
  assert.equal(overLimit("1.2.3.4", 1000 + RATE.window_s * 1000 + RATE.limit, seen), false);
  assert.equal(seen.has("5.6.7.8"), true);
  overLimit("9.9.9.9", 1000 + 10 * RATE.window_s * 1000, seen); // old addresses are dropped
  assert.equal(seen.has("5.6.7.8"), false);
});

test("the served function answers 429 once an address is over the limit", async () => {
  const call = () => served(new Request("https://x.example/api/fetch-page", { method: "POST", body: "not json", headers: { "x-nf-client-connection-ip": "203.0.113.7" } }));
  for (let i = 0; i < RATE.limit; i++) assert.equal((await call()).status, 422);
  assert.equal((await call()).status, 429);
});
