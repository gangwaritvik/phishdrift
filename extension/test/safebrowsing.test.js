// Safe Browsing: canonical URLs and expressions (vectors from Google's "URLs and Hashing" spec),
// prefix lookup with a stub confirm, and the prefix-file sync.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { SafeBrowsing, canonicalize, expressions, fromBase64, syncSafeBrowsing, toBase64 } from "../dist/safebrowsing.js";
import { ListSet } from "../dist/lists.js";
import { buildTrie } from "../dist/lib/psl.js";
import { psl as loadPsl } from "./helpers.js";

const canon = (url) => {
  const { host, path, query } = canonicalize(url);
  return host + path + (query === null ? "" : `?${query}`);
};

test("canonical URLs match the spec's vectors", () => {
  const cases = {
    "http://host/%25%32%35": "host/%25",
    "http://host/%25%32%35%25%32%35": "host/%25%25",
    "http://host/%2525252525252525": "host/%25",
    "http://host/asdf%25%32%35asd": "host/asdf%25asd",
    "http://host/%%%25%32%35asd%%": "host/%25%25%25asd%25%25",
    "http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/": "168.188.99.26/.secure/www.ebay.com/",
    "http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B": "host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+",
    "http://www.google.com/blah/..": "www.google.com/",
    "www.google.com/": "www.google.com/",
    "www.google.com": "www.google.com/",
    "http://www.evil.com/blah#frag": "www.evil.com/blah",
    "http://www.GOOgle.com/": "www.google.com/",
    "http://www.google.com.../": "www.google.com/",
    "http://www.google.com/foo\tbar\rbaz\n2": "www.google.com/foobarbaz2",
    "http://www.google.com/q?": "www.google.com/q?",
    "http://www.google.com/q?r?": "www.google.com/q?r?",
    "http://www.google.com/q?r?s": "www.google.com/q?r?s",
    "http://evil.com/foo#bar#baz": "evil.com/foo",
    "http://evil.com/foo;": "evil.com/foo;",
    "http://evil.com/foo?bar;": "evil.com/foo?bar;",
    "http://notrailingslash.com": "notrailingslash.com/",
    "http://www.gotaport.com:1234/": "www.gotaport.com/",
    "  http://www.google.com/  ": "www.google.com/",
    "http:// leadingspace.com/": "%20leadingspace.com/",
    "http://%20leadingspace.com/": "%20leadingspace.com/",
    "%20leadingspace.com/": "%20leadingspace.com/",
    "https://www.securesite.com/": "www.securesite.com/",
    "http://host.com/ab%23cd": "host.com/ab%23cd",
    "http://host.com//twoslashes?more//slashes": "host.com/twoslashes?more//slashes",
  };
  for (const [input, want] of Object.entries(cases)) assert.equal(canon(input), want, input);
});

test("expressions match the spec's examples", () => {
  assert.deepEqual(expressions("http://a.b.c/1/2.html?param=1"), [
    "a.b.c/1/2.html?param=1", "a.b.c/1/2.html", "a.b.c/", "a.b.c/1/",
    "b.c/1/2.html?param=1", "b.c/1/2.html", "b.c/", "b.c/1/",
  ]);
  assert.deepEqual(expressions("http://a.b.c.d.e.f.g/1.html"), [
    "a.b.c.d.e.f.g/1.html", "a.b.c.d.e.f.g/", "c.d.e.f.g/1.html", "c.d.e.f.g/", "d.e.f.g/1.html",
    "d.e.f.g/", "e.f.g/1.html", "e.f.g/", "f.g/1.html", "f.g/",
  ]);
  assert.deepEqual(expressions("http://1.2.3.4/1/"), ["1.2.3.4/1/", "1.2.3.4/"]);
});

const sha = (s) => createHash("sha256").update(Buffer.from(s, "latin1")).digest();
const fileOf = (exprs) => {
  const prefixes = exprs.map((e) => sha(e).subarray(0, 4).toString("hex")).sort();
  return Uint8Array.from(Buffer.from(prefixes.join(""), "hex"));
};

test("a prefix hit counts only when the full hash is confirmed", async () => {
  const sb = new SafeBrowsing(fileOf(["evil.example/login/", "zzz.test/"]));
  const asked = [];
  const confirmYes = async (prefix) => {
    asked.push(prefix);
    return [sha("evil.example/login/").toString("hex")];
  };
  assert.equal(await sb.match("https://evil.example/login/step?x=1", confirmYes), "evil.example/login/");
  assert.deepEqual(asked, [sha("evil.example/login/").subarray(0, 4).toString("hex")]);
  assert.equal(await sb.match("https://fine.example/", confirmYes), null);
  assert.equal(asked.length, 1, "no prefix hit, no backend call");
  assert.equal(await sb.match("https://evil.example/login/", async () => ["00".repeat(32)]), null, "a prefix collision is not a hit");
  assert.equal(await sb.match("https://evil.example/login/", async () => { throw new Error("down"); }), null, "a failed confirm is not a hit");
});

test("a Safe Browsing hit blocks even an allowlisted site", async () => {
  const psl = buildTrie(loadPsl());
  const sb = new SafeBrowsing(fileOf(["good.example/bad/"]));
  const confirm = async () => [sha("good.example/bad/").toString("hex")];
  const allow = { allowlist: { prefix_bytes: 16, domains: [], open_hosting: [] }, blocklist: { prefix_bytes: 8, domains: [], urls: [] } };
  const lists = new ListSet(allow, { platforms: new Set(), psl, safebrowsing: sb, confirm });
  assert.equal((await lists.check("https://good.example/bad/page")).blocked, "url");
  assert.equal((await lists.check("https://good.example/ok")).blocked, null);
});

test("prefix file sync", async () => {
  const bytes = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
  const reply = (status, body, etag) => async () => ({ status, ok: status < 300, headers: new Map([["ETag", etag]]), arrayBuffer: async () => body.buffer });
  const first = await syncSafeBrowsing({ backendUrl: "x", fetchFn: reply(200, bytes, '"a"') });
  assert.equal(first.status, "updated");
  assert.deepEqual([...fromBase64(first.stored.b64)], [...bytes]);
  assert.equal(first.stored.etag, '"a"');
  assert.equal((await syncSafeBrowsing({ backendUrl: "x", fetchFn: reply(304) , stored: first.stored })).status, "unchanged");
  assert.equal((await syncSafeBrowsing({ backendUrl: "x", fetchFn: reply(404) })).status, "none");
  assert.equal((await syncSafeBrowsing({ backendUrl: "x", fetchFn: reply(200, Uint8Array.from([1, 2, 3]), '"b"') })).status, "rejected");
  const big = { etag: '"c"', b64: toBase64(new Uint8Array(4 * 20000)) };
  assert.equal((await syncSafeBrowsing({ backendUrl: "x", stored: big, fetchFn: reply(200, new Uint8Array(4 * 100), '"d"') })).status, "rejected");
  assert.equal((await syncSafeBrowsing({ backendUrl: "x", fetchFn: async () => { throw new Error("offline"); } })).status, "failed");
});
