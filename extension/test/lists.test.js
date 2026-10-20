import assert from "node:assert/strict";
import { test } from "node:test";

import { hashPrefix, listDomainKey, listUrlKey } from "../dist/keys.js";
import { readFileSync } from "node:fs";

import { inZone, ListSet, withBundledAllowlist } from "../dist/lists.js";
import { psl as loadPsl } from "./helpers.js";
import { buildTrie } from "../dist/lib/psl.js";

const psl = buildTrie(loadPsl());
const BYTES = 6;
const h = (key) => hashPrefix(key, BYTES);
const platforms = new Set(["github.io"]);

async function lists() {
  return new ListSet(
    {
      blocklist: {
        prefix_bytes: BYTES,
        domains: [await h("evil-login.com")],
        urls: [await h(listUrlKey("https://badguy.github.io/login/"))],
      },
      allowlist: { prefix_bytes: BYTES, domains: [await h("example.com")] },
    },
    { platforms, psl },
  );
}

test("domain blocklist and allowlist match on the registrable domain", async () => {
  const set = await lists();
  const hit = await set.check("https://www.sub.evil-login.com/a?b=1");
  assert.deepEqual([hit.domain, hit.blocked, hit.allow], ["evil-login.com", "domain", false]);
  const ok = await set.check("http://EXAMPLE.com/x");
  assert.deepEqual([ok.blocked, ok.allow], [null, true]);
  assert.deepEqual((await set.check("https://other.org/")).blocked, null);
});

test("shared hosting matches the full URL only and is never allowlisted", async () => {
  const set = await lists();
  const bad = await set.check("http://badguy.github.io/login");
  assert.deepEqual([bad.shared, bad.blocked, bad.allow, bad.trustKey], [true, "url", false, "badguy.github.io"]);
  const other = await set.check("https://goodguy.github.io/login/");
  assert.equal(other.blocked, null);
});

test("open-hosting zones lift the allowlist inside the zone only", async () => {
  const set = new ListSet(
    {
      blocklist: {
        prefix_bytes: BYTES,
        domains: [],
        urls: [await h(listUrlKey("https://tenant.swedencentral.cloudapp.azure.com/ch/login"))],
      },
      allowlist: {
        prefix_bytes: BYTES,
        domains: [await h("azure.com"), await h("google.com")],
        open_hosting: ["cloudapp.azure.com", "drive.google.com"],
      },
    },
    { platforms, psl },
  );
  const bad = await set.check("https://tenant.swedencentral.cloudapp.azure.com/ch/login");
  assert.deepEqual([bad.shared, bad.blocked, bad.allow], [true, "url", false]);
  const other = await set.check("https://new.westeurope.cloudapp.azure.com/");
  assert.deepEqual([other.shared, other.blocked, other.allow], [true, null, false]);
  const drive = await set.check("https://drive.google.com/file/d/x");
  assert.deepEqual([drive.shared, drive.allow, drive.trustKey], [true, false, "drive.google.com"]);
  assert.equal((await set.check("https://portal.azure.com/")).allow, true);
  assert.equal((await set.check("https://www.google.com/search?q=x")).allow, true);
});

test("a full-URL entry matches on any domain, also an allowlisted one", async () => {
  const set = new ListSet(
    {
      blocklist: { prefix_bytes: BYTES, domains: [], urls: [await h(listUrlKey("https://github.com/x/y/raw/a.exe"))] },
      allowlist: { prefix_bytes: BYTES, domains: [await h("github.com")], open_hosting: [] },
    },
    { platforms, psl },
  );
  const bad = await set.check("https://github.com/x/y/raw/a.exe");
  assert.deepEqual([bad.shared, bad.blocked, bad.allow], [false, "url", true]);
  const ok = await set.check("https://github.com/x/y");
  assert.deepEqual([ok.blocked, ok.allow], [null, true]);
});

test("inZone matches a zone and hosts below it, never a longer label", () => {
  const zones = new Set(["cloudapp.azure.com"]);
  assert.equal(inZone("cloudapp.azure.com", zones), true);
  assert.equal(inZone("a.b.cloudapp.azure.com", zones), true);
  assert.equal(inZone("xcloudapp.azure.com", zones), false);
  assert.equal(inZone("portal.azure.com", zones), false);
});

test("empty or missing lists match nothing; unparsable URLs give no domain", async () => {
  const empty = new ListSet(null, { platforms, psl });
  assert.deepEqual(await empty.check("https://evil-login.com/"), {
    domain: "evil-login.com", shared: false, shortener: false, trustKey: "evil-login.com", allow: false, blocked: null,
  });
  assert.equal((await empty.check("")).domain, null);
  assert.equal(listDomainKey("http://192.168.0.1/x", psl), "192.168.0.1");
});

test("the bundled allowlist applies until a synced one exists, and covers big sites", async () => {
  const bundled = JSON.parse(readFileSync(new URL("../dist/data/allowlist.json", import.meta.url)));
  const set = new ListSet(withBundledAllowlist(null, bundled), { platforms, psl });
  for (const url of ["https://web.whatsapp.com/", "https://www.google.com/search?q=x"]) {
    assert.equal((await set.check(url)).allow, true, url);
  }
  assert.equal((await set.check("https://badguy.github.io/")).allow, false);
  const synced = { allowlist: { prefix_bytes: BYTES, domains: [await h("example.com")] } };
  assert.equal(withBundledAllowlist(synced, bundled), synced);
  const blockOnly = { blocklist: { prefix_bytes: BYTES, domains: [], urls: [] }, allowlist: { domains: [] } };
  assert.equal(withBundledAllowlist(blockOnly, bundled).allowlist, bundled);
  const google = await h("google.com");
  const blocked = { blocklist: { prefix_bytes: BYTES, domains: [google], urls: [] } };
  const merged = withBundledAllowlist(blocked, bundled).allowlist.domains;
  assert.equal(merged.includes(google), false);
  assert.equal(merged.length, bundled.domains.length - 1);
});

test("a shortener is never allowlisted, even when its domain is on the allowlist", async () => {
  const set = new ListSet(
    { allowlist: { prefix_bytes: BYTES, domains: [await h("t.co"), await h("example.com")] } },
    { platforms, psl, shorteners: new Set(["t.co"]) },
  );
  const short = await set.check("https://t.co/AbC123");
  assert.deepEqual([short.shortener, short.allow], [true, false]);
  const site = await set.check("https://example.com/");
  assert.deepEqual([site.shortener, site.allow], [false, true]);
});

test("a popular tenant site on a platform is allowlisted by its exact host, a sibling is not", async () => {
  const set = new ListSet(
    {
      blocklist: { prefix_bytes: BYTES, domains: [], urls: [await h(listUrlKey("https://stitch.withgoogle.com/login/x"))] },
      allowlist: { prefix_bytes: BYTES, domains: [await h("stitch.withgoogle.com")] },
    },
    { platforms: new Set(["withgoogle.com"]), psl },
  );
  const ok = await set.check("https://stitch.withgoogle.com/projects/1?pli=1");
  assert.deepEqual([ok.shared, ok.allow, ok.blocked], [true, true, null]);
  assert.equal((await set.check("https://evil.withgoogle.com/")).allow, false);
  assert.equal((await set.check("https://withgoogle.com/")).allow, false);
  // an exact listed phishing URL on that host still wins over the allowlist
  assert.equal((await set.check("https://stitch.withgoogle.com/login/x")).blocked, "url");
});
