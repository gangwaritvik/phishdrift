import assert from "node:assert/strict";
import { test } from "node:test";

import { hashPrefix, listDomainKey, listUrlKey } from "../dist/keys.js";
import { ListSet } from "../dist/lists.js";
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

test("empty or missing lists match nothing; unparsable URLs give no domain", async () => {
  const empty = new ListSet(null, { platforms, psl });
  assert.deepEqual(await empty.check("https://evil-login.com/"), {
    domain: "evil-login.com", shared: false, trustKey: "evil-login.com", allow: false, blocked: null,
  });
  assert.equal((await empty.check("")).domain, null);
  assert.equal(listDomainKey("http://192.168.0.1/x", psl), "192.168.0.1");
});
