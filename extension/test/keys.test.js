// Python/JavaScript parity for the list keys and hashes: tests/fixtures/list_key_parity.json is
// written by backend/make_fixture.py from backend/lists.py.

import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { test } from "node:test";

import { hashPrefix, listDomainKey, listUrlKey } from "../dist/keys.js";
import { buildTrie } from "../dist/lib/psl.js";
import { psl as loadPsl } from "./helpers.js";

const fixture = new URL("../../tests/fixtures/list_key_parity.json", import.meta.url);

test("list keys and hashes equal Python's", { skip: !existsSync(fixture) }, async () => {
  const { cases, prefix_bytes: bytes } = JSON.parse(readFileSync(fixture, "utf8"));
  const psl = buildTrie(loadPsl());
  assert.ok(cases.length >= 60);
  const failures = [];
  for (const c of cases) {
    const got = {
      url_key: listUrlKey(c.url),
      domain_key: listDomainKey(c.url, psl),
      url_hash: await hashPrefix(listUrlKey(c.url), bytes),
      domain_hash: await hashPrefix(listDomainKey(c.url, psl), bytes),
    };
    for (const k of Object.keys(got)) {
      if (got[k] !== c[k]) failures.push(`${JSON.stringify(c.url)} ${k}: ${got[k]} vs ${c[k]}`);
    }
  }
  assert.equal(failures.length, 0, failures.slice(0, 20).join("\n"));
});

test("hash prefix is the first bytes of sha256", async () => {
  // sha256("abc") = ba7816bf 8f01cfea ...
  assert.equal(await hashPrefix("abc", 4), "ba7816bf");
});
