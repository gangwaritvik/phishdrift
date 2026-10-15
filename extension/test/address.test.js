import assert from "node:assert/strict";
import { test } from "node:test";

import { ERROR_REASON, LONG_URL_REASON, MAX_URL_CHARS, scoreAddress } from "../dist/address.js";
import { SAFE, SUSPICIOUS } from "../dist/combine.js";
import { loadHybrid } from "../dist/lib/hybrid.js";
import { psl, readDist } from "./helpers.js";

const model = loadHybrid(readDist("data/tier_a_hybrid.json"), psl());

test("a huge address gets a soft warning instead of switching the check off", () => {
  const words = Array.from({ length: 200_000 }, (_, i) => `w${i % 10}`).join("/");
  const r = scoreAddress(model, `https://example.org/${words}`);
  assert.deepEqual([r.verdict, r.reasons[0].text], [SUSPICIOUS, LONG_URL_REASON]);
});

test("an address just under the cap with ~5k path words is scored by the model", () => {
  const url = `https://example.org/${Array.from({ length: 5_000 }, () => "ab").join("/")}`;
  assert.ok(url.length < MAX_URL_CHARS);
  const r = scoreAddress(model, url);
  assert.ok(r.prob !== null && r.verdict >= SAFE);
});

test("a scoring error gives a soft warning", () => {
  const broken = { ...model, names: null };
  const r = scoreAddress(broken, "https://example.org/");
  assert.deepEqual([r.verdict, r.reasons[0].text], [SUSPICIOUS, ERROR_REASON]);
});
