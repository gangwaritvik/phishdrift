import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { handle } from "../../netlify/functions/llm-check.mjs";
import { buildPrompt, cleanWords, judge, makeTrie, parse } from "../src/llm_check.js";

const read = (p) => JSON.parse(readFileSync(new URL(p, import.meta.url), "utf8"));
const cfg = read("../data/llm_check.json");
const psl = makeTrie(read("../data/psl_icann.json"));
const cases = read("../../tests/fixtures/llm_parity.json");

test("prompt, parse and verdict match backend/llm.py", () => {
  for (const c of cases) {
    assert.equal(buildPrompt(c.host, cleanWords(c.words, cfg.max_path_words)), c.prompt, c.text);
    const parsed = parse(c.text);
    assert.deepEqual(parsed, c.parsed, c.text);
    assert.deepEqual(judge(c.host, parsed, cfg.min_confidence, cfg.phishing_min, psl), c.judged, c.text);
  }
});

const post = (body) =>
  new Request("https://site.example/api/llm-check", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

function gemini(text, calls = []) {
  return async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text }] } }] }), { status: 200 });
  };
}

test("function: no key means disabled, and nothing is asked", async () => {
  const calls = [];
  const res = await handle(post({ domain: "paypa1.com" }), { env: {}, fetchFn: gemini("{}", calls) });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).error, "disabled");
  assert.equal(calls.length, 0);
});

test("function: asks Gemini with the key in a header, judges, caches", async () => {
  const calls = [];
  const answer = '{"brand": "PayPal", "brand_domain": "paypal.com", "confidence": 0.9, "phishing": 0.3, "reason": "r"}';
  const opts = { env: { GEMINI_API_KEY: "k-test" }, fetchFn: gemini(answer, calls) };
  const first = await (await handle(post({ domain: "PayPa1-secure.com" }), opts)).json();
  assert.deepEqual(first, { raise: true, kind: "brand", brand: "PayPal", brand_domain: "paypal.com", confidence: 0.9, phishing: 0.3, error: null, cached: false });
  assert.equal(calls[0].init.headers["x-goog-api-key"], "k-test");
  assert.ok(!calls[0].url.includes("k-test") && !calls[0].init.body.includes("k-test"));
  assert.ok(calls[0].url.includes(cfg.model));
  const again = await (await handle(post({ domain: "paypa1-secure.com" }), opts)).json();
  assert.equal(again.cached, true);
  assert.equal(calls.length, 1);
});

test("function: provider errors and bad answers give no opinion and are not cached", async () => {
  const env = { GEMINI_API_KEY: "k" };
  const down = async () => new Response('{"error": {"message": "quota"}}', { status: 429 });
  const r1 = await (await handle(post({ domain: "a-down.com" }), { env, fetchFn: down })).json();
  assert.equal(r1.error, "provider_failed");
  assert.match(r1.detail, /HTTP 429: quota/);
  assert.equal(r1.raise, false);
  const r2 = await (await handle(post({ domain: "a-down.com" }), { env, fetchFn: gemini("nonsense") })).json();
  assert.equal(r2.error, "bad_answer");
  assert.equal(r2.cached, false);
});

test("function: rejects bad input and answers CORS preflight", async () => {
  const env = { GEMINI_API_KEY: "k" };
  for (const body of [{ domain: "https://x.com/a" }, { domain: "x" }, { domain: 5 }, { domain: "x.com", path_words: "a" }]) {
    assert.equal((await handle(post(body), { env })).status, 422, JSON.stringify(body));
  }
  const bad = new Request("https://s/api/llm-check", { method: "POST", body: "{" });
  assert.equal((await handle(bad, { env })).status, 400);
  const pre = await handle(new Request("https://s/api/llm-check", { method: "OPTIONS" }), { env });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get("access-control-allow-origin"), "*");
  assert.equal((await handle(new Request("https://s/api/llm-check"), { env })).status, 405);
});

test("function: daily cap per instance", async () => {
  const env = { GEMINI_API_KEY: "k" };
  const calls = [];
  const fetchFn = gemini("nonsense", calls); // bad answers are not cached, so every request asks
  const now = () => Date.parse("2030-01-02T00:00:00Z");
  let last;
  for (let i = 0; i <= cfg.max_calls_per_day; i++) last = await (await handle(post({ domain: "cap.com" }), { env, fetchFn, now })).json();
  assert.equal(last.error, "daily_cap");
  assert.equal(calls.length, cfg.max_calls_per_day);
});

test("function: a model without quota is replaced by the next fallback model", async () => {
  const urls = [];
  const answer = '{"brand": null, "brand_domain": null, "confidence": 0.1, "phishing": 0.1, "reason": "r"}';
  const fetchFn = async (url) => {
    urls.push(url);
    return urls.length === 1
      ? new Response('{"error": {"message": "quota"}}', { status: 429 })
      : new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: answer }] } }] }), { status: 200 });
  };
  const r = await (await handle(post({ domain: "fallback-test.com" }), { env: { GEMINI_API_KEY: "k" }, fetchFn })).json();
  assert.equal(r.error, null);
  assert.equal(urls.length, 2);
  assert.ok(urls[0].includes(cfg.model) && urls[1].includes(cfg.fallback_models[0]));
});

test("function: a model that does not answer in its share of the time is replaced by the next one", async () => {
  const seen = [];
  const answer = '{"brand": null, "brand_domain": null, "confidence": 0, "phishing": 0.1, "reason": "r"}';
  const fetchFn = async (url, init) => {
    seen.push(url);
    if (seen.length === 1) {
      await new Promise((_, rej) => init.signal.addEventListener("abort", () => rej(init.signal.reason)));
    }
    return new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: answer }] } }] }), { status: 200 });
  };
  const keepAlive = setTimeout(() => {}, 15000); // AbortSignal.timeout timers do not hold the event loop
  const r = await (await handle(post({ domain: "slow-first.com" }), { env: { GEMINI_API_KEY: "k" }, fetchFn })).json();
  clearTimeout(keepAlive);
  assert.equal(r.error, null);
  assert.equal(seen.length, 2);
});
