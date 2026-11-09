import assert from "node:assert/strict";
import { test } from "node:test";

import { llmEndpoint, sanitizeSettings } from "../src/config.js";

test("the LLM check goes to the hosted address when set, else the backend", () => {
  assert.equal(llmEndpoint(sanitizeSettings({})), "http://127.0.0.1:8000/llm-check");
  assert.equal(llmEndpoint(sanitizeSettings({ backendUrl: "https://b.example/" })), "https://b.example/llm-check");
  const hosted = sanitizeSettings({ llmUrl: "https://demo.netlify.app/llm-check/" });
  assert.equal(llmEndpoint(hosted), "https://demo.netlify.app/llm-check");
  for (const bad of ["", "ftp://x/y", "https://u:p@x.com/llm-check", "not a url", 5]) {
    assert.equal(sanitizeSettings({ llmUrl: bad }).llmUrl, "", String(bad));
  }
});

test("the domain check is on by default, can be switched off, and a bad address falls back to the default", () => {
  const dflt = sanitizeSettings({});
  assert.equal(dflt.tierC, true);
  assert.match(dflt.tierCUrl, /^https:\/\/.+\/api\/domain-check$/);
  assert.equal(sanitizeSettings({ tierC: false }).tierC, false);
  assert.equal(sanitizeSettings({ tierC: "no" }).tierC, true);
  assert.equal(sanitizeSettings({ tierCUrl: "https://demo.netlify.app/api/domain-check/" }).tierCUrl, "https://demo.netlify.app/api/domain-check");
  for (const bad of ["", "ftp://x/y", "https://u:p@x.com/a", "not a url", 5]) assert.equal(sanitizeSettings({ tierCUrl: bad }).tierCUrl, dflt.tierCUrl, String(bad));
  assert.equal(sanitizeSettings({ tierCTimeoutMs: 100 }).tierCTimeoutMs, 12_000);
});
