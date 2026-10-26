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
