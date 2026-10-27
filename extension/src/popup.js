const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
const send = (msg) => chrome.runtime.sendMessage({ ...msg, tabId: tab.id });
const $ = (id) => document.getElementById(id);
const HEADLINES = [
  ["safe", "No warning for this page"],
  ["suspicious", "This page looks suspicious"],
  ["dangerous", "This page looks dangerous"],
];

const result = tab ? await send({ type: "status" }) : null;
if (!result) {
  $("headline").textContent = "Nothing checked on this page";
  $("site").textContent = "PhishDrift checks web pages (http and https) as you open them.";
} else {
  const [cls, text] = HEADLINES[result.verdict];
  $("headline").textContent = text;
  $("headline").className = cls;
  $("site").textContent = result.domain ?? "";
  for (const reason of result.reasons) {
    const li = document.createElement("li");
    li.textContent = reason;
    $("reasons").append(li);
  }
  $("notes").textContent = result.notes.join(" ");
  $("trust").hidden = result.layer === "user-trusted" || result.layer === "allowlist";
  $("report").hidden = result.verdict === 0;
}

$("trust").addEventListener("click", async () => {
  const { ok } = await send({ type: "trust" });
  $("status").textContent = ok ? "Trusted. Reload the page to clear any warning." : "Could not save.";
});
$("report").addEventListener("click", async () => {
  const { ok } = await send({ type: "feedback", kind: "false_positive" });
  $("status").textContent = ok ? "Thanks. Only the website name was sent." : "Backend not reachable.";
});

// Opt-in switch for the backend's LLM brand check (settings.llmCheck, off by default).
const { settings } = await chrome.storage.local.get("settings");
$("llm").checked = settings?.llmCheck === true;
$("llm").addEventListener("change", async () => {
  const current = (await chrome.storage.local.get("settings")).settings ?? {};
  await chrome.storage.local.set({ settings: { ...current, llmCheck: $("llm").checked } });
  $("status").textContent = $("llm").checked ? "AI check on. It applies to the next page you open." : "AI check off.";
});

// Address of a hosted LLM check (settings.llmUrl); empty means the backend's own /llm-check.
$("llmUrl").value = settings?.llmUrl ?? "";
$("llmUrl").addEventListener("change", async () => {
  const value = $("llmUrl").value.trim();
  if (value && !/^https?:\/\//.test(value)) {
    $("status").textContent = "Enter an address starting with https://";
    return;
  }
  const current = (await chrome.storage.local.get("settings")).settings ?? {};
  await chrome.storage.local.set({ settings: { ...current, llmUrl: value } });
  $("status").textContent = value ? "AI check address saved." : "AI check uses your backend again.";
});

// Address of the hosted domain check (settings.tierCUrl, domain age / DNS / certificate); empty = off.
$("tierCUrl").value = settings?.tierCUrl ?? "";
$("tierCUrl").addEventListener("change", async () => {
  const value = $("tierCUrl").value.trim();
  if (value && !/^https?:\/\//.test(value)) {
    $("status").textContent = "Enter an address starting with https://";
    return;
  }
  const current = (await chrome.storage.local.get("settings")).settings ?? {};
  await chrome.storage.local.set({ settings: { ...current, tierCUrl: value } });
  $("status").textContent = value ? "Domain check on. Only the site's domain is sent." : "Domain check off.";
});
