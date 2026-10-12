const tabId = Number(new URLSearchParams(location.search).get("tab"));
const send = (msg) => chrome.runtime.sendMessage({ ...msg, tabId });
const $ = (id) => document.getElementById(id);

const result = await send({ type: "status" });
if (result) {
  $("target").textContent = result.url;
  const reasons = result.reasons.length ? result.reasons : ["The address looks like a phishing address."];
  for (const text of reasons) {
    const li = document.createElement("li");
    li.textContent = text;
    $("reasons").append(li);
  }
  $("note").textContent = result.notes.join(" ");
}

$("back").addEventListener("click", () => {
  if (history.length > 1) history.back();
  else window.close();
});
$("proceed").addEventListener("click", async () => {
  const { ok, url } = await send({ type: "bypass" });
  if (ok) location.replace(url);
});
$("report").addEventListener("click", async () => {
  const { ok } = await send({ type: "feedback", kind: "false_positive" });
  $("status").textContent = ok
    ? "Thanks. Only the website name was sent."
    : "Could not send the report (the backend is not reachable).";
});
