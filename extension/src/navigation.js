// Small pure helpers for the service worker's tab handling (tested in Node).

// The worse of two results (higher verdict; the first on a tie).
export function worse(a, b) {
  if (!a) return b;
  if (!b) return a;
  return b.verdict > a.verdict ? b : a;
}

// "Take me back to safety": the most recent safe address of this tab on another site, else a new
// tab page. Never history.back(), which can land on the phishing page itself (or a redirect to it).
export function safeExit(seen, dangerousUrl, domainOf) {
  const bad = domainOf(dangerousUrl);
  for (const entry of [...(seen ?? [])].reverse()) {
    if (entry.url === dangerousUrl || !entry.domain || entry.domain === bad) continue;
    return entry.url;
  }
  return "chrome://newtab/";
}

