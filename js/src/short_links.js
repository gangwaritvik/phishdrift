// Follows a short link to the address it leads to, without opening that address: hops are
// requested only while the current address is on a link shortener, and the first address off a
// shortener is returned unvisited, for the normal checks. Used by the Netlify Function
// (netlify/functions/expand.mjs) for the online URL check page; settings come from
// js/data/short_links.json (python -m backend export-llm-js, block short_links in
// configs/backend.yaml).
//
// request(url, method, ms) -> { status, location, body, headers } does one request without following
// redirects or running anything (body: the first bytes of a GET, or ""; headers: lower-case names);
// it throws on failure.

const META_REFRESH = /<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["']\s*\d*\s*[;,]\s*url\s*=\s*['"]?([^"'>\s]+)/i;

// The address a page sends the browser to with <meta http-equiv="refresh">, or null.
export function metaRefresh(body) {
  const m = META_REFRESH.exec(body ?? "");
  return m ? m[1].replace(/&amp;/g, "&") : null;
}

// Some shortener services answer a link they have stopped redirecting (tinyurl.com: "no spam" page)
// with a redirect to their own warning page, and name the real destination in a response header of
// that same answer (observed: x-lighttpd-longurl). Any header named x-...longurl is read as that
// statement; it is only an address to check, never requested.
export function headerDestination(headers) {
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (/^x-[a-z-]*longurl$/.test(name.toLowerCase()) && typeof value === "string") return value;
  }
  return null;
}

function webAddress(text, base) {
  try {
    const u = new URL(text, base);
    return u.protocol === "http:" || u.protocol === "https:" ? u.href : null;
  } catch {
    return null;
  }
}

// { final, complete, hops: [{ url, status, method }], error }
// complete: final is off every shortener (the destination); otherwise final is the last address
// reached and error says why it stopped (no_redirect: the link's page does not redirect; service_page:
// the shortener sent the link on to one of its own pages that does not redirect, usually a warning,
// preview or removed-link page; too_many_hops, timeout, bad_redirect, or the request's own error).
export async function expand(start, { isShortener, request, cfg, now = Date.now }) {
  const deadline = now() + cfg.timeout_ms;
  const hops = [];
  let url = start;
  for (let hop = 0; hop <= cfg.max_hops; hop++) {
    if (!isShortener(url)) return { final: url, complete: true, hops, error: null };
    if (hop === cfg.max_hops) break;
    let next = null;
    try {
      for (const method of ["HEAD", "GET"]) {
        const left = deadline - now();
        if (left <= 0) return { final: url, complete: false, hops, error: "timeout" };
        const res = await request(url, method, left);
        hops.push({ url, status: res.status, method });
        const target = headerDestination(res.headers) ?? (res.status >= 300 && res.status < 400 ? res.location : method === "GET" ? metaRefresh(res.body) : null);
        if (target) {
          next = webAddress(target, url);
          if (!next) return { final: url, complete: false, hops, error: "bad_redirect" };
          break;
        }
      }
    } catch (err) {
      return { final: url, complete: false, hops, error: String(err?.message ?? err).slice(0, 120) };
    }
    if (!next) return { final: url, complete: false, hops, error: url === start ? "no_redirect" : "service_page" };
    url = next;
  }
  return { final: url, complete: false, hops, error: "too_many_hops" };
}
