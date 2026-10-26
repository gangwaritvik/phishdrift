// Follows real short links with the hosted function's own code (netlify/functions/expand.mjs),
// for a machine with open internet (the GitHub workflow short-link-probe.yml). Only shortener
// addresses are requested; the destinations are printed, never opened.
//   node js/bench/expand_probe.mjs URL...
import { handle } from "../../netlify/functions/expand.mjs";

for (const url of process.argv.slice(2)) {
  const t = Date.now();
  const res = await handle(new Request("https://probe/api/expand", { method: "POST", body: JSON.stringify({ url }) }));
  const body = await res.json();
  const hops = (body.hops ?? []).map((h) => `${h.method} ${h.status}`).join(", ");
  console.log(`${url}\n  -> ${body.final ?? "-"} complete=${body.complete} error=${body.error} [${hops}] ${Date.now() - t} ms`);
}
