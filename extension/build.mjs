// Assemble the loadable extension in extension/dist: the extension's own files, the tier A
// feature/model code from js/src (as dist/lib) and the model bundle from js/data (as dist/data).
// Load dist/ with chrome://extensions > Developer mode > Load unpacked.

import { cpSync, existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, "dist");
const jsRoot = join(here, "..", "js");

for (const file of ["tier_a_hybrid.json", "psl_icann.json"]) {
  if (!existsSync(join(jsRoot, "data", file))) {
    throw new Error(`js/data/${file} is missing: run python -m models.export_hybrid / python -m features export-js`);
  }
}

rmSync(dist, { recursive: true, force: true });
mkdirSync(join(dist, "data"), { recursive: true });
cpSync(join(here, "manifest.json"), join(dist, "manifest.json"));
for (const f of readdirSync(join(here, "src"))) cpSync(join(here, "src", f), join(dist, f));
cpSync(join(jsRoot, "src"), join(dist, "lib"), { recursive: true });
for (const file of ["tier_a_hybrid.json", "psl_icann.json"]) {
  cpSync(join(jsRoot, "data", file), join(dist, "data", file));
}
// Node needs this to treat dist/*.js as modules in the tests; Chrome ignores it.
writeFileSync(join(dist, "package.json"), '{ "type": "module" }\n');
console.log("built", dist);
