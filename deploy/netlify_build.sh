#!/usr/bin/env bash
# Netlify build (netlify.toml): copy the URL check page and the files it loads into site_dist/,
# then build the blocklist from the public phishing feed (lists.blocklist_feeds in
# configs/backend.yaml). A failed blocklist build is not fatal: the page then says it has no list.
set -euo pipefail
OUT=site_dist
rm -rf "$OUT"
mkdir -p "$OUT/demo" "$OUT/extension" "$OUT/js/data" "$OUT/data/lists"
cp demo/index.html demo/app.js demo/check.js demo/evidence.js "$OUT/demo/"
cp -r extension/src extension/data "$OUT/extension/"
cp -r js/src "$OUT/js/"
cp js/data/tier_a_hybrid.json js/data/psl_icann.json "$OUT/js/data/"
printf '%s' '<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=demo/index.html"><a href="demo/index.html">Open the URL checker</a>' > "$OUT/index.html"

LISTS=$(mktemp -d)
if python3 -m pip install --quiet pandas pyarrow pyyaml requests tldextract \
  && python3 -m backend build-lists --no-evidence --no-tenant-sites --out "$LISTS"; then
  cp "$LISTS/blocklist.json" "$OUT/data/lists/"
else
  echo "WARNING: blocklist not built; the page will run without one" >&2
fi
du -sh "$OUT"
