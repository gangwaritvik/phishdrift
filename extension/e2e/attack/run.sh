#!/bin/bash
# run.sh [OUTDIR] [case-filter]: attack harness on a test copy of extension/dist (the "tabs" permission
# is added to the copy only, so the harness can read tab URLs). Build first: node ../../build.mjs
# Sandbox without network: the harness only talks to 127.0.0.1 (every host name resolves there), so
# `unshare -rn bash -c 'python3 lo_up.py && ./run.sh ...'` proves no real site is contacted.
# Needs Playwright with a Chromium (global install or PLAYWRIGHT_MODULE).
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
DIST=${DIST:-$HERE/../../dist}
OUT=${1:-$HERE/out}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
cp -r "$DIST"/. "$T"/
python3 - "$T/manifest.json" <<'PY'
import json,sys; p=sys.argv[1]; m=json.load(open(p)); m["permissions"]=sorted(set(m["permissions"]+["tabs"])); json.dump(m,open(p,"w"),indent=1)
PY
NODE_PATH=${NODE_PATH:-$(npm root -g)} node "$HERE/harness.mjs" "$T" "$OUT" $2
