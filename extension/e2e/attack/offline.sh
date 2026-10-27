#!/bin/bash
# offline.sh [OUTDIR] [filter]: run.sh in a network namespace that has only the loopback interface
# (proves no real site is contacted: every host name resolves to 127.0.0.1).
HERE=$(cd "$(dirname "$0")" && pwd)
exec unshare -rn bash -c 'python3 "$0/lo_up.py" && exec bash "$0/run.sh" "$@"' "$HERE" "$@"
