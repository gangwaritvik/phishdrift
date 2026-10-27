#!/usr/bin/env bash
# Used by the tier C capture workflows. The captures live on the orphan branch `tier-c-data`.
#   ci_data_branch.sh fetch   clone it to ./databranch and copy its data/ into ./data/
#   ci_data_branch.sh push    copy the new capture files back and push (retries on a race)
#   ci_data_branch.sh results DIR   copy DIR into results/ on the branch (reports, model) and push
set -euo pipefail
repo="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_REPOSITORY}"
case "${1:-}" in
fetch)
  git clone --depth 1 --branch tier-c-data "$repo" databranch
  mkdir -p data
  cp -r databranch/data/. data/
  ;;
push | results)
  mkdir -p databranch/data/interim
  if [ "$1" = results ]; then
    mkdir -p databranch/results
    cp -r "${2:?results needs a directory}"/. databranch/results/
    set -- results "${3:-results}"
  else
    for d in domain_info capture_state; do
      [ -d "data/interim/$d" ] && cp -r "data/interim/$d" databranch/data/interim/
    done
  fi
  cd databranch
  git config user.name "github-actions[bot]"
  git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
  git add -A
  git diff --cached --quiet && { echo "nothing new"; exit 0; }
  git commit -qm "${2:-capture} $(date -u +%Y-%m-%dT%H:%MZ)"
  for i in 1 2 3 4 5 6; do
    git push origin tier-c-data && exit 0
    sleep $((i * 4 + RANDOM % 5))
    git pull --rebase -q origin tier-c-data
  done
  exit 1
  ;;
*) echo "usage: $0 fetch|push|results DIR" >&2; exit 2 ;;
esac
