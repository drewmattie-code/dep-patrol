#!/bin/bash
# Create a security branch from the commit that is actually deployed, not from whatever is checked out.
# usage: branch-from-deployed.sh <deployed-ref> <branch-name>
#   deployed-ref: a branch, tag or commit you have confirmed is live (release list, image tag, deploy branch)
# Refuses to run with uncommitted changes, so nobody's work gets mixed into a security fix.
set -euo pipefail
REF="${1:?deployed ref (branch, tag or commit)}"; BR="${2:?new branch name, e.g. security/next-16.4.6}"
git rev-parse --git-dir >/dev/null
if [ -n "$(git status --porcelain)" ]; then echo "STOP: uncommitted changes here. Commit or move them first."; exit 1; fi
git fetch --quiet --all || true
git rev-parse --verify --quiet "$REF^{commit}" >/dev/null || { echo "STOP: $REF is not a known commit"; exit 1; }
git switch -c "$BR" "$REF"
echo "on $BR from $(git log -1 --format='%h %s' "$REF")"
