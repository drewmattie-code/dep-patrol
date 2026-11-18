#!/bin/bash
# Write down how to undo a deploy BEFORE you deploy. Appends one line to .dep-patrol-rollback.log in the repo.
# usage: record-rollback.sh <platform> <app> [release]
#   platform: fly | vercel | wrangler | other
#   release:  what is live now. Give it yourself when the platform's CLI cannot be read here
#             (always needed for 'other').
# It will not write a record without a release to go back to: it says STOP, exits 1 and records nothing.
set -uo pipefail
[ $# -ge 2 ] || { echo "usage: $0 <fly|vercel|wrangler|other> <app> [release]"; exit 2; }
P="$1"; APP="$2"; CUR="${3:-}"; WHY=""

ask() {   # run a platform CLI: stdout to RAW, the reason to WHY when it fails
  local err; err=$(mktemp)
  RAW=$("$@" 2>"$err") || { WHY=$(tail -3 "$err"); [ -n "$WHY" ] || WHY="'$1' failed or is not installed"; RAW=""; }
  rm -f "$err"
}

if [ -z "$CUR" ]; then
  case "$P" in
    fly)   # newest release first; skip one that never finished. Releases are not images, so keep both.
      ask fly releases -a "$APP" --json
      CUR=$(printf '%s' "$RAW" | python3 -c '
import json, sys
try:
    rel = [r for r in json.load(sys.stdin) if isinstance(r, dict)]
except Exception:
    rel = []
live = [r for r in rel if str(r.get("Status", "complete")).lower() == "complete" and r.get("Version") and r.get("ImageRef")]
if live:
    print("v%s image %s" % (live[0]["Version"], live[0]["ImageRef"]))') ;;
    wrangler)   # the JSON list is oldest first: the live deployment is the newest one
      ask npx wrangler deployments list --name "$APP" --json
      CUR=$(printf '%s' "$RAW" | python3 -c '
import json, sys
try:
    deps = [d for d in json.load(sys.stdin) if isinstance(d, dict) and d.get("versions")]
except Exception:
    deps = []
if deps:
    newest = max(deps, key=lambda d: d.get("created_on", ""))
    version = max(newest["versions"], key=lambda v: v.get("percentage", 0)).get("version_id")
    if version:
        print("version " + version)') ;;
    vercel)   # the first Ready Production row is what is serving
      ask vercel ls "$APP"
      CUR=$(printf '%s\n' "$RAW" | awk '/Ready/ && /Production/ { for (i = 1; i <= NF; i++) if ($i ~ /^https:\/\//) { print $i; exit } }') ;;
    other) WHY="give the current release as the third argument" ;;
    *) echo "unknown platform '$P' (use fly, vercel, wrangler or other)"; exit 2 ;;
  esac
fi

if [ -z "$CUR" ]; then
  echo "STOP: could not read what is live for $APP on $P. Nothing was recorded."
  [ -z "$WHY" ] || echo "  $WHY"
  echo "  Find the current release yourself, then run: record-rollback.sh $P $APP <release>"
  exit 1
fi
echo "$(date -u +%FT%TZ) $P $APP current=$CUR commit=$(git rev-parse --short HEAD 2>/dev/null || echo none)" | tee -a .dep-patrol-rollback.log
