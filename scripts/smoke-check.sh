#!/bin/bash
# After a deploy: check that each URL answers with the status you expect. Exits 1 if any does not.
# usage: smoke-check.sh <url>[=<status>] ...          (status defaults to 200)
#   smoke-check.sh https://app.example.com/ https://app.example.com/api/session=401
# A signed-out endpoint answering 401 shows the auth layer is up, which a 200 on the home page does not.
# Redirects are not followed: a 302 is reported as 302, so give the final URL or expect the redirect.
set -uo pipefail
[ $# -ge 1 ] || { echo "usage: $0 url[=status] ..."; exit 2; }
bad=0
for arg in "$@"; do
  url="$arg"; want=200
  if [[ "$arg" =~ ^(.*)=([0-9]{3})$ ]]; then url="${BASH_REMATCH[1]}"; want="${BASH_REMATCH[2]}"; fi
  got=$(curl -sS -o /dev/null -w '%{http_code}' --max-time "${SMOKE_TIMEOUT:-20}" "$url" 2>/dev/null) || got="no answer"
  if [ "$got" = "$want" ]; then echo "ok    $want  $url"; else echo "FAIL  wanted $want, got $got  $url"; bad=1; fi
done
exit $bad
