#!/bin/bash
# Write down how to undo a deploy BEFORE you deploy. Appends to .dep-patrol-rollback.log in the repo.
# usage: record-rollback.sh <platform> <app>
#   platform: fly | vercel | wrangler | other
# For 'other', pass the current release id as a third argument.
set -euo pipefail
P="${1:?platform}"; APP="${2:?app name}"; NOW=$(date -u +%FT%TZ)
case "$P" in
  fly)      CUR=$(fly releases -a "$APP" --json 2>/dev/null | python3 -c "import json,sys;r=json.load(sys.stdin)[0];print(f\"v{r.get('Version')} image {r.get('ImageRef','?')}\")") ;;
  vercel)   CUR=$(vercel ls "$APP" 2>/dev/null | sed -n 2p) ;;
  wrangler) CUR=$(npx wrangler deployments list --name "$APP" 2>/dev/null | grep -m1 -i "version" || true) ;;
  *)        CUR="${3:?current release id}" ;;
esac
echo "$NOW $P $APP current=${CUR:-unknown} commit=$(git rev-parse --short HEAD 2>/dev/null)" | tee -a .dep-patrol-rollback.log
