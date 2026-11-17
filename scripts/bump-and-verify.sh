#!/bin/bash
# Bump npm packages to exact versions, then prove nothing broke: install, audit, typecheck, tests, build.
# usage: bump-and-verify.sh <pkg>@<version> [<pkg>@<version> ...]
# Env: TEST_CMD (default "npm test --if-present"), BUILD_CMD (default "npm run build --if-present"),
#      SKIP_TSC=1 to skip `npx tsc --noEmit`.
# Exits non-zero at the first failing step. Logs go to ./.dep-patrol-verify/.
set -uo pipefail
[ $# -ge 1 ] || { echo "usage: $0 pkg@version ..."; exit 2; }
L=.dep-patrol-verify; mkdir -p "$L"
step() { local name="$1"; shift; echo "== $name"; if "$@" > "$L/$name.log" 2>&1; then echo "   ok"; else echo "   FAILED (see $L/$name.log)"; tail -15 "$L/$name.log"; exit 1; fi; }
step install npm install --save-exact "$@"
echo "== audit (production)"; npm audit --omit=dev --json > "$L/audit.json" 2>/dev/null
python3 -c "import json;m=json.load(open('$L/audit.json')).get('metadata',{}).get('vulnerabilities',{});print('   ',m)"
if [ "${SKIP_TSC:-0}" != 1 ] && [ -f tsconfig.json ]; then step typecheck npx tsc --noEmit; fi
step tests bash -c "${TEST_CMD:-npm test --if-present}"
step build bash -c "${BUILD_CMD:-npm run build --if-present}"
echo "all green. Review 'git diff package.json', commit, record the rollback, then deploy."
