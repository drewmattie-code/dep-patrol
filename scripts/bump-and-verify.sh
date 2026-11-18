#!/bin/bash
# Bump dependencies to exact versions, prove the advisory is gone, then prove nothing broke.
# usage: bump-and-verify.sh [--fixes ADVISORY[,ADVISORY...]] <pkg>@<version> [<pkg>@<version> ...]
# Run it in the project folder. The lockfile there picks the tool:
#   package-lock.json  -> npm install --save-exact         pnpm-lock.yaml     -> pnpm add --save-exact
#   uv.lock            -> uv lock --upgrade-package        requirements*.txt  -> the == pins are edited in place
# --fixes names the advisories this bump is for (GHSA-..., CVE-...). Each must be present before the bump and
#   gone after it, in a scan that really ran. Without --fixes nothing is claimed about any advisory.
# Env: TEST_CMD and BUILD_CMD (npm and pnpm default to the test and build scripts if present; Python has no
#      default, so set TEST_CMD), SKIP_TSC=1, ALLOW_UNTRACKED_LOCK=1.
# Stops at the first failing step with a non-zero exit (3 = the bump is verified but no tests were run).
# Logs go to ./.dep-patrol-verify/.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if [ -n "${DEP_PATROL_SCAN:-}" ]; then SCAN=("$DEP_PATROL_SCAN"); else SCAN=(python3 "$HERE/scan.py"); fi
FIXES=""
if [ "${1:-}" = "--fixes" ]; then FIXES="${2:-}"; shift; shift || true; fi
[ $# -ge 1 ] || { echo "usage: $0 [--fixes ADVISORY[,ADVISORY...]] pkg@version ..."; exit 2; }
read -r -a IDS <<< "${FIXES//,/ }"

if   [ -f npm-shrinkwrap.json ]; then TOOL=npm;  LOCK=npm-shrinkwrap.json
elif [ -f package-lock.json ];   then TOOL=npm;  LOCK=package-lock.json
elif [ -f pnpm-lock.yaml ];      then TOOL=pnpm; LOCK=pnpm-lock.yaml
elif [ -f uv.lock ];             then TOOL=uv;   LOCK=uv.lock
elif ls requirements*.txt >/dev/null 2>&1; then TOOL=pip; LOCK=$(ls requirements*.txt | head -1)
else echo "STOP: no lockfile here (package-lock.json, pnpm-lock.yaml, uv.lock or requirements*.txt). Run this in the project folder."; exit 1; fi

# A lockfile that is not in git means the next install can pull different versions than the ones verified here.
if git rev-parse --git-dir >/dev/null 2>&1 && [ "${ALLOW_UNTRACKED_LOCK:-0}" != 1 ]; then
  git ls-files --error-unmatch "$LOCK" >/dev/null 2>&1 || {
    echo "STOP: $LOCK is not committed. Commit it first, or set ALLOW_UNTRACKED_LOCK=1 if that is on purpose."; exit 1; }
fi

L=.dep-patrol-verify; mkdir -p "$L"
step() { local name="$1"; shift; echo "== $name"; if "$@" > "$L/$name.log" 2>&1; then echo "   ok"; else echo "   FAILED (see $L/$name.log)"; tail -15 "$L/$name.log"; exit 1; fi; }
verify() { "${SCAN[@]}" --repo . --max-depth 0 --verify-fixed "${IDS[@]}"; }
answers() { grep -E ': (still present|gone|cannot confirm)' "$1" | sed 's/^/   /'; }

pin_requirements() {   # edit "name==old" to "name==new" in requirements*.txt, all or nothing
  python3 - "$@" <<'PY'
import glob, re, sys
files = {f: open(f).read().splitlines(keepends=True) for f in sorted(glob.glob("requirements*.txt"))}
norm = lambda n: re.sub(r"[-_.]+", "-", n).lower()
missing = []
for spec in sys.argv[1:]:
    name, _, version = spec.rpartition("@")
    hit = False
    for f, lines in files.items():
        for i, line in enumerate(lines):
            m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+)", line)
            if m and norm(m.group(1)) == norm(name):
                if "--hash" in line or (i + 1 < len(lines) and "--hash" in lines[i + 1]):
                    sys.exit(f"STOP: {f} pins hashes. Re-run your compile step for {name} instead (pip-compile --upgrade-package {name}=={version}).")
                lines[i], hit = line[:m.start(3)] + version + line[m.end(3):], True
    if not hit:
        missing.append(name)
if missing:
    sys.exit("STOP: not pinned with == in any requirements file: " + ", ".join(missing))
for f, lines in files.items():
    open(f, "w").write("".join(lines))
PY
}

if [ ${#IDS[@]} -gt 0 ]; then
  echo "== before: is the advisory here?"
  verify > "$L/before.log" 2>&1; rc=$?
  answers "$L/before.log"
  case $rc in
    1) echo "   yes" ;;
    0) echo "STOP: $FIXES is not present before the bump. Check the advisory id, and that this is the right folder."; exit 1 ;;
    *) echo "STOP: could not scan this project, so the fix could not be checked afterwards either (see $L/before.log)."; exit 1 ;;
  esac
fi

case $TOOL in
  npm)  step install npm install --save-exact "$@" ;;
  pnpm) step install pnpm add --save-exact "$@" ;;
  uv)   args=(); for p in "$@"; do args+=(--upgrade-package "${p%@*}==${p##*@}"); done; step install uv lock "${args[@]}" ;;
  pip)  step install pin_requirements "$@" ;;
esac

if [ ${#IDS[@]} -gt 0 ]; then
  echo "== after: is the advisory gone?"
  verify > "$L/after.log" 2>&1; rc=$?
  answers "$L/after.log"
  case $rc in
    0) echo "   ok" ;;
    1) echo "   FAILED: $FIXES is still present after the bump (see $L/after.log)"; exit 1 ;;
    *) echo "   FAILED: the fix could not be confirmed, because the scan did not complete (see $L/after.log)"; exit 1 ;;
  esac
else
  echo "== scan after the bump (no --fixes given, so nothing is claimed about a specific advisory)"
  "${SCAN[@]}" --repo . --max-depth 0 --out "$L/report" > "$L/scan.log" 2>&1; rc=$?
  grep -E '^dep-patrol ' "$L/scan.log" | sed 's/^/   /'
  [ $rc -ne 2 ] || { echo "   FAILED: the scan did not complete (see $L/scan.log)"; exit 1; }
fi

TESTED=1
if [ "$TOOL" = npm ] || [ "$TOOL" = pnpm ]; then
  if [ "${SKIP_TSC:-0}" != 1 ] && [ -f tsconfig.json ]; then step typecheck npx tsc --noEmit; fi
  step tests bash -c "${TEST_CMD:-$TOOL run --if-present test}"
  step build bash -c "${BUILD_CMD:-$TOOL run --if-present build}"
else
  if [ -n "${TEST_CMD:-}" ]; then step tests bash -c "$TEST_CMD"; else TESTED=0; fi
  [ -z "${BUILD_CMD:-}" ] || step build bash -c "$BUILD_CMD"
fi
if [ $TESTED = 1 ]; then echo "all green. Review the diff, commit, record the rollback, then deploy."
else echo "bump done, but NO TESTS WERE RUN: set TEST_CMD (for example TEST_CMD='uv run pytest -q') and run this again before you deploy."; exit 3; fi
