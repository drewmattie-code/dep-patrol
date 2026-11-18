#!/bin/bash
# Bump dependencies to exact versions, prove the advisory is gone, then prove nothing broke.
# usage: bump-and-verify.sh [--fixes ADVISORY[,ADVISORY...]] <pkg>@<version> [<pkg>@<version> ...]
# Run it in the project folder. The lockfile there picks the tool:
#   package-lock.json  -> npm install --save-exact         pnpm-lock.yaml     -> pnpm add --save-exact
#   uv.lock            -> uv lock --upgrade-package        requirements*.txt  -> the == pins are edited in place
# --fixes names the advisories this bump is for (GHSA-..., CVE-...). Each must be present before the bump and
#   gone after it, in a scan that really ran. Without --fixes nothing is claimed about any advisory.
# A fix that is younger than a release cooldown is let through for that fix only (see "A release cooldown" below).
# Env: TEST_CMD and BUILD_CMD (npm and pnpm default to the test and build scripts if present; Python has no
#      default, so set TEST_CMD), SKIP_TSC=1, ALLOW_UNTRACKED_LOCK=1, ALLOW_YOUNG_DEPS=1 (let in packages the fix
#      needs that are also younger than the cooldown).
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

# ---- A release cooldown refuses a security fix too.
# A cooldown is a package manager setting that will not install a version until it is some days old (npm
# min-release-age, pnpm minimumReleaseAge, uv exclude-newer, pip uploaded-prior-to). It stops a poisoned release from
# an hour ago, and it also stops yesterday's patch. When the install is refused for that reason and no other, this
# lets the named fix through the narrowest way each tool has, and says what it did. Each tool was tried for real on
# 2026-11-18 (npm 11.21.3, pnpm 11.2.2, uv 0.11.21):
#   npm   installs from a lockfile whatever the cooldown says, so one command with the cooldown off is enough.
#   pnpm  holds a lockfile install to the cooldown as well, so the exception must be written in pnpm-workspace.yaml
#         and committed, or the next frozen install is refused.
#   uv    re-resolves when the lockfile and the project disagree, so an exception given only on the command line is
#         quietly undone by the next `uv lock`. It must be written in the project and committed.
ILOG="$L/install.log"
quiet() { "$@" > "$ILOG" 2>&1; }
failed() { echo "   FAILED (see $ILOG)"; tail -15 "$ILOG"; exit 1; }
named() { local x; for x in "${NAMES[@]}"; do [ "$x" = "$1" ] && return 0; done; return 1; }
norm() { printf '%s' "$1" | tr 'A-Z_.' 'a-z--'; }

others_stop() {   # packages the cooldown refuses that were not named on the command line
  echo "STOP: the cooldown also refuses what you did not name: $*"
  echo "   The fix needs them and they are younger than the cooldown. Look at each one, then run this again with"
  echo "   ALLOW_YOUNG_DEPS=1 to let them in as well. Nothing was changed."
  exit 1
}

let_in() {   # write the exception into the project, all or nothing: let_in pnpm <pkg@ver>... | let_in uv <name>...
  python3 - "$@" <<'PY'
import datetime, os, re, sys
tool, wanted = sys.argv[1], sys.argv[2:]
def stop(path, what, line):
    sys.exit(f"STOP: {path} writes {what} on one line, which this script will not rewrite.\n"
             f"   Add this to it yourself, then run this again: {line}")
if tool == "pnpm":
    # pnpm 11.2.2 honours only the FIRST entry for a package (tried 2026-11-18): a second line for the same name is
    # ignored. So a package gets one line: its name alone, one version, or several versions joined with ||.
    path, key = "pnpm-workspace.yaml", "minimumReleaseAgeExclude"
    lines = open(path).read().splitlines() if os.path.exists(path) else []
    word = lambda s: f"'{s}'" if s.startswith("@") or " " in s else s      # a YAML word cannot start with @
    split = lambda s: (lambda m: (m.group(1), [v.strip() for v in (m.group(2) or "").split("||") if v.strip()]))(
        re.match(r"^(@?[^@]+)(?:@(.+))?$", s))
    at = next((i for i, ln in enumerate(lines) if re.match(rf"^{key}\s*:", ln)), None)
    if at is None:
        lines.append(f"{key}:")
        at = len(lines) - 1
    elif re.sub(r"\s+#.*$", "", lines[at].split(":", 1)[1]).strip():
        stop(path, key, ", ".join(wanted))
    end, indent, have = at + 1, "  ", {}
    while end < len(lines) and re.match(r"^\s+-\s", lines[end]):
        indent = re.match(r"^(\s+)-", lines[end]).group(1)
        name, versions = split(lines[end].split("-", 1)[1].strip().strip("'\""))
        have.setdefault(name, (end, versions))
        end += 1
    for s in wanted:
        name, (version,) = split(s)
        if name not in have:
            lines.insert(end, f"{indent}- {word(s)}")
            have[name] = (end, [version])
            end += 1
        elif have[name][1] and version not in have[name][1]:
            row, versions = have[name]
            versions.append(version)
            lines[row] = f"{indent}- {word(name + '@' + ' || '.join(versions))}"
    open(path, "w").write("\n".join(lines) + "\n")
    print(path)
else:
    path = "uv.toml" if os.path.exists("uv.toml") else "pyproject.toml"
    head = "[exclude-newer-package]" if path == "uv.toml" else "[tool.uv.exclude-newer-package]"
    lines = open(path).read().splitlines()
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    key = lambda n: n if re.fullmatch(r"[A-Za-z0-9_-]+", n) else f'"{n}"'
    norm = lambda n: re.sub(r"[-_.]+", "-", n.strip().strip('"')).lower()
    if any(re.match(r"^\s*exclude-newer-package\s*=", ln) for ln in lines):
        stop(path, "exclude-newer-package", ", ".join(f'{key(n)} = "{now}"' for n in wanted))
    at = next((i for i, ln in enumerate(lines) if ln.strip() == head), None)
    if at is None:
        lines += ([""] if lines and lines[-1].strip() else []) + [head] + [f'{key(n)} = "{now}"' for n in wanted]
    else:
        end = next((i for i in range(at + 1, len(lines)) if lines[i].lstrip().startswith("[")), len(lines))
        last = max([i for i in range(at, end) if lines[i].strip()])
        for n in wanted:
            hit = next((i for i in range(at + 1, end) if "=" in lines[i] and norm(lines[i].split("=")[0]) == norm(n)), None)
            if hit is not None:
                lines[hit] = f'{key(n)} = "{now}"'
            else:
                last += 1
                lines.insert(last, f'{key(n)} = "{now}"')
                end += 1
    open(path, "w").write("\n".join(lines) + "\n")
    print(path)
PY
}

NAMES=("$@")
case $TOOL in
  npm)
    echo "== install"
    if quiet npm install --save-exact "$@"; then echo "   ok"
    elif grep -q "ETARGET" "$ILOG" && grep -q "with a date before" "$ILOG"; then
      echo "   refused by the release cooldown on this machine: $* is younger than it"
      echo "== install past the cooldown, for this one command"
      quiet npm install --save-exact "$@" --min-release-age=0 || failed
      echo "   ok. The cooldown was off for this command only and is still set."
      echo "   Everything that command resolved came in with it off, so read the lockfile diff before you commit."
    else failed; fi ;;
  pnpm)
    echo "== install"
    if quiet pnpm add --save-exact "$@"; then echo "   ok"
    elif grep -q "ERR_PNPM_NO_MATURE_MATCHING_VERSION" "$ILOG"; then
      young=(); while IFS= read -r s; do [ -n "$s" ] && young+=("$s"); done < <(
        sed -nE 's/^[[:space:]]+([^[:space:]]+@[^@[:space:]]+) was published at .*/\1/p' "$ILOG" | sort -u)
      [ ${#young[@]} -gt 0 ] || failed
      extra=(); for s in "${young[@]}"; do named "$s" || extra+=("$s"); done
      [ ${#extra[@]} -eq 0 ] || [ "${ALLOW_YOUNG_DEPS:-0}" = 1 ] || others_stop "${extra[*]}"
      echo "   refused by the release cooldown: ${young[*]} $([ ${#young[@]} -eq 1 ] && echo is || echo are) younger than it"
      order=(); for s in "${NAMES[@]}"; do for y in "${young[@]}"; do [ "$s" = "$y" ] && order+=("$s"); done; done
      [ ${#extra[@]} -eq 0 ] || order+=("${extra[@]}")
      file=$(let_in pnpm "${order[@]}") || exit 1
      echo "== install with the exception written in $file"
      quiet pnpm add --save-exact "$@" || failed
      echo "   ok. pnpm holds a lockfile install to the cooldown as well, so the exception has to stay in the repo."
      echo "   Commit $file with the lockfile. Take ${order[*]} out of minimumReleaseAgeExclude once"
      echo "   $([ ${#order[@]} -eq 1 ] && echo "it is" || echo "they are") older than the cooldown."
    else failed; fi ;;
  uv)
    args=(); for p in "$@"; do args+=(--upgrade-package "${p%@*}==${p##*@}"); done
    echo "== install"
    if quiet uv lock "${args[@]}"; then echo "   ok"
    elif grep -q 'filtered by `exclude-newer`' "$ILOG"; then
      young=(); while IFS= read -r s; do [ -n "$s" ] && young+=("$s"); done < <(
        sed -nE 's/^hint: `([^`]+)` was filtered by `exclude-newer`.*/\1/p' "$ILOG" | sort -u)
      [ ${#young[@]} -gt 0 ] || failed
      extra=(); for s in "${young[@]}"; do hit=0; for p in "$@"; do [ "$(norm "${p%@*}")" = "$(norm "$s")" ] && hit=1; done
        [ $hit = 1 ] || extra+=("$s"); done
      [ ${#extra[@]} -eq 0 ] || [ "${ALLOW_YOUNG_DEPS:-0}" = 1 ] || others_stop "${extra[*]}"
      echo "   refused by the release cutoff (exclude-newer): ${young[*]} $([ ${#young[@]} -eq 1 ] && echo is || echo are) newer than it"
      file=$(let_in uv "${young[@]}") || exit 1
      echo "== install with the exception written in $file"
      quiet uv lock "${args[@]}" || failed
      echo "   ok"
      step lock-matches-the-project uv lock --check
      echo "   A later uv lock would quietly go back to the old version, so the exception has to stay in the repo."
      echo "   Commit $file with uv.lock. Take ${young[*]} out of exclude-newer-package once the fixed"
      echo "   version is older than the cutoff."
    else failed; fi ;;
  pip)
    step install pin_requirements "$@"
    for p in pip pip3; do
      cut=$(command -v "$p" >/dev/null 2>&1 && "$p" config get install.uploaded-prior-to 2>/dev/null) || cut=""
      if [ -n "$cut" ]; then
        echo "   pip has a release cutoff on this machine (uploaded-prior-to=$cut). The pins are edited, but an install"
        echo "   will refuse a version newer than the cutoff. For this fix: pip install -r <file> --uploaded-prior-to=P0D"
        break
      fi
    done ;;
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
