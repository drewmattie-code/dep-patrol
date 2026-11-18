"""The shell helpers, run for real with stand-in CLIs on PATH (fly, npx, vercel, npm, pnpm, uv) and a local web server."""
import http.server, json, os, shutil, subprocess, tempfile, threading, unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
FLY_OK = json.dumps([{"Version": 79, "Status": "complete", "ImageRef": "registry.fly.io/shop:deployment-01NEW"},
                     {"Version": 78, "Status": "complete", "ImageRef": "registry.fly.io/shop:deployment-01OLD"}])
WRANGLER_OK = json.dumps([
    {"id": "d1", "created_on": "2026-11-10T00:00:00Z", "versions": [{"version_id": "11111111-1111-4111-8111-111111111111", "percentage": 100}]},
    {"id": "d2", "created_on": "2026-11-17T00:00:00Z", "versions": [{"version_id": "22222222-2222-4222-8222-222222222222", "percentage": 100}]}])
VERCEL_OK = """Vercel CLI 39.1.0
> Deployments for acme/site [221ms]

  Age     Deployment                                Status      Environment     Duration     Username
  5m      https://site-pre111-acme.vercel.app       ● Ready     Preview         39s          drew
  2h      https://site-abc123-acme.vercel.app       ● Ready     Production      41s          drew
  1d      https://site-def456-acme.vercel.app       ● Ready     Production      40s          drew
"""


class Shell(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.bin, self.work, self.log = self.tmp / "bin", self.tmp / "work", self.tmp / "calls.log"
        self.bin.mkdir()
        self.work.mkdir()

    def stub(self, name, body):
        f = self.bin / name
        f.write_text("#!/bin/bash\n" + body + "\n")
        f.chmod(0o755)

    def prints(self, name, text, code=0):
        (self.tmp / f"{name}.out").write_text(text)
        self.stub(name, f'echo "{name} $*" >> "{self.log}"\ncat "{self.tmp / (name + ".out")}"\nexit {code}')

    def sh(self, script, *args, **env):
        e = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}", **env)
        r = subprocess.run(["bash", str(SCRIPTS / script), *args], cwd=self.work, capture_output=True, text=True, env=e)
        return r.returncode, r.stdout + r.stderr

    def calls(self):
        return self.log.read_text() if self.log.exists() else ""

    def record(self):
        f = self.work / ".dep-patrol-rollback.log"
        return f.read_text() if f.exists() else ""


class RecordRollbackTest(Shell):
    def test_fly_records_version_and_image(self):
        self.prints("fly", FLY_OK)
        rc, out = self.sh("record-rollback.sh", "fly", "shop")
        self.assertEqual(rc, 0, out)
        self.assertIn("fly shop current=v79 image registry.fly.io/shop:deployment-01NEW", self.record())
        self.assertEqual(len(self.record().splitlines()), 1)

    def test_fly_skips_a_release_that_never_went_live(self):
        self.prints("fly", json.dumps([{"Version": 80, "Status": "failed", "ImageRef": "registry.fly.io/shop:deployment-01BAD"}]
                                      + json.loads(FLY_OK)))
        self.sh("record-rollback.sh", "fly", "shop")
        self.assertIn("current=v79 image registry.fly.io/shop:deployment-01NEW", self.record())

    def test_failed_lookup_records_nothing_and_says_what_to_do(self):
        # v2 wrote "current=unknown" and exited 0: a rollback record with nothing to roll back to
        self.stub("fly", 'echo "Error: no access token available" >&2; exit 1')
        rc, out = self.sh("record-rollback.sh", "fly", "shop")
        self.assertNotEqual(rc, 0)
        self.assertIn("STOP", out)
        self.assertIn("record-rollback.sh fly shop <release>", out)
        self.assertEqual(self.record(), "")
        self.prints("fly", "[]")
        self.assertNotEqual(self.sh("record-rollback.sh", "fly", "shop")[0], 0)
        self.assertEqual(self.record(), "")

    def test_the_operator_can_give_the_release(self):
        self.stub("fly", "exit 1")
        rc, out = self.sh("record-rollback.sh", "fly", "shop", "v78 image registry.fly.io/shop:deployment-01OLD")
        self.assertEqual(rc, 0, out)
        self.assertIn("fly shop current=v78 image registry.fly.io/shop:deployment-01OLD", self.record())

    def test_wrangler_takes_the_newest_deployment(self):
        self.prints("npx", WRANGLER_OK)
        rc, out = self.sh("record-rollback.sh", "wrangler", "edge")
        self.assertEqual(rc, 0, out)
        self.assertIn("wrangler edge current=version 22222222-2222-4222-8222-222222222222", self.record())
        self.assertIn("wrangler deployments list --name edge --json", self.calls())

    def test_wrangler_failure_records_nothing(self):
        self.stub("npx", 'echo "Not logged in." >&2; exit 1')
        rc, out = self.sh("record-rollback.sh", "wrangler", "edge")
        self.assertNotEqual(rc, 0)
        self.assertEqual(self.record(), "")

    def test_vercel_takes_the_current_production_deployment(self):
        self.prints("vercel", VERCEL_OK)
        rc, out = self.sh("record-rollback.sh", "vercel", "site")
        self.assertEqual(rc, 0, out)
        self.assertIn("vercel site current=https://site-abc123-acme.vercel.app", self.record())

    def test_other_platform_needs_the_release(self):
        self.assertNotEqual(self.sh("record-rollback.sh", "other", "box")[0], 0)
        self.assertEqual(self.sh("record-rollback.sh", "other", "box", "image sha256:abc")[0], 0)
        self.assertIn("other box current=image sha256:abc", self.record())
        self.assertEqual(self.sh("record-rollback.sh")[0], 2)


class InstallScheduleTest(Shell):
    """--dry-run prints the choice and installs nothing."""

    def dry(self, pythons):
        cfg = self.tmp / "config.json"
        cfg.write_text("{}")
        self.stub("py-old", "echo False")
        self.stub("py-new", "echo True")
        return self.sh("install-schedule.sh", "--dry-run", str(cfg), DEP_PATROL_PYTHONS=" ".join(f"{self.bin}/{p}" for p in pythons))

    def test_picks_a_python_that_can_read_toml_lockfiles(self):
        # over ssh and under launchd the first python3 is often the old system one
        rc, out = self.dry(["py-old", "py-new"])
        self.assertEqual(rc, 0, out)
        self.assertIn(f"python: {self.bin}/py-new", out)
        self.assertNotIn("warning", out)

    def test_warns_when_only_an_old_python_exists(self):
        rc, out = self.dry(["py-old"])
        self.assertEqual(rc, 0, out)
        self.assertIn(f"python: {self.bin}/py-old", out)
        self.assertIn("warning", out)
        self.assertIn("3.11", out)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        code = {"/": 200, "/login": 200, "/api/session": 401, "/boom": 500}.get(self.path.split("?")[0], 404)
        self.send_response(code)
        self.end_headers()
        self.wfile.write(b"x")

    def log_message(self, *args):
        pass


class SmokeCheckTest(Shell):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_all_as_expected(self):
        rc, out = self.sh("smoke-check.sh", f"{self.base}/", f"{self.base}/login?next=/a=b", f"{self.base}/api/session=401")
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.count("ok"), 3)

    def test_wrong_status_and_dead_host_fail(self):
        rc, out = self.sh("smoke-check.sh", f"{self.base}/", f"{self.base}/boom")
        self.assertEqual(rc, 1)
        self.assertIn("FAIL", out)
        self.assertIn("500", out)
        self.assertEqual(self.sh("smoke-check.sh", "http://127.0.0.1:9/")[0], 1)
        self.assertEqual(self.sh("smoke-check.sh")[0], 2)


class BumpAndVerifyTest(Shell):
    """The scanner is replaced by a stand-in that answers with scripted exit codes, one per call."""

    def setUp(self):
        super().setUp()
        for tool in ("npm", "pnpm", "uv"):
            self.stub(tool, f'echo "{tool} $*" >> "{self.log}"')
        self.stub("scanner", f'''n=$(cat "{self.tmp}/count" 2>/dev/null || echo 0); echo $((n + 1)) > "{self.tmp}/count"
codes=($SCAN_CODES); echo "scan $*" >> "{self.log}"; exit ${{codes[$n]:-0}}''')

    def repo(self, **files):
        for name, text in files.items():
            (self.work / name).write_text(text)
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com", GIT_COMMITTER_NAME="t",
                   GIT_COMMITTER_EMAIL="t@example.com", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
        for cmd in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "init"]):
            subprocess.run(["git", *cmd], cwd=self.work, check=True, capture_output=True, env=env)

    def bump(self, *args, codes="1 0", **env):
        marker = self.tmp / "tests-ran"
        env = dict({"DEP_PATROL_SCAN": str(self.bin / "scanner"), "SCAN_CODES": codes, "TEST_CMD": f"touch {marker}",
                    "BUILD_CMD": "true"}, **env)
        rc, out = self.sh("bump-and-verify.sh", *args, **env)
        return rc, out, marker.exists()

    def test_npm_happy_path(self):
        self.repo(**{"package.json": "{}", "package-lock.json": "{}"})
        rc, out, tested = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6", "eslint-config-next@16.4.6")
        self.assertEqual((rc, tested), (0, True), out)
        self.assertIn("all green", out)
        calls = self.calls()
        self.assertIn("npm install --save-exact next@16.4.6 eslint-config-next@16.4.6", calls)
        self.assertEqual(calls.count("--verify-fixed GHSA-aaaa-aaaa-aaaa"), 2)   # before the bump and after it
        self.assertLess(calls.index("scan "), calls.index("npm install"))

    def test_advisory_still_present_after_the_bump_fails_before_the_tests(self):
        # v2 printed the audit totals and carried on: a bump could "pass" with its target advisory still open
        self.repo(**{"package.json": "{}", "package-lock.json": "{}"})
        rc, out, tested = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6", codes="1 1")
        self.assertNotEqual(rc, 0)
        self.assertFalse(tested)
        self.assertIn("still present", out)

    def test_scan_that_did_not_run_is_not_a_pass(self):
        self.repo(**{"package.json": "{}", "package-lock.json": "{}"})
        rc, out, tested = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6", codes="1 2")
        self.assertNotEqual(rc, 0)
        self.assertFalse(tested)
        self.assertIn("could not be confirmed", out)

    def test_advisory_not_there_before_the_bump_stops_before_changing_anything(self):
        self.repo(**{"package.json": "{}", "package-lock.json": "{}"})
        for codes, words in (("0", "not present before the bump"), ("2", "scan this project")):
            (self.tmp / "count").unlink(missing_ok=True)
            self.log.unlink(missing_ok=True)
            rc, out, _ = self.bump("--fixes", "GHSA-typo", "next@16.4.6", codes=codes)
            self.assertNotEqual(rc, 0)
            self.assertIn(words, out)
            self.assertNotIn("npm install", self.calls())

    def test_without_fixes_the_scan_must_still_complete(self):
        self.repo(**{"package.json": "{}", "package-lock.json": "{}"})
        rc, out, tested = self.bump("next@16.4.6", codes="1")     # other findings remain: reported, not a failure
        self.assertEqual((rc, tested), (0, True), out)
        self.assertIn("no --fixes", out)
        (self.tmp / "count").unlink()
        rc, out, tested = self.bump("next@16.4.6", codes="2")
        self.assertNotEqual(rc, 0)

    def test_lockfile_that_is_not_committed_stops_the_bump(self):
        (self.work / "package-lock.json").write_text("{}")
        self.repo(**{"package.json": "{}", ".gitignore": "package-lock.json\n"})
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6")
        self.assertNotEqual(rc, 0)
        self.assertIn("not committed", out)
        self.assertNotIn("npm install", self.calls())
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6", ALLOW_UNTRACKED_LOCK="1")
        self.assertEqual(rc, 0, out)

    def test_failing_tests_fail_the_bump(self):
        self.repo(**{"package.json": "{}", "package-lock.json": "{}"})
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6", TEST_CMD="false")
        self.assertNotEqual(rc, 0)
        self.assertIn("FAILED", out)

    def test_pnpm_and_uv_projects_use_their_own_tool(self):
        self.repo(**{"package.json": "{}", "pnpm-lock.yaml": ""})
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6")
        self.assertEqual(rc, 0, out)
        self.assertIn("pnpm add --save-exact next@16.4.6", self.calls())

    def test_uv_project(self):
        self.repo(**{"pyproject.toml": "", "uv.lock": ""})
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "jinja2@3.1.6", "idna@3.7")
        self.assertEqual(rc, 0, out)
        self.assertIn("uv lock --upgrade-package jinja2==3.1.6 --upgrade-package idna==3.7", self.calls())

    def test_python_bump_with_no_test_command_does_not_exit_clean(self):
        self.repo(**{"pyproject.toml": "", "uv.lock": ""})
        rc, out, tested = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "jinja2@3.1.6", TEST_CMD="")
        self.assertEqual((rc, tested), (3, False), out)
        self.assertIn("NO TESTS WERE RUN", out)

    def test_requirements_pins_are_edited_in_place(self):
        self.repo(**{"requirements.txt": "flask==3.0.0\nJinja2==3.1.2  # templates\nuvicorn[standard]==0.30.0\n"})
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "jinja2@3.1.6", "uvicorn@0.30.6")
        self.assertEqual(rc, 0, out)
        self.assertEqual((self.work / "requirements.txt").read_text(),
                         "flask==3.0.0\nJinja2==3.1.6  # templates\nuvicorn[standard]==0.30.6\n")
        (self.tmp / "count").unlink()
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "requests@2.32.0")
        self.assertNotEqual(rc, 0)
        self.assertIn("not pinned", out)

    def test_no_manifest_and_no_arguments(self):
        self.assertEqual(self.sh("bump-and-verify.sh")[0], 2)
        rc, out, _ = self.bump("next@16.4.6")
        self.assertNotEqual(rc, 0)
        self.assertIn("no lockfile", out)


# What each package manager really says when a version is younger than its release cooldown, recorded 2026-11-18
# from npm 11.21.3, pnpm 11.2.2 and uv 0.11.21 (the package names and dates are changed, the wording is theirs).
NPM_TOO_NEW = """npm error code ETARGET
npm error notarget No matching version found for next@16.4.6 with a date before 2026-11-11, 3:56:58 p.m..
npm error notarget In most cases you or one of your dependencies are requesting a package version that doesn't exist."""
PNPM_TOO_NEW = """[ERR_PNPM_NO_MATURE_MATCHING_VERSION] {n} version{s} not meet the minimumReleaseAge constraint:
{rows}"""
PNPM_ROW = "  {spec} was published at 2026-11-17T15:08:58.238Z, within the minimumReleaseAge cutoff (2026-11-11T20:57:25.055Z)"
UV_TOO_NEW = """  x No solution found when resolving dependencies:
  Because there is no version of jinja2==3.1.6 and your project depends on jinja2==3.1.6, we can conclude that your
  project's requirements are unsatisfiable.
hint: `jinja2` was filtered by `exclude-newer` to only include packages uploaded before 2026-11-11T00:00:00Z. The requested version, v3.1.6, was published at 2026-11-17T16:08:19.53Z. Consider using `exclude-newer-package` to override the cutoff for this package."""


class CooldownBumpTest(BumpAndVerifyTest):
    """A release cooldown refuses the fix. The bump lets that one fix through, the narrowest way each tool has."""

    def says(self, name, text):
        f = self.tmp / f"{name}.says"
        f.write_text(text + "\n")
        return f

    # ---- npm: the lockfile install is not held to the cooldown, so one command with it off is enough
    def npm_refuses(self, text=NPM_TOO_NEW):
        self.stub("npm", f'echo "npm $*" >> "{self.log}"\n[ "$1" = install ] || exit 0\n'
                         f'case "$*" in *--min-release-age=0*) exit 0;; esac\ncat "{self.says("npm", text)}" >&2; exit 1')

    def test_npm_fix_younger_than_the_cooldown_goes_in_with_it_off_for_that_one_command(self):
        self.repo(**{"package.json": "{}", "package-lock.json": "{}"})
        self.npm_refuses()
        rc, out, tested = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6")
        self.assertEqual((rc, tested), (0, True), out)
        installs = [c for c in self.calls().splitlines() if c.startswith("npm install")]
        self.assertEqual(installs, ["npm install --save-exact next@16.4.6",
                                    "npm install --save-exact next@16.4.6 --min-release-age=0"])
        self.assertIn("release cooldown", out)
        self.assertIn("next@16.4.6", out)
        self.assertIn("lockfile diff", out)             # everything that command resolved came in with the cooldown off

    def test_npm_with_no_refusal_is_never_given_the_flag(self):
        self.repo(**{"package.json": "{}", "package-lock.json": "{}"})
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("min-release-age", self.calls())
        self.assertNotIn("cooldown", out)

    def test_npm_failing_for_another_reason_is_not_tried_again(self):
        self.repo(**{"package.json": "{}", "package-lock.json": "{}"})
        self.npm_refuses("npm error code ERESOLVE\nnpm error ERESOLVE unable to resolve dependency tree")
        rc, out, tested = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6")
        self.assertEqual((rc == 0, tested), (False, False), out)
        self.assertEqual(self.calls().count("npm install"), 1)
        self.assertIn("ERESOLVE", out)

    # ---- pnpm: a lockfile install IS held to the cooldown, so the exception has to live in the repo
    def pnpm_refuses(self, *specs):
        """A stand-in that lets a version in the way pnpm 11.2.2 really does (tried 2026-11-18): only the FIRST entry
        for a package counts, and that entry is the name alone, one version, or several joined with ||."""
        rows = "\n".join(PNPM_ROW.format(spec=s) for s in specs)
        text = PNPM_TOO_NEW.format(n=len(specs), s=" does" if len(specs) == 1 else "s do", rows=rows)
        check = self.tmp / "let-in.py"
        check.write_text("""import re, sys
entries = {}
try:
    lines = open("pnpm-workspace.yaml").read().splitlines()
except OSError:
    lines = []
on = False
for ln in lines:
    if re.match(r"^minimumReleaseAgeExclude:\\s*$", ln):
        on = True
    elif on and re.match(r"^\\s+-\\s", ln):
        item = ln.split("-", 1)[1].strip().strip("'\\"")
        m = re.match(r"^(@?[^@]+)(?:@(.+))?$", item)
        entries.setdefault(m.group(1), [v.strip() for v in (m.group(2) or "").split("||") if v.strip()])
    elif on:
        on = False
for spec in sys.argv[1:]:
    name, _, ver = spec.rpartition("@")
    if name not in entries or (entries[name] and ver not in entries[name]):
        sys.exit(1)
""")
        need = " ".join(f"'{s}'" for s in specs)
        self.stub("pnpm", f'echo "pnpm $*" >> "{self.log}"\n[ "$1" = add ] || exit 0\n'
                          f'python3 "{check}" {need} || {{ cat "{self.says("pnpm", text)}"; exit 1; }}\nexit 0')

    def workspace(self):
        return (self.work / "pnpm-workspace.yaml").read_text()

    def test_pnpm_fix_younger_than_the_cooldown_is_named_in_the_workspace_file(self):
        self.repo(**{"package.json": "{}", "pnpm-lock.yaml": "", "pnpm-workspace.yaml": "packages:\n  - apps/*\nminimumReleaseAge: 10080\n"})
        self.pnpm_refuses("next@16.4.6")
        rc, out, tested = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6")
        self.assertEqual((rc, tested), (0, True), out)
        self.assertEqual(self.workspace(), "packages:\n  - apps/*\nminimumReleaseAge: 10080\nminimumReleaseAgeExclude:\n  - next@16.4.6\n")
        self.assertEqual(self.calls().count("pnpm add --save-exact next@16.4.6"), 2)
        self.assertIn("commit pnpm-workspace.yaml", out.lower())
        self.assertIn("older than the cooldown", out)   # when to take the line out again

    def test_pnpm_project_with_no_workspace_file_gets_one(self):
        self.repo(**{"package.json": "{}", "pnpm-lock.yaml": ""})
        self.pnpm_refuses("next@16.4.6")
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.workspace(), "minimumReleaseAgeExclude:\n  - next@16.4.6\n")

    def test_pnpm_adds_to_a_list_that_is_already_there_and_never_twice(self):
        before = "minimumReleaseAge: 10080\nminimumReleaseAgeExclude:\n  - left-pad@1.3.0\n  - next@16.4.6\nonlyBuiltDependencies:\n  - sharp\n"
        self.repo(**{"package.json": "{}", "pnpm-lock.yaml": "", "pnpm-workspace.yaml": before})
        self.pnpm_refuses("next@16.4.6", "eslint-config-next@16.4.6")
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6", "eslint-config-next@16.4.6")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.workspace(), "minimumReleaseAge: 10080\nminimumReleaseAgeExclude:\n  - left-pad@1.3.0\n  - next@16.4.6\n"
                                           "  - eslint-config-next@16.4.6\nonlyBuiltDependencies:\n  - sharp\n")

    def test_pnpm_package_with_an_older_exception_gets_both_versions_on_one_line(self):
        # found by running the real thing: a second entry for the same package is ignored, so the fix stayed refused
        before = "minimumReleaseAge: 10080\nminimumReleaseAgeExclude:\n  - next@16.4.5\n  - '@next/env@16.4.5'\n"
        self.repo(**{"package.json": "{}", "pnpm-lock.yaml": "", "pnpm-workspace.yaml": before})
        self.pnpm_refuses("next@16.4.6", "@next/env@16.4.6")
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6", "@next/env@16.4.6")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.workspace(), "minimumReleaseAge: 10080\nminimumReleaseAgeExclude:\n  - 'next@16.4.5 || 16.4.6'\n"
                                           "  - '@next/env@16.4.5 || 16.4.6'\n")

    def test_pnpm_package_already_let_in_by_name_is_left_alone(self):
        before = "minimumReleaseAgeExclude:\n  - next\n"
        self.repo(**{"package.json": "{}", "pnpm-lock.yaml": "", "pnpm-workspace.yaml": before})
        self.pnpm_refuses("next@16.4.6", "eslint-config-next@16.4.6")
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6", "eslint-config-next@16.4.6")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.workspace(), "minimumReleaseAgeExclude:\n  - next\n  - eslint-config-next@16.4.6\n")

    def test_pnpm_list_written_on_one_line_stops_and_says_what_to_add(self):
        before = "minimumReleaseAge: 10080\nminimumReleaseAgeExclude: [left-pad]\n"
        self.repo(**{"package.json": "{}", "pnpm-lock.yaml": "", "pnpm-workspace.yaml": before})
        self.pnpm_refuses("next@16.4.6")
        rc, out, tested = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6")
        self.assertEqual((rc == 0, tested, self.workspace()), (False, False, before), out)
        self.assertIn("STOP", out)
        self.assertIn("next@16.4.6", out)

    def test_pnpm_another_package_too_young_stops_unless_it_is_allowed(self):
        self.repo(**{"package.json": "{}", "pnpm-lock.yaml": ""})
        self.pnpm_refuses("next@16.4.6", "@next/env@16.4.6")
        rc, out, tested = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6")
        self.assertEqual((rc == 0, tested), (False, False), out)
        self.assertIn("STOP", out)
        self.assertIn("@next/env@16.4.6", out)
        self.assertIn("ALLOW_YOUNG_DEPS=1", out)
        self.assertFalse((self.work / "pnpm-workspace.yaml").exists())      # all or nothing
        (self.tmp / "count").unlink()
        rc, out, tested = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "next@16.4.6", ALLOW_YOUNG_DEPS="1")
        self.assertEqual((rc, tested), (0, True), out)
        self.assertEqual(self.workspace(), "minimumReleaseAgeExclude:\n  - next@16.4.6\n  - '@next/env@16.4.6'\n")

    # ---- uv: a later `uv lock` or `uv sync --locked` quietly takes the fix back out unless the project says to keep it
    def uv_refuses(self, check=0):
        self.stub("uv", f'echo "uv $*" >> "{self.log}"\n[ "$1 $2" = "lock --check" ] && exit {check}\n'
                        f'grep -qE \'^jinja2 = "\' uv.toml pyproject.toml 2>/dev/null && exit 0\n'
                        f'cat "{self.says("uv", UV_TOO_NEW)}" >&2; exit 1')

    def test_uv_fix_younger_than_the_cutoff_is_named_in_the_project(self):
        self.repo(**{"pyproject.toml": '[project]\nname = "x"\n\n[tool.uv]\nexclude-newer = "7 days"\n', "uv.lock": ""})
        self.uv_refuses()
        rc, out, tested = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "jinja2@3.1.6")
        self.assertEqual((rc, tested), (0, True), out)
        text = (self.work / "pyproject.toml").read_text()
        self.assertRegex(text, r'\[tool\.uv\.exclude-newer-package\]\njinja2 = "20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ"\n$')
        self.assertTrue(text.startswith('[project]\nname = "x"\n\n[tool.uv]\nexclude-newer = "7 days"\n'))
        uv = [c for c in self.calls().splitlines() if c.startswith("uv ")]
        self.assertEqual(uv, ["uv lock --upgrade-package jinja2==3.1.6", "uv lock --upgrade-package jinja2==3.1.6", "uv lock --check"])
        self.assertIn("commit pyproject.toml", out.lower())

    def test_uv_project_with_its_own_uv_toml_gets_it_there(self):
        self.repo(**{"pyproject.toml": '[project]\nname = "x"\n', "uv.toml": 'exclude-newer = "7 days"\n', "uv.lock": ""})
        self.uv_refuses()
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "jinja2@3.1.6")
        self.assertEqual(rc, 0, out)
        self.assertRegex((self.work / "uv.toml").read_text(), r'^exclude-newer = "7 days"\n\n\[exclude-newer-package\]\njinja2 = "20[^"]+Z"\n$')
        self.assertEqual((self.work / "pyproject.toml").read_text(), '[project]\nname = "x"\n')

    def test_uv_adds_to_a_table_that_is_already_there(self):
        before = 'exclude-newer = "7 days"\n\n[exclude-newer-package]\nidna = "2026-11-01T00:00:00Z"\n\n[pip]\nindex-url = "https://example.test/simple"\n'
        self.repo(**{"pyproject.toml": '[project]\nname = "x"\n', "uv.toml": before, "uv.lock": ""})
        self.uv_refuses()
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "jinja2@3.1.6")
        self.assertEqual(rc, 0, out)
        self.assertRegex((self.work / "uv.toml").read_text(),
                         r'^exclude-newer = "7 days"\n\n\[exclude-newer-package\]\nidna = "2026-11-01T00:00:00Z"\njinja2 = "20[^"]+Z"\n\n\[pip\]\nindex-url')

    def test_uv_exception_written_on_one_line_stops_and_says_what_to_add(self):
        before = '[project]\nname = "x"\n\n[tool.uv]\nexclude-newer = "7 days"\nexclude-newer-package = { idna = "2026-11-01T00:00:00Z" }\n'
        self.repo(**{"pyproject.toml": before, "uv.lock": ""})
        self.uv_refuses()
        rc, out, tested = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "jinja2@3.1.6")
        self.assertEqual((rc == 0, tested, (self.work / "pyproject.toml").read_text()), (False, False, before), out)
        self.assertIn("STOP", out)
        self.assertIn("jinja2", out)

    def test_uv_lockfile_that_no_longer_matches_the_project_fails_the_bump(self):
        self.repo(**{"pyproject.toml": '[project]\nname = "x"\n', "uv.lock": ""})
        self.uv_refuses(check=1)
        rc, out, tested = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "jinja2@3.1.6")
        self.assertEqual((rc == 0, tested), (False, False), out)
        self.assertIn("FAILED", out)

    def test_uv_with_no_refusal_changes_no_file(self):
        self.repo(**{"pyproject.toml": '[project]\nname = "x"\n', "uv.lock": ""})
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "jinja2@3.1.6")
        self.assertEqual((rc, (self.work / "pyproject.toml").read_text()), (0, '[project]\nname = "x"\n'), out)
        self.assertNotIn("lock --check", self.calls())

    # ---- pinned requirements: nothing is installed here, but the install that follows may be refused
    def test_requirements_bump_says_so_when_pip_has_a_cutoff(self):
        self.repo(**{"requirements.txt": "requests==2.31.0\n"})
        for name in ("pip", "pip3"):
            self.stub(name, 'if [ "$1 $2 $3" = "config get install.uploaded-prior-to" ]; then echo P7D; exit 0; fi; exit 1')
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "requests@2.32.0", TEST_CMD="true")
        self.assertEqual(rc, 0, out)
        self.assertIn("uploaded-prior-to", out)
        self.assertIn("P0D", out)

    def test_requirements_bump_is_quiet_when_pip_has_none(self):
        self.repo(**{"requirements.txt": "requests==2.31.0\n"})
        for name in ("pip", "pip3"):
            self.stub(name, "exit 1")
        rc, out, _ = self.bump("--fixes", "GHSA-aaaa-aaaa-aaaa", "requests@2.32.0", TEST_CMD="true")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("uploaded-prior-to", out)



if __name__ == "__main__":
    unittest.main()
