"""Shared end-to-end harness: real discovery, real git, real report writing; npm audit and OSV are recorded."""
import contextlib, io, json, os, shutil, subprocess, sys, tempfile, unittest, urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scan  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
CLEAN_AUDIT = json.dumps({"auditReportVersion": 2, "vulnerabilities": {}, "metadata": {}})
HIGH = {"id": "GHSA-9wx4-h78v-vm56", "summary": "requests: fixture session leak", "aliases": ["CVE-2030-0002"],
        "database_specific": {"severity": "HIGH"},
        "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}]}]}
NEEDS_TOML = unittest.skipIf(scan.tomllib is None, "needs Python 3.11+ or tomli")


class Harness(unittest.TestCase):
    """A temp machine: code/ with projects, a config, and recorded answers for npm audit, OSV and the package indexes.
    The recorded OSV says exactly one thing is vulnerable: requests 2.31.0 (advisory HIGH). A test can add to
    `vulnerable`, and name in `newest` the release a package index hands out today."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.code = self.tmp / "code"
        self.audit, self.osv_down = (FIX / "npm/audit.json").read_text(), False
        self.vulnerable, self.newest = {("requests", "2.31.0")}, {}
        real_run = scan.run

        def fake_run(cmd, cwd, timeout=300):
            if cmd[:2] == ["npm", "audit"]:
                return (1, self.audit, "") if self.audit else (1, "", "npm error code ENOTFOUND")
            if cmd[0] == "git":
                return real_run(cmd, cwd, timeout)
            raise AssertionError(f"unexpected command {cmd}")

        def fake_http(url, payload=None, tries=4):
            if self.osv_down:
                raise OSError("network down")
            if payload is not None:
                return {"results": [{"vulns": [{"id": HIGH["id"]}]} if (q["package"]["name"], q["version"]) in
                                    self.vulnerable else {} for q in payload["queries"]]}
            if not url.startswith(scan.OSV_API):   # a package index, asked for the newest release
                for pkg, ver in self.newest.items():
                    if f"/{pkg}/" in url:
                        return {"version": ver, "info": {"version": ver}}
                raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
            return HIGH
        for target, fake in (("run", fake_run), ("http_json", fake_http)):
            p = mock.patch.object(scan, target, side_effect=fake)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch.object(scan, "find_depsguard", return_value=None)   # the machine's own depsguard stays out of the tests
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(scan, "CACHE_DIR", self.tmp / "cache")
        p.start()
        self.addCleanup(p.stop)

    def project(self, name, npm=False, uv=False, requirements=None):
        d = self.code / name
        d.mkdir(parents=True, exist_ok=True)
        if npm:
            shutil.copy(FIX / "npm/package-lock.json", d / "package-lock.json")
        if uv:
            shutil.copy(FIX / "uv/uv.lock", d / "uv.lock")
        if requirements:
            (d / "requirements.txt").write_text(requirements)
        return d

    def config(self, **extra):
        cfg = self.tmp / "cfg.json"
        cfg.write_text(json.dumps(dict({"roots": [str(self.code)], "out": str(self.tmp / "reports")}, **extra)))
        return str(cfg)

    def main(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = scan.main(list(argv))
        return rc, out.getvalue()

    def entry(self, *argv):
        """Like main(), through the command-line entry point that guards against crashes."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            rc = scan.entry(list(argv))
        return rc, out.getvalue()

    def report(self):
        day = next((self.tmp / "reports").iterdir())
        return json.loads((day / "report.json").read_text()), (day / "report.md").read_text(), day

    def git(self, cwd, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com", GIT_COMMITTER_NAME="t",
                   GIT_COMMITTER_EMAIL="t@example.com", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
        return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True, env=env).stdout.strip()

    def commit(self, repo, message, **files):
        """Write files (path -> text, None deletes), commit, return the full sha."""
        if not (Path(repo) / ".git").exists():
            self.git(repo, "init", "-q", "-b", "main")
        for rel, text in files.items():
            f = Path(repo) / rel.replace("__", "/")
            if text is None:
                f.unlink()
            else:
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(text)
        self.git(repo, "add", "-A")
        self.git(repo, "commit", "-q", "--allow-empty", "-m", message)
        return self.git(repo, "rev-parse", "HEAD")
