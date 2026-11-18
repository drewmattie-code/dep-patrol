"""One test class per scanner adapter. Offline: recorded tool output, a mocked OSV API, real-format lockfiles."""
import json, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scan  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
NEEDS_TOML = unittest.skipIf(scan.tomllib is None, "needs Python 3.11+ or tomli")


def load(rel):
    return json.loads((FIX / rel).read_text())


def by_id(findings):
    return {f["id"]: f for f in findings}


class NpmParseTest(unittest.TestCase):
    def setUp(self):
        self.f = by_id(scan.npm_parse(load("npm/audit.json"), load("npm/package-lock.json"), "package-lock.json"))

    def test_one_finding_per_advisory_and_none_dropped(self):
        # v2 kept one finding per package and cut its advisory list to 10
        self.assertEqual(len(self.f), 18)
        undici = [f for f in self.f.values() if f["package"] == "undici"]
        self.assertEqual(len(undici), 12)
        self.assertEqual(sorted(f["severity"] for f in undici).count("critical"), 1)

    def test_direct_production_advisory(self):
        n = self.f["GHSA-2464-fhr4-w9xw"]
        self.assertEqual((n["package"], n["severity"], n["scope"], n["direct"]), ("next", "critical", "production", True))
        self.assertEqual(n["versions"], ["16.4.0"])
        self.assertEqual(n["fix"], "next@16.4.6")
        self.assertEqual(n["score"], 9.8)
        self.assertEqual(n["url"], "https://github.com/advisories/GHSA-2464-fhr4-w9xw")
        self.assertIn("1112233", n["aliases"])
        self.assertEqual((n["ecosystem"], n["manifest"]), ("npm", "package-lock.json"))

    def test_transitive_names_the_direct_dependency_it_comes_through(self):
        p = self.f["GHSA-7fh5-64p2-3v2j"]
        self.assertEqual((p["package"], p["scope"], p["direct"], p["via"]), ("postcss", "production", False, ["next"]))

    def test_dev_tool_is_dev_scope(self):
        self.assertEqual(self.f["GHSA-82fw-gwwq-j7x9"]["scope"], "dev")

    def test_two_installed_versions_are_judged_separately(self):
        # v2 walked the tree by package name: the first copy seen decided for every copy
        old = self.f["GHSA-3v7f-55p6-f55p"]   # range <2.3.2: only the production copy 2.3.1
        new = self.f["GHSA-c2c7-rcm5-vvqj"]   # range >=4.0.0 <4.0.4: only vitest's copy 4.0.2
        self.assertEqual((old["scope"], old["versions"], old["direct"]), ("production", ["2.3.1"], True))
        self.assertEqual((new["scope"], new["versions"], new["direct"], new["via"]), ("dev", ["4.0.2"], False, ["vitest"]))

    def test_dev_optional_ships_in_production(self):
        self.assertEqual(self.f["GHSA-67mh-4wv8-2f99"]["scope"], "production")

    def test_major_fix_is_labelled(self):
        self.assertEqual(self.f["GHSA-cc11-undi-ci11"]["fix"], "undici@7.0.0 (major)")

    def test_one_advisory_listed_once_per_version_branch_is_merged(self):
        # npm repeats an advisory for each affected release line. Keeping only the first entry (the 7.x line,
        # which matches the dev copy) hid the production copy on the 6.x line. Found on a real repo.
        def via(source, rng):
            return {"source": source, "name": "undici", "dependency": "undici", "title": "undici: fixture", "severity": "high",
                    "url": "https://github.com/advisories/GHSA-p88m-4jfj-68fv", "range": rng, "cvss": {"score": 7.5}}
        audit = {"auditReportVersion": 2, "vulnerabilities": {"undici": {
            "name": "undici", "severity": "high", "isDirect": False, "effects": [], "range": "<=6.26.0 || 7.0.0 - 7.27.0",
            "via": [via(111, ">=7.0.0 <7.28.0"), via(222, "<6.27.0")], "fixAvailable": True,
            "nodes": ["node_modules/testcontainers/node_modules/undici", "node_modules/undici"]}}}
        lock = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/undici": {"version": "6.24.1"},
                                                   "node_modules/testcontainers/node_modules/undici": {"version": "7.25.0", "dev": True}}}
        found = scan.npm_parse(audit, lock, "package-lock.json")
        self.assertEqual(len(found), 1)
        f = found[0]
        self.assertEqual((f["id"], f["scope"], f["versions"]), ("GHSA-p88m-4jfj-68fv", "production", ["6.24.1", "7.25.0"]))
        self.assertEqual(f["range"], ">=7.0.0 <7.28.0 || <6.27.0")
        self.assertEqual(f["aliases"], ["111", "222"])

    def test_old_lockfile_without_package_table_is_scope_unknown(self):
        f = by_id(scan.npm_parse(load("npm/audit.json"), {"lockfileVersion": 1, "dependencies": {}}, "package-lock.json"))
        self.assertEqual({x["scope"] for x in f.values()}, {"unknown"})


class NpmScanTest(unittest.TestCase):
    def run_with(self, rc, out, err=""):
        with tempfile.TemporaryDirectory() as t, mock.patch.object(scan, "run", return_value=(rc, out, err)):
            (Path(t) / "package-lock.json").write_text((FIX / "npm/package-lock.json").read_text())
            return scan.npm_scan(t, "package-lock.json")

    def test_good_audit(self):
        r = self.run_with(1, (FIX / "npm/audit.json").read_text())
        self.assertEqual((r["status"], len(r["findings"]), r["packages"]), ("scanned", 18, 8))

    def test_clean_audit_is_scanned_with_no_findings(self):
        r = self.run_with(0, json.dumps({"auditReportVersion": 2, "vulnerabilities": {}, "metadata": {}}))
        self.assertEqual((r["status"], r["findings"]), ("scanned", []))

    def test_empty_output_is_a_failure_not_a_clean_result(self):
        # v2 read empty stdout as {} and reported zero findings
        r = self.run_with(1, "", "npm error code ENOTFOUND\nnpm error network request to registry failed")
        self.assertEqual(r["status"], "failed")
        self.assertIn("ENOTFOUND", r["detail"])
        self.assertEqual(r["findings"], [])

    def test_error_object_and_wrong_shape_are_failures(self):
        r = self.run_with(1, json.dumps({"error": {"code": "ENOLOCK", "summary": "This command requires an existing lockfile."}}))
        self.assertEqual(r["status"], "failed")
        self.assertIn("ENOLOCK", r["detail"])
        self.assertEqual(self.run_with(0, "{}")["status"], "failed")
        self.assertEqual(self.run_with(0, "[]")["status"], "failed")
        self.assertEqual(self.run_with(0, "<html>proxy login</html>")["status"], "failed")

    def test_missing_npm_or_timeout_is_a_failure(self):
        self.assertEqual(self.run_with(None, "", "npm: not found")["status"], "failed")


class PnpmTest(unittest.TestCase):
    def test_per_advisory_scope_direct_and_path(self):
        f = by_id(scan.pnpm_parse(load("pnpm/audit.json"), "pnpm-lock.yaml"))
        self.assertEqual(len(f), 3)
        n = f["GHSA-9g9p-9gw9-jx7f"]
        self.assertEqual((n["package"], n["scope"], n["direct"], n["versions"], n["fix"]),
                         ("next", "production", True, ["14.2.35"], ">=15.5.10"))
        e = f["GHSA-67mh-4wv8-2f99"]
        self.assertEqual((e["scope"], e["direct"], e["via"]), ("dev", False, ["vite"]))
        w = f["GHSA-3h5v-q93c-6h6q"]   # in a dev tool AND in production, direct in a workspace package
        self.assertEqual((w["scope"], w["direct"]), ("production", True))

    def scan_with(self, rc, out, err="", have=("pnpm",)):
        with mock.patch.object(scan, "run", return_value=(rc, out, err)), \
                mock.patch.object(scan.shutil, "which", side_effect=lambda t: f"/bin/{t}" if t in have else None):
            return scan.pnpm_scan("/tmp", "pnpm-lock.yaml")

    def test_scan_good_and_failures(self):
        self.assertEqual(self.scan_with(1, (FIX / "pnpm/audit.json").read_text())["status"], "scanned")
        bad = self.scan_with(1, json.dumps({"error": {"code": "ERR_PNPM_AUDIT_NO_LOCKFILE", "message": "No pnpm-lock.yaml found"}}))
        self.assertEqual(bad["status"], "failed")
        self.assertIn("ERR_PNPM_AUDIT_NO_LOCKFILE", bad["detail"])
        self.assertEqual(self.scan_with(1, "")["status"], "failed")
        self.assertEqual(self.scan_with(0, "{}")["status"], "failed")

    def test_no_pnpm_and_no_osv_scanner_is_unscanned_with_the_fix(self):
        r = self.scan_with(0, "", have=())
        self.assertEqual(r["status"], "unscanned")
        self.assertIn("pnpm", r["detail"])


def names(pkgs):
    return {p["name"]: (p["version"], p["scope"], p["direct"]) for p in pkgs}


class PythonPackagesTest(unittest.TestCase):
    def test_requirements_pins_and_loose_lines(self):
        with tempfile.TemporaryDirectory() as t:
            Path(t, "requirements.txt").write_text("Django==4.2.1\nrequests>=2\nuvicorn[standard]==0.30.0  # web\n-e .\n"
                                                   "git+https://example.com/x.git\nTyping_Extensions==4.9.0\n")
            pkgs, info = scan.python_packages(t, "requirements.txt")
            self.assertEqual(names(pkgs), {"django": ("4.2.1", "production", None), "uvicorn": ("0.30.0", "production", None),
                                           "typing-extensions": ("4.9.0", "production", None)})
            self.assertEqual(info["unpinned"], ["requests"])

    def test_included_files_are_read_unless_they_are_scanned_on_their_own(self):
        # "-r deps/pinned.txt" used to be skipped: whatever it pinned was never checked, and nothing said so
        with tempfile.TemporaryDirectory() as t:
            Path(t, "deps").mkdir()
            Path(t, "requirements.txt").write_text("-r deps/pinned.txt\nflask==3.0.0\n--requirement requirements-dev.txt\n-r missing.txt\n")
            Path(t, "deps", "pinned.txt").write_text("jinja2==3.1.2\nrequests>=2\n-r ../requirements.txt\n")
            Path(t, "requirements-dev.txt").write_text("pytest==8.0.0\n")
            pkgs, info = scan.python_packages(t, "requirements.txt")
            self.assertEqual(sorted(names(pkgs)), ["flask", "jinja2"])            # pytest is its own manifest
            self.assertEqual(info["unpinned"], ["requests", "-r missing.txt (file not found)"])

    def test_requirements_folder_files(self):
        with tempfile.TemporaryDirectory() as t:
            Path(t, "requirements").mkdir()
            Path(t, "requirements", "base.txt").write_text("django==4.2.1\n")
            Path(t, "requirements", "prod.txt").write_text("-r base.txt\ngunicorn==21.2.0\n")
            Path(t, "requirements", "dev.txt").write_text("-r base.txt\npytest==8.0.0\n")
            got = {f: names(scan.python_packages(t, f"requirements/{f}.txt")[0]) for f in ("base", "prod", "dev")}
            self.assertEqual(got, {"base": {"django": ("4.2.1", "production", None)},
                                   "prod": {"gunicorn": ("21.2.0", "production", None)},
                                   "dev": {"pytest": ("8.0.0", "dev", None)}})

    def test_requirements_scope_comes_from_the_file_name_or_is_unknown(self):
        with tempfile.TemporaryDirectory() as t:
            for n in ("requirements-dev.txt", "requirements_test.txt", "requirements-gpu.txt", "requirements-prod.txt"):
                Path(t, n).write_text("x==1.0\n")
            got = {n: scan.python_packages(t, n)[0][0]["scope"] for n in
                   ("requirements-dev.txt", "requirements_test.txt", "requirements-gpu.txt", "requirements-prod.txt")}
            self.assertEqual(got, {"requirements-dev.txt": "dev", "requirements_test.txt": "dev",
                                   "requirements-gpu.txt": "unknown", "requirements-prod.txt": "production"})

    def test_pip_compile_annotations_say_what_is_direct(self):
        pkgs, info = scan.python_packages(FIX / "pip-compile", "requirements.txt")
        self.assertEqual(names(pkgs), {"click": ("8.1.7", "production", False), "flask": ("3.0.0", "production", True),
                                       "jinja2": ("3.1.2", "production", False), "markupsafe": ("2.1.3", "production", False),
                                       "werkzeug": ("3.0.1", "production", True)})
        self.assertEqual(info["unpinned"], [])

    @NEEDS_TOML
    def test_uv_lock_scope_follows_the_dependency_graph(self):
        # v2 marked every package in a lockfile as a direct production dependency
        pkgs, info = scan.python_packages(FIX / "uv", "uv.lock")
        self.assertEqual(names(pkgs), {
            "requests": ("2.31.0", "production", True), "urllib3": ("2.0.7", "production", False),
            "uvicorn": ("0.30.0", "production", True), "httptools": ("0.6.1", "production", False),
            "numpy": ("1.26.0", "production", True),       # an optional extra can ship
            "pytest": ("8.0.0", "dev", True), "pluggy": ("1.4.0", "dev", False),
            "mkdocs": ("1.5.3", "dev", True),             # a docs extra is tooling
            "orphan": ("1.0.0", "unknown", False)})
        self.assertEqual(info["skipped"], ["demo", "internal-lib"])   # the project itself and a git source: not on PyPI

    @NEEDS_TOML
    def test_uv_lock_without_a_project_entry_is_scope_unknown(self):
        pkgs, _ = scan.python_packages(FIX / "uv-noroot", "uv.lock")
        self.assertEqual(names(pkgs), {"requests": ("2.31.0", "unknown", None), "urllib3": ("2.0.7", "unknown", None)})

    @NEEDS_TOML
    def test_poetry_lock_scope_from_pyproject(self):
        pkgs, info = scan.python_packages(FIX / "poetry", "poetry.lock")
        self.assertEqual(names(pkgs), {"jinja2": ("3.1.2", "production", True), "markupsafe": ("2.1.3", "production", False),
                                       "pytest": ("8.0.0", "dev", True), "pluggy": ("1.4.0", "dev", False)})
        self.assertEqual(info["skipped"], ["internal-lib"])

    @NEEDS_TOML
    def test_poetry_lock_without_pyproject_is_scope_unknown(self):
        with tempfile.TemporaryDirectory() as t:
            Path(t, "poetry.lock").write_text((FIX / "poetry/poetry.lock").read_text())
            pkgs, _ = scan.python_packages(t, "poetry.lock")
            self.assertEqual({p["scope"] for p in pkgs}, {"unknown"})
            self.assertEqual({p["direct"] for p in pkgs}, {None})

    @NEEDS_TOML
    def test_poetry_2_groups_field(self):
        pkgs, _ = scan.python_packages(FIX / "poetry2", "poetry.lock")
        self.assertEqual({n: v[1] for n, v in names(pkgs).items()},
                         {"jinja2": "production", "typing-extensions": "production", "pytest": "dev", "pluggy": "dev"})


GHSA = {"id": "GHSA-h5c8-rqwp-cp95", "summary": "Jinja2 xmlattr filter", "aliases": ["CVE-2024-22195", "PYSEC-2026-1473"],
        "database_specific": {"severity": "MODERATE"},
        "affected": [{"package": {"name": "jinja2", "ecosystem": "PyPI"},
                      "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.11.9"}]},
                                 {"type": "ECOSYSTEM", "events": [{"introduced": "3.0.0"}, {"fixed": "3.1.3"}]}]},
                     {"package": {"name": "jinja2-rs", "ecosystem": "crates.io"},
                      "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.0.9"}]}]}]}
PYSEC = {"id": "PYSEC-2026-1473", "aliases": ["CVE-2024-22195", "GHSA-h5c8-rqwp-cp95"],
         "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"}],
         "affected": [{"package": {"name": "jinja2", "ecosystem": "PyPI"},
                       "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.1.3"}]}]}]}
RECORDS = {"GHSA-h5c8-rqwp-cp95": GHSA, "PYSEC-2026-1473": PYSEC}


class PythonScanTest(unittest.TestCase):
    def scan_req(self, text, batch, records=RECORDS, name="requirements.txt", runs=1):
        calls = []

        def fake_http(url, payload=None, tries=4):
            calls.append((url, payload))
            if payload is not None:
                return batch(payload) if callable(batch) else batch
            return records[url.rsplit("/", 1)[1]]
        with tempfile.TemporaryDirectory() as t, mock.patch.object(scan, "CACHE_DIR", Path(t) / "cache"), \
                mock.patch.object(scan, "http_json", side_effect=fake_http):
            Path(t, name).write_text(text)
            for _ in range(runs):
                r = scan.python_scan(t, name)
        return r, calls

    def test_alias_copies_collapse_and_the_fix_is_for_this_package_and_branch(self):
        batch = {"results": [{"vulns": [{"id": "GHSA-h5c8-rqwp-cp95"}, {"id": "PYSEC-2026-1473"}]}, {}]}
        r, _ = self.scan_req("jinja2==3.1.2\nzzz==1.0\n", batch)
        self.assertEqual((r["status"], r["packages"]), ("scanned", 2))
        self.assertEqual(len(r["findings"]), 1)
        f = r["findings"][0]
        self.assertEqual((f["id"], f["package"], f["severity"], f["fix"], f["versions"], f["manifest"], f["ecosystem"]),
                         ("GHSA-h5c8-rqwp-cp95", "jinja2", "moderate", "3.1.3", ["3.1.2"], "requirements.txt", "PyPI"))
        self.assertEqual(f["aliases"], ["CVE-2024-22195", "PYSEC-2026-1473"])
        self.assertEqual((f["scope"], f["direct"]), ("production", None))

    def test_details_are_cached_between_runs(self):
        batch = {"results": [{"vulns": [{"id": "GHSA-h5c8-rqwp-cp95"}]}]}
        _, calls = self.scan_req("jinja2==3.1.2\n", batch, runs=2)
        self.assertEqual(sum(1 for url, _ in calls if "/v1/vulns/" in url), 1)

    def test_more_than_ten_advisories_on_one_package_all_survive(self):
        ids = [f"PYSEC-2030-{i}" for i in range(14)]
        records = {i: {"id": i, "summary": f"advisory {i}"} for i in ids}
        r, _ = self.scan_req("big==1.0\n", {"results": [{"vulns": [{"id": i} for i in ids]}]}, records)
        self.assertEqual(len(r["findings"]), 14)
        self.assertEqual({f["severity"] for f in r["findings"]}, {"unknown"})

    def test_osv_unreachable_is_a_failure(self):
        def boom(payload):
            raise OSError("network down")
        r, _ = self.scan_req("jinja2==3.1.2\n", boom)
        self.assertEqual((r["status"], r["findings"]), ("failed", []))
        self.assertIn("network down", r["detail"])

    def test_short_or_malformed_batch_answer_is_a_failure(self):
        self.assertEqual(self.scan_req("a==1\nb==2\n", {"results": [{}]})[0]["status"], "failed")
        self.assertEqual(self.scan_req("a==1\n", {"message": "rate limited"})[0]["status"], "failed")

    def test_loose_requirements_make_the_manifest_partial(self):
        r, _ = self.scan_req("jinja2==3.1.2\nrequests>=2\n", {"results": [{}]})
        self.assertEqual(r["status"], "partial")
        self.assertIn("requests", r["detail"])

    def test_nothing_pinned_is_unscanned(self):
        r, calls = self.scan_req("requests>=2\nflask\n", {"results": []})
        self.assertEqual(r["status"], "unscanned")
        self.assertEqual(calls, [])

    def test_big_lockfiles_are_queried_in_batches(self):
        text = "".join(f"pkg{i}==1.0\n" for i in range(1200))
        r, calls = self.scan_req(text, lambda payload: {"results": [{} for _ in payload["queries"]]})
        self.assertEqual(r["status"], "scanned")
        self.assertEqual([len(p["queries"]) for _, p in calls], [500, 500, 200])

    def test_a_paged_osv_answer_is_followed_to_the_end(self):
        records = {i: {"id": i} for i in ("PYSEC-2030-1", "PYSEC-2030-2", "PYSEC-2030-3")}

        def batch(payload):
            q = payload["queries"]
            if any("page_token" in x for x in q):   # the follow-up asks only for the paged package
                self.assertEqual([(x["package"]["name"], x["page_token"]) for x in q], [("big", "tok1")])
                return {"results": [{"vulns": [{"id": "PYSEC-2030-3"}]}]}
            return {"results": [{"vulns": [{"id": "PYSEC-2030-1"}, {"id": "PYSEC-2030-2"}], "next_page_token": "tok1"}, {}]}
        r, _ = self.scan_req("big==1.0\nsmall==1.0\n", batch, records)
        self.assertEqual(sorted(f["id"] for f in r["findings"]), ["PYSEC-2030-1", "PYSEC-2030-2", "PYSEC-2030-3"])

    def test_missing_detail_keeps_the_finding_as_unknown(self):
        def fake_http(url, payload=None, tries=4):
            if payload is not None:
                return {"results": [{"vulns": [{"id": "GHSA-h5c8-rqwp-cp95"}]}]}
            raise OSError("detail fetch failed")
        with tempfile.TemporaryDirectory() as t, mock.patch.object(scan, "CACHE_DIR", Path(t) / "cache"), \
                mock.patch.object(scan, "http_json", side_effect=fake_http):
            Path(t, "requirements.txt").write_text("jinja2==3.1.2\n")
            r = scan.python_scan(t, "requirements.txt")
        self.assertEqual(r["status"], "scanned")
        self.assertEqual([(f["id"], f["severity"]) for f in r["findings"]], [("GHSA-h5c8-rqwp-cp95", "unknown")])
        self.assertIn("details", r["detail"])


class OsvScannerTest(unittest.TestCase):
    def test_parse_groups_scores_and_notices(self):
        f = by_id(scan.osv_scanner_parse(load("osv-scanner/output.json"), "Cargo.lock"))
        self.assertEqual(sorted(f), ["GHSA-c38w-74pg-36hr", "RUSTSEC-2024-0436", "RUSTSEC-2026-0194",
                                     "RUSTSEC-2026-0293", "RUSTSEC-2026-0459"])
        t = f["RUSTSEC-2026-0194"]
        self.assertEqual((t["package"], t["versions"], t["severity"], t["ecosystem"], t["scope"], t["direct"], t["manifest"]),
                         ("tokio", ["1.30.0"], "high", "crates.io", "unknown", None, "Cargo.lock"))
        self.assertEqual(t["fix"], "1.38.2")
        self.assertEqual(f["RUSTSEC-2024-0436"]["severity"], "info")              # unmaintained notice
        self.assertEqual(f["RUSTSEC-2026-0293"]["severity"], "unknown")           # nobody rated it
        self.assertEqual(f["RUSTSEC-2026-0459"]["severity"], "high")              # CVSS 4 scored by osv-scanner: 8.4
        g = f["GHSA-c38w-74pg-36hr"]                                              # GHSA + RUSTSEC copies: one advisory
        self.assertEqual((g["severity"], g["aliases"]), ("moderate", ["CVE-2023-49092", "RUSTSEC-2023-0071"]))

    def scan_with(self, rc, out, err="", have=True):
        with mock.patch.object(scan, "run", return_value=(rc, out, err)), \
                mock.patch.object(scan.shutil, "which", return_value="/bin/osv-scanner" if have else None):
            return scan.osv_scanner_scan("/work/repo", "Cargo.lock")

    def test_scan_statuses(self):
        self.assertEqual(self.scan_with(1, (FIX / "osv-scanner/output.json").read_text())["status"], "scanned")
        self.assertEqual(self.scan_with(0, json.dumps({"results": []}))["status"], "scanned")
        bad = self.scan_with(127, "", "extraction failed on specified lockfile")
        self.assertEqual(bad["status"], "failed")
        self.assertIn("extraction failed", bad["detail"])
        self.assertEqual(self.scan_with(128, "", "No package sources found")["status"], "failed")
        self.assertEqual(self.scan_with(0, "{}")["status"], "failed")

    def test_not_installed_is_unscanned_with_the_command(self):
        r = self.scan_with(0, "", have=False)
        self.assertEqual(r["status"], "unscanned")
        self.assertIn("brew install osv-scanner", r["detail"])


if __name__ == "__main__":
    unittest.main()
