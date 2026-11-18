"""Discovery, severity and version-range logic. Offline."""
import json, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scan  # noqa: E402


def shape(projects):
    return {p["name"]: [(m["file"], m["ecosystem"], m["status"]) for m in p["manifests"]] for p in projects}


def touch(path, text=""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


class DiscoverTest(unittest.TestCase):
    def test_finds_projects_and_skips_node_modules(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "code"
            touch(root / "app" / "package-lock.json", "{}")
            touch(root / "app" / "node_modules" / "dep" / "package-lock.json", "{}")
            touch(root / "svc" / "api" / "requirements.txt", "flask==2.0.0\n")
            touch(root / "tool" / "Cargo.lock")
            touch(root / "web" / "yarn.lock")
            touch(root / "gosvc" / "go.mod", "module x\n")
            self.assertEqual(shape(scan.discover([str(root)], 3, [])), {
                "code/app": [("package-lock.json", "npm", "pending")],
                "code/gosvc": [("go.mod", "go", "pending")],
                "code/svc/api": [("requirements.txt", "python", "pending")],
                "code/tool": [("Cargo.lock", "rust", "pending")],
                "code/web": [("yarn.lock", "yarn", "pending")]})

    def test_mixed_language_folder_keeps_every_manifest(self):
        # v2 kept one ecosystem per folder: the Python side of a JS + Python app was never scanned
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "code"
            touch(root / "app" / "package-lock.json", "{}")
            touch(root / "app" / "uv.lock")
            touch(root / "app" / "requirements-dev.txt", "pytest==8.0.0\n")
            self.assertEqual(shape(scan.discover([str(root)], 3, [])), {"code/app": [
                ("package-lock.json", "npm", "pending"),
                ("requirements-dev.txt", "python", "pending"),
                ("uv.lock", "python", "pending")]})

    def test_exclude_include_and_unlimited_depth(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            touch(root / "a" / "b" / "c" / "d" / "e" / "package-lock.json", "{}")
            touch(root / "old-app" / "package-lock.json", "{}")
            self.assertEqual(len(scan.discover([str(root)], 3, ["old-*"])), 0)
            self.assertEqual(len(scan.discover([str(root)], None, ["old-*"])), 1)
            self.assertEqual([p["name"] for p in scan.discover([str(root)], None, [], ["old-*"])], [f"{root.name}/old-app"])

    def test_workspace_root_covers_member_js_lockfiles_only(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "mono"
            touch(root / "package.json", json.dumps({"workspaces": ["packages/*"]}))
            touch(root / "package-lock.json", "{}")
            touch(root / "packages" / "ui" / "package-lock.json", "{}")          # member: covered by the root lock
            touch(root / "packages" / "api" / "package-lock.json", "{}")         # member with a Python side
            touch(root / "packages" / "api" / "uv.lock")
            touch(root / "packages" / "ui" / "nested" / "package-lock.json", "{}")  # not a member (packages/* is one level)
            touch(root / "tools" / "cli" / "package-lock.json", "{}")            # outside the workspace globs
            self.assertEqual(shape(scan.discover([str(root)], None, [])), {
                "mono": [("package-lock.json", "npm", "pending"),
                         ("packages/api/package-lock.json", "npm", "covered"),
                         ("packages/ui/package-lock.json", "npm", "covered")],
                "mono/packages/api": [("uv.lock", "python", "pending")],
                "mono/packages/ui/nested": [("package-lock.json", "npm", "pending")],
                "mono/tools/cli": [("package-lock.json", "npm", "pending")]})

    def test_pnpm_workspace_file(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "mono"
            touch(root / "pnpm-workspace.yaml", "packages:\n  - 'apps/*'\n  - \"libs/**\"\n")
            touch(root / "pnpm-lock.yaml")
            touch(root / "apps" / "web" / "pnpm-lock.yaml")
            touch(root / "libs" / "a" / "b" / "pnpm-lock.yaml")
            self.assertEqual(shape(scan.discover([str(root)], None, [])), {"mono": [
                ("pnpm-lock.yaml", "pnpm", "pending"),
                ("apps/web/pnpm-lock.yaml", "pnpm", "covered"),
                ("libs/a/b/pnpm-lock.yaml", "pnpm", "covered")]})

    def test_requirements_folder_belongs_to_its_project(self):
        # the Django layout: requirements/base.txt, dev.txt, prod.txt and no requirements.txt at all
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "code"
            touch(root / "app" / "package-lock.json", "{}")
            for name in ("base", "dev", "prod"):
                touch(root / "app" / "requirements" / f"{name}.txt", "x==1.0\n")
            touch(root / "app" / "requirements" / "README.md", "notes")
            self.assertEqual(shape(scan.discover([str(root)], 3, [])), {"code/app": [
                ("package-lock.json", "npm", "pending"), ("requirements/base.txt", "python", "pending"),
                ("requirements/dev.txt", "python", "pending"), ("requirements/prod.txt", "python", "pending")]})

    def test_second_js_lockfile_is_recorded_not_scanned(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "code"
            touch(root / "a" / "package-lock.json", "{}")
            touch(root / "a" / "yarn.lock")
            touch(root / "b" / "package-lock.json", "{}")
            touch(root / "b" / "yarn.lock")
            touch(root / "b" / "package.json", json.dumps({"packageManager": "yarn@1.22.22"}))
            got = shape(scan.discover([str(root)], 3, []))
            self.assertEqual(got["code/a"], [("package-lock.json", "npm", "pending"), ("yarn.lock", "yarn", "skipped")])
            self.assertEqual(got["code/b"], [("package-lock.json", "npm", "skipped"), ("yarn.lock", "yarn", "pending")])


class SeverityTest(unittest.TestCase):
    def test_cvss3_base_scores(self):
        cases = {"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
                 "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 8.8,
                 "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N": 7.5,
                 "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N": 5.4,
                 "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N": 4.7,   # scope changed
                 "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H": 9.9,   # scope changed, low privileges
                 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0}
        for vector, want in cases.items():
            self.assertEqual(scan.cvss3_score(vector), want, vector)

    def test_cvss3_refuses_what_it_cannot_score(self):
        self.assertIsNone(scan.cvss3_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N"))
        self.assertIsNone(scan.cvss3_score("CVSS:3.1/AV:N/AC:L"))
        self.assertIsNone(scan.cvss3_score("garbage"))
        self.assertIsNone(scan.cvss3_score(None))

    def test_rating_bands(self):
        self.assertEqual([scan.rating(s) for s in (10, 9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.1)],
                         ["critical", "critical", "high", "high", "moderate", "moderate", "low", "low"])

    def test_osv_severity_prefers_the_published_label(self):
        v = {"database_specific": {"severity": "MODERATE"},
             "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        self.assertEqual(scan.osv_severity(v)[:2], ("moderate", "advisory"))
        self.assertEqual(scan.osv_severity({"database_specific": {"severity": "MEDIUM"}})[0], "moderate")

    def test_osv_severity_reads_top_level_cvss_vectors(self):
        # v2 only read database_specific.severity, so these became "unknown" and never counted as urgent
        v = {"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"}]}
        self.assertEqual(scan.osv_severity(v), ("high", "CVSS 7.5", 7.5))
        rustsec = {"affected": [{"database_specific": {"cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]}
        self.assertEqual(scan.osv_severity(rustsec)[0], "critical")

    def test_osv_severity_says_why_it_is_unknown(self):
        v4 = {"severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"}]}
        self.assertEqual(scan.osv_severity(v4)[0], "unknown")
        self.assertIn("4.0", scan.osv_severity(v4)[1])
        self.assertEqual(scan.osv_severity({})[:2], ("unknown", "no rating published"))
        notice = {"affected": [{"database_specific": {"informational": "unmaintained", "cvss": None}}]}
        self.assertEqual(scan.osv_severity(notice)[:2], ("info", "notice: unmaintained"))


GHSA = {"id": "GHSA-h5c8-rqwp-cp95", "summary": "Jinja2 xmlattr filter", "aliases": ["CVE-2024-22195", "PYSEC-2026-1473"],
        "database_specific": {"severity": "MODERATE"},
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"}]}
PYSEC = {"id": "PYSEC-2026-1473", "summary": "", "aliases": ["CVE-2024-22195", "GHSA-h5c8-rqwp-cp95"],
         "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"}]}


class AliasGroupingTest(unittest.TestCase):
    def test_ghsa_and_pysec_copies_of_one_cve_become_one_advisory(self):
        groups = scan.group_advisories([PYSEC, GHSA])
        self.assertEqual(len(groups), 1)
        g = groups[0]
        self.assertEqual(g["id"], "GHSA-h5c8-rqwp-cp95")
        self.assertEqual(g["aliases"], ["CVE-2024-22195", "PYSEC-2026-1473"])
        self.assertEqual(g["severity"], "moderate")
        self.assertEqual(g["title"], "Jinja2 xmlattr filter")
        self.assertEqual(g["url"], "https://github.com/advisories/GHSA-h5c8-rqwp-cp95")

    def test_reviewed_label_wins_over_a_copy_with_a_harsher_vector(self):
        low = {"id": "GHSA-248v-346w-9cwc", "aliases": ["PYSEC-2024-230"], "database_specific": {"severity": "LOW"}}
        copy = {"id": "PYSEC-2024-230", "aliases": ["GHSA-248v-346w-9cwc"],
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"}]}
        self.assertEqual(scan.group_advisories([copy, low])[0]["severity"], "low")

    def test_unlabelled_group_takes_the_best_vector_and_unrelated_stay_apart(self):
        a = {"id": "PYSEC-2030-1", "aliases": ["CVE-2030-0001"],
             "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        b = {"id": "PYSEC-2030-2"}
        groups = {g["id"]: g for g in scan.group_advisories([a, b])}
        self.assertEqual(groups["PYSEC-2030-1"]["severity"], "critical")
        self.assertEqual(groups["PYSEC-2030-1"]["url"], "https://osv.dev/vulnerability/PYSEC-2030-1")
        self.assertEqual(groups["PYSEC-2030-2"]["severity"], "unknown")

    def test_withdrawn_advisories_are_dropped(self):
        self.assertEqual(scan.group_advisories([dict(GHSA, withdrawn="2026-01-01T00:00:00Z")]), [])


class SemverTest(unittest.TestCase):
    def test_comparator_sets(self):
        yes = [("2.3.1", "<2.3.2"), ("4.0.2", ">=4.0.0 <4.0.4"), ("16.4.0", ">=16.0.0 <=16.4.0"),
               ("3.0.0", "<2.3.2 || >=3.0.0 <3.0.1"), ("2.1.0-beta.7", ">=2.1.0-beta.7 <4.1.12"),
               ("1.2.3", "=1.2.3"), ("1.2.3", "1.2.3"), ("1.2.3", "*"), ("0.21.0", "<=0.24.2"), ("1.0.0", ">0.9.9")]
        no = [("4.0.4", ">=4.0.0 <4.0.4"), ("2.3.2", "<2.3.2"), ("2.1.0-beta.6", ">=2.1.0-beta.7 <4.1.12"),
              ("1.0.0-rc.1", ">=1.0.0"), ("2.5.0", "<2.3.2 || >=3.0.0 <3.0.1")]
        for v, r in yes:
            self.assertIs(scan.semver_satisfies(v, r), True, (v, r))
        for v, r in no:
            self.assertIs(scan.semver_satisfies(v, r), False, (v, r))

    def test_unreadable_input_is_none_not_a_guess(self):
        self.assertIsNone(scan.semver_satisfies("1.0.0", "~1.0 weird"))
        self.assertIsNone(scan.semver_satisfies("not-a-version", "<2.0.0"))


if __name__ == "__main__":
    unittest.main()
