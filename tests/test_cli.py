"""End to end through main(): real discovery and report writing, with the two network edges (npm audit, OSV) recorded."""
import json, shutil, sys, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scan  # noqa: E402
from harness import FIX, HIGH, NEEDS_TOML, Harness  # noqa: E402


class FullRunTest(Harness):
    @NEEDS_TOML
    def test_mixed_npm_and_uv_project_scans_both_sides(self):
        # the reviewers' case: v2 scanned the npm half and reported the project as done
        self.project("shop", npm=True, uv=True)
        rc, out = self.main("--config", self.config(exposed=["shop"]))
        data, md, day = self.report()
        self.assertEqual(rc, 1)
        p = data["projects"][0]
        self.assertEqual((data["schema"], p["name"], p["exposed"]), (3, "code/shop", True))
        self.assertEqual({m["file"]: m["status"] for m in p["manifests"]}, {"package-lock.json": "scanned", "uv.lock": "scanned"})
        self.assertEqual({f["manifest"] for f in p["findings"]}, {"package-lock.json", "uv.lock"})
        self.assertEqual(len(p["findings"]), 19)
        self.assertIn("1 needs action", out)
        self.assertIn("## code/shop (LIVE)", md)
        self.assertIn("## How this was scanned", md)
        for name in ("report.sarif", "run.log"):
            self.assertTrue((day / name).exists(), name)

    def test_failed_audit_is_exit_2_and_says_so(self):
        self.project("api", requirements="requests==2.31.0\n")
        self.osv_down = True
        rc, out = self.main("--config", self.config(exposed=["api"]))
        data, md, _ = self.report()
        self.assertEqual(rc, 2)
        self.assertEqual(data["projects"][0]["manifests"][0]["status"], "failed")
        self.assertIn("1 manifest could not be scanned", out)
        self.assertIn("## Scan problems", md)

    def test_json_output_has_the_same_exit_codes(self):
        # v2 returned 0 from --json before looking at the findings
        self.project("api", requirements="requests==2.31.0\n")
        cfg = self.config(exposed=["api"])
        rc, out = self.main("--config", cfg, "--json")
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out)["projects"][0]["findings"][0]["id"], HIGH["id"])
        self.assertFalse((self.tmp / "reports").exists())   # --json prints; it does not write report files
        self.osv_down = True
        self.assertEqual(self.main("--config", cfg, "--json")[0], 2)

    def test_second_run_reports_the_change_and_keeps_stale_findings(self):
        self.project("api", requirements="requests==2.31.0\n")
        cfg = self.config(exposed=["api"])
        with mock.patch.object(scan, "today", return_value="2026-10-01"):
            self.assertEqual(self.main("--config", cfg)[0], 1)
        self.osv_down = True
        with mock.patch.object(scan, "today", return_value="2026-11-01"):
            rc, out = self.main("--config", cfg)
        self.assertEqual(rc, 1)   # still urgent: the audit failed, the last known high finding stands
        md = (self.tmp / "reports" / "2026-11-01" / "report.md").read_text()
        self.assertIn("## Since the last scan (2026-10-01)", md)
        self.assertIn("**Fixed:** 0", md)
        self.assertIn("not re-checked since 2026-10-01", md)

    def test_missing_roots_dry_run_and_unknown_keys(self):
        self.project("shop", npm=True)
        self.assertEqual(self.main("--roots", str(self.tmp / "missing"))[0], 2)
        rc, out = self.main("--config", self.config(), "--dry-run")
        self.assertEqual(rc, 0)
        self.assertIn("1 project, 1 manifest would be scanned", out)
        rc, _ = self.main("--config", self.config(roots=[str(self.code), str(self.tmp / "usb")]))
        self.assertEqual(rc, 1)   # a critical in what could be scanned still wins...
        _, md, _ = self.report()
        self.assertIn("roots not found", md)   # ...and the missing root is in the report

    def test_missing_root_alone_is_incomplete(self):
        self.project("api", requirements="zzz==1.0\n")
        rc, out = self.main("--config", self.config(roots=[str(self.code), str(self.tmp / "usb")]))
        self.assertEqual(rc, 2)
        self.assertIn("roots not found", out)

    def test_repo_mode_counts_every_project_as_live(self):
        self.project("api", requirements="requests==2.31.0\n")
        rc, out = self.main("--repo", str(self.code), "--json")
        data = json.loads(out)
        self.assertEqual((rc, data["projects"][0]["exposed"], data["projects"][0]["name"]), (1, True, "code/api"))

    def test_repo_mode_never_writes_into_the_machine_report_folder(self):
        # a one-repo report in the shared folder would become "the last scan" and wreck the next change list
        self.project("api", requirements="requests==2.31.0\n")
        with mock.patch.object(scan, "DEFAULT_OUT", str(self.tmp / "machine-reports")):
            rc, out = self.main("--repo", str(self.code))
            self.assertEqual(rc, 1)
            self.assertIn("1 needs action", out)
            self.assertFalse((self.tmp / "machine-reports").exists())
            self.main("--repo", str(self.code), "--out", str(self.tmp / "ci"), "--sarif", str(self.tmp / "ci.sarif"))
            self.assertTrue(any((self.tmp / "ci").rglob("report.md")))
            self.assertEqual(json.loads((self.tmp / "ci.sarif").read_text())["version"], "2.1.0")
            self.assertFalse((self.tmp / "machine-reports").exists())

    def test_sarif_path_in_a_folder_that_does_not_exist_yet(self):
        self.project("api", requirements="requests==2.31.0\n")
        target = self.tmp / "new" / "deep" / "results.sarif"
        rc, _ = self.main("--repo", str(self.code), "--sarif", str(target))
        self.assertEqual(rc, 1)
        self.assertEqual(len(json.loads(target.read_text())["runs"][0]["results"]), 1)

    def test_a_crash_is_exit_2_never_1(self):
        # exit 1 means "findings need action": a crash must not look like that, or like a pass
        self.project("api", requirements="requests==2.31.0\n")
        with mock.patch.object(scan, "summarize", side_effect=RuntimeError("boom")):
            rc, out = self.entry("--repo", str(self.code))
        self.assertEqual(rc, 2)
        self.assertIn("dep-patrol crashed", out)
        self.assertIn("boom", out)

    def test_max_depth_flag(self):
        self.project("api", requirements="requests==2.31.0\n")
        (self.code / "requirements.txt").write_text("zzz==1.0\n")
        rc, out = self.main("--repo", str(self.code), "--max-depth", "0", "--json")
        self.assertEqual([p["name"] for p in json.loads(out)["projects"]], ["code"])

    def test_an_exposed_or_deployed_entry_that_matches_nothing_is_a_problem(self):
        # a live app whose folder moved (or was misspelt) would otherwise just stop being treated as live
        self.project("api", requirements="zzz==1.0\n")
        cfg = self.config(exposed=["api", "old-shop"], deployed={"gone/web": {"ref": "main"}})
        rc, out = self.main("--config", cfg)
        data, md, _ = self.report()
        self.assertEqual(rc, 2)
        self.assertEqual(len(data["problems"]), 2)
        self.assertIn("old-shop", md)
        self.assertIn("gone/web", md)
        rc, out = self.main("--repo", str(self.code), "--config", cfg, "--json")   # a shared config in CI: not this repo's concern
        self.assertEqual((rc, json.loads(out)["problems"]), (0, []))

    def test_exposed_only_skips_everything_else(self):
        self.project("api", requirements="requests==2.31.0\n")
        self.project("lab", requirements="requests==2.31.0\n")
        rc, out = self.main("--config", self.config(exposed=["api"]), "--exposed-only", "--json")
        self.assertEqual([p["name"] for p in json.loads(out)["projects"]], ["code/api"])

    def test_ignore_rule_from_config_and_unused_rule_warning(self):
        self.project("api", requirements="requests==2.31.0\n")
        cfg = self.config(exposed=["api"], ignore=[{"advisory": "CVE-2030-0002", "reason": "not reachable"},
                                                   {"advisory": "GHSA-zzzz-zzzz-zzzz", "reason": "old"}])
        rc, out = self.main("--config", cfg)
        data, md, _ = self.report()
        self.assertEqual(rc, 0)
        self.assertEqual(data["projects"][0]["findings"][0]["ignored"], {"reason": "not reachable"})
        self.assertIn("GHSA-zzzz-zzzz-zzzz", " ".join(data["warnings"]))

    def test_notify_runs_for_urgent_and_for_a_broken_scan(self):
        self.project("api", requirements="requests==2.31.0\n")
        marker = self.tmp / "notified.txt"
        cfg = self.config(exposed=["api"], notify=f'printf "%s" "$DEP_PATROL_SUMMARY" > {marker}')
        self.main("--config", cfg, "--notify")
        self.assertIn("1 needs action", marker.read_text())
        marker.unlink()
        self.osv_down = True
        shutil.rmtree(self.tmp / "reports")   # no earlier report: nothing to carry forward, only the failure
        self.main("--config", cfg, "--notify")
        self.assertIn("could not be scanned", marker.read_text())   # v2 stayed silent when the scan itself broke

    def test_a_crashing_adapter_fails_that_manifest_only(self):
        self.project("shop", npm=True)
        self.project("api", requirements="zzz==1.0\n")
        with mock.patch.object(scan, "npm_parse", side_effect=KeyError("nodes")):
            rc, out = self.main("--config", self.config(), "--json")
        ms = {p["name"]: p["manifests"][0] for p in json.loads(out)["projects"]}
        self.assertEqual((rc, ms["code/shop"]["status"], ms["code/api"]["status"]), (2, "failed", "scanned"))
        self.assertIn("scanner error", ms["code/shop"]["detail"])

    def test_no_toml_reader_is_unscanned_not_silent(self):
        self.project("svc", uv=True)
        with mock.patch.object(scan, "tomllib", None), mock.patch.object(scan.shutil, "which", return_value=None):
            rc, out = self.main("--config", self.config(), "--json")
        m = json.loads(out)["projects"][0]["manifests"][0]
        self.assertEqual((rc, m["status"]), (0, "unscanned"))
        self.assertIn("3.11", m["detail"])


if __name__ == "__main__":
    unittest.main()
