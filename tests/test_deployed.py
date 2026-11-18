"""Live versus merged: which commit is deployed, and is the advisory still in it. Real git repos, recorded OSV."""
import json, sys, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scan  # noqa: E402
from harness import HIGH, Harness  # noqa: E402

BAD, GOOD = "requests==2.31.0\n", "requests==2.32.0\n"


class DeployedTest(Harness):
    def repo(self, first=BAD, second=GOOD):
        """A repo 'api' whose first commit is live and whose checkout is one commit ahead."""
        d = self.project("api")
        live = self.commit(d, "ship", **{"requirements.txt": first})
        self.git(d, "tag", "live")
        head = self.commit(d, "bump", **{"requirements.txt": second})
        return d, live, head

    def run_scan(self, deployed, *extra, **cfg):
        rc, out = self.main("--config", self.config(exposed=["api"], deployed={"api": deployed}, **cfg), "--json", *extra)
        return rc, json.loads(out)["projects"][0]

    def test_fix_is_merged_but_the_live_commit_still_has_it(self):
        # the case that matters most: three clean checkouts say nothing about what customers are hitting
        d, live, head = self.repo()
        rc, p = self.run_scan({"ref": "live"})
        self.assertEqual(p["findings"], [])                                  # this checkout is fixed
        dep = p["deployed"]
        self.assertEqual((dep["status"], dep["commit"], dep["source"]), ("differs", live[:7], "ref live"))
        self.assertEqual([(f["id"], f["versions"]) for f in dep["findings"]], [(HIGH["id"], ["2.31.0"])])
        self.assertEqual([m["status"] for m in dep["manifests"]], ["scanned"])
        self.assertEqual(rc, 1)                                              # production is still exposed

    def test_report_says_what_is_live(self):
        self.repo()
        rc, out = self.main("--config", self.config(exposed=["api"], deployed={"api": {"ref": "live"}}))
        _, md, _ = self.report()
        self.assertEqual(rc, 1)
        self.assertIn("1 needs action", out)
        self.assertIn("not this checkout", md)
        self.assertIn("still in what is live", md)
        self.assertIn(HIGH["id"], md)

    def test_live_matches_the_checkout(self):
        d, live, head = self.repo()
        rc, p = self.run_scan({"ref": "main"})
        self.assertEqual((rc, p["deployed"]["status"], p["deployed"]["commit"], p["deployed"]["findings"]),
                         (0, "same", head[:7], []))

    def test_vulnerable_checkout_ahead_of_a_clean_live_commit_still_counts(self):
        self.repo(first=GOOD, second=BAD)
        rc, p = self.run_scan({"ref": "live"})
        self.assertEqual((rc, len(p["findings"]), p["deployed"]["findings"]), (1, 1, []))

    def test_command_can_report_the_live_commit(self):
        d, live, head = self.repo()
        rc, p = self.run_scan({"command": f"echo '{live}  deployed 3 days ago'"})
        self.assertEqual((p["deployed"]["status"], p["deployed"]["commit"], p["deployed"]["source"]), ("differs", live[:7], "command"))
        rc, p = self.run_scan({"command": "echo live"})                      # a tag or branch name works too
        self.assertEqual(p["deployed"]["commit"], live[:7])

    def test_unknown_live_commit_is_an_incomplete_scan(self):
        self.repo(first=GOOD, second=GOOD)
        for spec, words in (({"command": "exit 3"}, "command failed"), ({"command": "echo"}, "printed nothing"),
                            ({"command": "echo 0123456789abcdef0123456789abcdef01234567"}, "not in this checkout"),
                            ({"ref": "origin/production"}, "not in this checkout"), ({}, "needs a ref or a command")):
            rc, p = self.run_scan(spec)
            self.assertEqual((rc, p["deployed"]["status"]), (2, "failed"), spec)
            self.assertIn(words, p["deployed"]["detail"], spec)

    def test_unknown_live_commit_is_in_the_report(self):
        self.repo(first=GOOD, second=GOOD)
        rc, out = self.main("--config", self.config(exposed=["api"], deployed={"api": {"command": "exit 3"}}))
        _, md, _ = self.report()
        self.assertEqual(rc, 2)
        self.assertIn("live commit unknown", out)
        self.assertIn("## Scan problems", md)
        self.assertIn("code/api: live commit unknown", md)

    def test_audit_failure_at_the_live_commit_is_incomplete(self):
        self.repo(first=BAD, second=GOOD)
        self.osv_down = True
        rc, p = self.run_scan({"ref": "live"})
        self.assertEqual(rc, 2)
        self.assertEqual([m["status"] for m in p["deployed"]["manifests"]], ["failed"])

    def test_folder_outside_git(self):
        self.project("api", requirements=GOOD)
        rc, p = self.run_scan({"ref": "main"})
        self.assertEqual((rc, p["deployed"]["status"]), (2, "failed"))
        self.assertIn("not a git repository", p["deployed"]["detail"])

    def test_manifest_added_after_the_live_commit(self):
        d = self.project("api")
        self.commit(d, "ship", **{"README.md": "hi\n"})
        self.git(d, "tag", "live")
        self.commit(d, "add deps", **{"requirements.txt": GOOD})
        rc, p = self.run_scan({"ref": "live"})
        self.assertEqual((rc, p["deployed"]["status"], p["deployed"]["manifests"], p["deployed"]["findings"]), (0, "differs", [], []))

    def test_project_in_a_subfolder_and_ignore_rules_reach_the_live_findings(self):
        d = self.project("api")   # the repo root is code/api, the project is code/api/services/web
        self.commit(d, "ship", **{"services__web__requirements.txt": BAD})
        self.git(d, "tag", "live")
        self.commit(d, "bump", **{"services__web__requirements.txt": GOOD})
        cfg = self.config(max_depth=None, exposed=["web"], deployed={"services/web": {"ref": "live"}},
                          ignore=[{"advisory": HIGH["id"], "reason": "not reachable"}])
        rc, out = self.main("--config", cfg, "--json")
        p = json.loads(out)["projects"][0]
        self.assertEqual((p["name"], p["deployed"]["status"]), ("code/api/services/web", "differs"))
        self.assertEqual(p["deployed"]["findings"][0]["ignored"], {"reason": "not reachable"})
        self.assertEqual(rc, 0)


class VerifyFixedTest(Harness):
    def verify(self, *ids):
        return self.main("--repo", str(self.code), "--verify-fixed", *ids)

    def test_still_present_then_gone(self):
        d = self.project("api", requirements=BAD)
        rc, out = self.verify(HIGH["id"])
        self.assertEqual(rc, 1)
        self.assertIn(f"{HIGH['id']}: still present", out)
        self.assertIn("requests 2.31.0", out)
        (d / "requirements.txt").write_text(GOOD)
        rc, out = self.verify("CVE-2030-0002")                               # an alias works
        self.assertEqual(rc, 0)
        self.assertIn("CVE-2030-0002: gone", out)

    def test_a_dev_only_copy_still_counts_as_present(self):
        d = self.project("api")
        (d / "requirements-dev.txt").write_text(BAD)
        self.assertEqual(self.verify(HIGH["id"])[0], 1)

    def test_cannot_confirm_when_the_scan_failed(self):
        # a bump "verified" by an audit that never ran is the failure this flag exists to stop
        self.project("api", requirements=GOOD)
        self.osv_down = True
        rc, out = self.verify(HIGH["id"])
        self.assertEqual(rc, 2)
        self.assertIn("cannot confirm", out)

    def test_cannot_confirm_when_part_was_not_scanned(self):
        self.project("api", requirements="requests>=2\nflask==3.0.0\n")
        rc, out = self.verify(HIGH["id"])
        self.assertEqual(rc, 2)
        self.assertIn("cannot confirm", out)


if __name__ == "__main__":
    unittest.main()
