"""Safeguards: the package managers' own settings, read with depsguard when it is installed. Real tool output, recorded."""
import json, sys, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scan  # noqa: E402
from harness import FIX, Harness  # noqa: E402

USER = (FIX / "depsguard/user.txt").read_text()      # depsguard scan --no-search: this machine's own settings
ROOT = (FIX / "depsguard/root.txt").read_text()      # depsguard scan in a code folder: the same again, plus three repos' files
SECURE = (FIX / "depsguard/secure.txt").read_text()  # everything set


class ParseTest(unittest.TestCase):
    def test_each_config_file_with_its_settings(self):
        blocks = {b["config"]: b for b in scan.parse_depsguard(USER)}
        self.assertEqual(list(blocks), ["~/.npmrc", "~/Library/Preferences/pnpm/config.yaml", "~/.bunfig.toml",
                                        "~/.config/uv/uv.toml", "~/.yarnrc.yml"])
        npmrc = blocks["~/.npmrc"]
        self.assertEqual(npmrc["what"], "npm v10.9.7 · pnpm v11.2.2")
        self.assertEqual([i["state"] for i in npmrc["items"]], ["unsupported", "missing"])
        self.assertEqual(npmrc["items"][1]["text"], "(npm) ignore-scripts: not set. Block malicious install scripts")
        self.assertEqual(len(blocks["~/Library/Preferences/pnpm/config.yaml"]["items"]), 5)

    def test_no_banner_progress_line_or_control_character_survives(self):
        text = json.dumps(scan.parse_depsguard(USER), ensure_ascii=False)
        for junk in ("\x1b", "Checking", "╭", "arnica", "Detected locations"):
            self.assertNotIn(junk, text)

    def test_a_wrong_value_needs_action_and_a_set_one_is_set(self):
        ws = {b["config"]: b for b in scan.parse_depsguard(ROOT)}["~/code/shop/pnpm-workspace.yaml"]
        self.assertEqual([(i["state"], i["text"]) for i in ws["items"]],
                         [("missing", "minimumReleaseAge: 1440 (want: 10080). Delay new versions by 7 days"),
                          ("ok", "ignoreScripts: true. Block malicious install scripts")])

    def test_text_that_is_not_a_report_gives_nothing(self):
        self.assertEqual(scan.parse_depsguard("depsguard: something else entirely\n"), [])
        self.assertEqual(scan.parse_depsguard(""), [])


class SafeguardsTest(Harness):
    def setUp(self):
        super().setUp()
        self.have, self.calls, self.answer = "/bin/depsguard", [], None

        def fake_scan(exe, cwd, search):
            self.calls.append((str(cwd), search))
            if self.answer is not None:
                return self.answer
            return (1, ROOT if search else USER, "")
        for target, fake in (("find_depsguard", lambda: self.have), ("depsguard_scan", fake_scan),
                             ("depsguard_version", lambda exe: "0.1.40")):
            p = mock.patch.object(scan, target, side_effect=fake)
            p.start()
            self.addCleanup(p.stop)

    def run_scan(self, *extra, **cfg):
        rc, out = self.main("--config", self.config(**cfg), *extra)
        return rc, out

    def test_the_report_gets_a_safeguards_section(self):
        self.project("api", requirements="requests==2.32.0\n")
        rc, out = self.run_scan()
        data, md, _ = self.report()
        s = data["safeguards"]
        self.assertEqual((s["status"], s["tool"], s["version"]), ("action", "depsguard", "0.1.40"))
        self.assertEqual(s["counts"], {"missing": 10, "unsupported": 2, "ok": 2})
        self.assertEqual(len(s["configs"]), 8)                      # the machine's five once, not once per run, and three repos' files
        self.assertEqual([c["where"] for c in s["configs"]], ["machine"] * 5 + ["code"] * 3)
        self.assertIn("## Safeguards", md)
        self.assertIn("depsguard 0.1.40", md)
        self.assertIn("### This machine", md)
        self.assertIn("`~/.npmrc` (npm v10.9.7 · pnpm v11.2.2)", md)
        self.assertIn("### In your code folders", md)
        self.assertIn("`~/code/shop/pnpm-workspace.yaml`", md)
        self.assertIn("1440 (want: 10080)", md)
        self.assertIn("1 more has everything set", md)             # the renovate file: counted, not listed
        self.assertNotIn("~/code/api/renovate.json", md)

    def test_the_two_cautions_come_with_it(self):
        self.project("api", requirements="requests==2.32.0\n")
        self.run_scan()
        md = self.report()[1]
        self.assertIn("also delays a security fix", md)
        self.assertIn("bump-and-verify.sh", md)
        self.assertIn("install scripts", md)
        self.assertIn("better-sqlite3", md)

    def test_missing_safeguards_never_change_the_exit_code(self):
        self.project("api", requirements="requests==2.32.0\n")       # nothing vulnerable
        rc, out = self.run_scan()
        self.assertEqual(rc, 0, out)
        self.assertIn("Safeguards: 10 not set", out)

    def test_not_installed_is_one_line_that_says_so(self):
        self.project("api", requirements="requests==2.32.0\n")
        self.have = None
        rc, out = self.run_scan()
        data, md, _ = self.report()
        self.assertEqual((rc, data["safeguards"]["status"], self.calls), (0, "not_installed", []))
        self.assertIn("## Safeguards", md)
        self.assertIn("Not checked", md)
        self.assertIn("https://github.com/arnica/depsguard", md)
        self.assertNotIn("Safeguards:", out)

    def test_everything_set(self):
        self.project("api", requirements="requests==2.32.0\n")
        self.answer = (0, SECURE, "")
        rc, out = self.run_scan()
        data, md, _ = self.report()
        self.assertEqual((rc, data["safeguards"]["status"], data["safeguards"]["counts"]),
                         (0, "ok", {"missing": 0, "unsupported": 0, "ok": 2}))
        self.assertIn("Every setting it checks is set", md)
        self.assertNotIn("Safeguards:", out)

    def test_a_check_that_could_not_run_says_so_and_changes_nothing_else(self):
        self.project("api", requirements="requests==2.32.0\n")
        self.answer = (101, "", "thread 'main' panicked at src/ui.rs:1:1")
        rc, out = self.run_scan()
        data, md, _ = self.report()
        self.assertEqual((rc, data["safeguards"]["status"]), (0, "failed"))
        self.assertIn("panicked", data["safeguards"]["detail"])
        self.assertIn("could not be checked", md)

    def test_output_it_cannot_read_is_kept_as_it_is(self):
        self.project("api", requirements="requests==2.32.0\n")
        self.answer = (1, "a new report layout nobody has seen\n", "")
        self.run_scan()
        data, md, _ = self.report()
        self.assertEqual((data["safeguards"]["status"], data["safeguards"]["configs"]), ("action", []))
        self.assertIn("a new report layout nobody has seen", md)

    def test_switched_off_in_the_config(self):
        self.project("api", requirements="requests==2.32.0\n")
        self.run_scan(safeguards=False)
        data, md, _ = self.report()
        self.assertEqual((data["safeguards"]["status"], self.calls), ("off", []))
        self.assertNotIn("## Safeguards", md)

    def test_a_one_repository_scan_leaves_it_out(self):
        d = self.project("api", requirements="requests==2.32.0\n")
        rc, out = self.main("--repo", str(d), "--json")
        self.assertEqual((json.loads(out)["safeguards"]["status"], self.calls), ("off", []))

    def test_json_output_carries_it(self):
        self.project("api", requirements="requests==2.32.0\n")
        rc, out = self.run_scan("--json")
        self.assertEqual(json.loads(out)["safeguards"]["counts"]["missing"], 10)

    def test_the_machine_once_then_each_code_folder(self):
        self.project("api", requirements="requests==2.32.0\n")
        other = self.tmp / "other"
        (other / "web").mkdir(parents=True)
        (other / "web" / "requirements.txt").write_text("requests==2.32.0\n")
        self.run_scan(roots=[str(self.code), str(other), str(self.tmp / "not-there")])
        self.assertEqual([c[1] for c in self.calls], [False, True, True])
        self.assertEqual([c[0] for c in self.calls][1:], [str(self.code), str(other)])
        self.assertEqual(len(self.report()[0]["safeguards"]["configs"]), 8)

    def test_a_dry_run_does_not_run_it(self):
        self.project("api", requirements="requests==2.32.0\n")
        self.run_scan("--dry-run")
        self.assertEqual(self.calls, [])

    def test_the_change_list_still_works_beside_it(self):
        self.project("api", requirements="requests==2.31.0\n")       # a high in a live app: needs action on its own
        rc, _ = self.run_scan(exposed=["api"])
        self.assertEqual(rc, 1)
        self.assertEqual(self.report()[0]["safeguards"]["status"], "action")


if __name__ == "__main__":
    unittest.main()
