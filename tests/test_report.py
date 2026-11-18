"""Policy on top of findings: ignore rules, urgency, exit codes, change tracking, the report and SARIF. Offline."""
import json, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scan  # noqa: E402

A, B, C = "GHSA-aaaa-aaaa-aaaa", "GHSA-bbbb-bbbb-bbbb", "GHSA-cccc-cccc-cccc"


def fnd(aid=A, package="next", severity="critical", scope="production", manifest="package-lock.json", aliases=(), **kw):
    f = scan.new_finding(aid, package, "npm", manifest, severity, scope, True, ["1.0.0"], "<2", f"{package}@2",
                         f"{package}: bad thing", None, aliases=aliases)
    f.update(kw)
    return f


def man(file="package-lock.json", status="scanned", ecosystem="npm", detail=None):
    return {"file": file, "ecosystem": ecosystem, "status": status, "detail": detail, "seconds": 0.1, "packages": 10}


def proj(name, exposed=False, findings=(), manifests=None, path=None, root=None):
    return {"name": name, "path": path or f"/x/{name}", "exposed": exposed, "deployed": None,
            "git": {"branch": "main", "commit": "abc1234", "date": "2026-11-01", "dirty": False, "root": root},
            "manifests": manifests if manifests is not None else [man()], "findings": list(findings)}


def rep(*projects, generated="2026-11-01", problems=()):
    return {"schema": 3, "version": scan.VERSION, "generated": generated, "problems": list(problems), "warnings": [],
            "projects": list(projects)}


RULES = dict(scan.DEFAULT_URGENCY)


class ExposureTest(unittest.TestCase):
    def test_exposed_matching_is_precise(self):
        self.assertTrue(scan.is_exposed("/a/shop/web", "shop/web", ["shop/web"]))
        self.assertFalse(scan.is_exposed("/a/blog/web", "blog/web", ["shop/web"]))
        self.assertFalse(scan.is_exposed("/a/webapp", "webapp", ["web"]))
        self.assertTrue(scan.is_exposed("/a/web", "web", ["web"]))
        self.assertTrue(scan.is_exposed("/a/site-prod", "site-prod", ["*-prod"]))
        self.assertFalse(scan.is_exposed("/a/myshop/web", "a/myshop/web", ["shop/web"]))
        self.assertTrue(scan.is_exposed("/a/shop/web", "a/shop/web", ["a/shop/web"]))


class MergeTest(unittest.TestCase):
    def test_same_advisory_on_two_copies_is_one_finding(self):
        a = fnd(scope="dev", via=["vitest"])
        a["versions"], a["direct"] = ["4.6.1"], False
        b = fnd(scope="unknown")
        b["versions"], b["direct"] = ["2.4.2"], None
        merged = scan.merge_findings([a, b, fnd(B)])
        self.assertEqual(len(merged), 2)
        m = next(f for f in merged if f["id"] == A)
        self.assertEqual((m["versions"], m["scope"], m["direct"], m["via"]), (["2.4.2", "4.6.1"], "unknown", None, ["vitest"]))


class IgnoreTest(unittest.TestCase):
    def test_one_of_two_advisories_on_a_package_can_be_ignored(self):
        # v2 matched on the package and dropped every advisory with it
        r = rep(proj("app", True, [fnd(A), fnd(B)]))
        unused = scan.apply_ignores(r, [{"advisory": A, "reason": "build-time only"}])
        fa, fb = r["projects"][0]["findings"]
        self.assertEqual(fa["ignored"], {"reason": "build-time only"})
        self.assertNotIn("ignored", fb)
        self.assertEqual(unused, [])
        self.assertEqual([f["id"] for f in scan.urgent_findings(r["projects"][0], RULES)], [B])

    def test_matching_is_exact_never_a_substring(self):
        r = rep(proj("app", True, [fnd(A, package="next-auth")]))
        rules = [{"match": "GHSA-aaaa", "reason": "x"}, {"match": "next", "reason": "x"}, {"package": "auth", "reason": "x"}]
        unused = scan.apply_ignores(r, rules)
        self.assertNotIn("ignored", r["projects"][0]["findings"][0])
        self.assertEqual(unused, rules)

    def test_alias_url_package_and_legacy_match(self):
        for rule in ({"advisory": "CVE-2030-0001"}, {"advisory": "https://github.com/advisories/" + A},
                     {"advisory": A.lower()}, {"package": "Next"}, {"match": A}, {"match": "next"},
                     {"advisory": A, "package": "next"}):
            r = rep(proj("app", True, [fnd(A, aliases=["CVE-2030-0001"])]))
            scan.apply_ignores(r, [dict(rule, reason="because")])
            self.assertIn("ignored", r["projects"][0]["findings"][0], rule)

    def test_advisory_plus_package_must_both_match_and_project_scopes_the_rule(self):
        r = rep(proj("app", True, [fnd(A, package="other")]), proj("tools/cli", True, [fnd(A)]))
        scan.apply_ignores(r, [{"advisory": A, "package": "next", "project": "tools/*", "reason": "r"}])
        self.assertNotIn("ignored", r["projects"][0]["findings"][0])
        self.assertIn("ignored", r["projects"][1]["findings"][0])

    def test_config_rejects_rules_without_a_target_or_reason(self):
        with tempfile.TemporaryDirectory() as t:
            cfg = Path(t) / "c.json"
            cfg.write_text(json.dumps({"roots": [t], "ignore": [{"reason": "no target"}, {"advisory": A}]}))
            _, problems, _ = scan.load_config(str(cfg), None)
            self.assertEqual(len([p for p in problems if "ignore" in p]), 2)


class UrgencyTest(unittest.TestCase):
    def urgent(self, p, **rules):
        return bool(scan.urgent_findings(p, dict(RULES, **rules)))

    def test_rules(self):
        self.assertTrue(self.urgent(proj("a", False, [fnd(severity="critical")])))
        self.assertTrue(self.urgent(proj("b", True, [fnd(severity="high")])))
        self.assertFalse(self.urgent(proj("c", False, [fnd(severity="high")])))
        self.assertFalse(self.urgent(proj("d", True, [])))
        self.assertFalse(self.urgent(proj("e", True, [fnd(severity="moderate")])))
        self.assertTrue(self.urgent(proj("e", True, [fnd(severity="moderate")]), moderate_on_exposed=True))
        self.assertFalse(self.urgent(proj("f", False, [fnd(severity="critical")]), critical_always=False))
        self.assertTrue(self.urgent(proj("g", True, [fnd(severity="critical")]), critical_always=False))

    def test_dev_never_counts_and_unknown_scope_counts(self):
        self.assertFalse(self.urgent(proj("a", True, [fnd(severity="critical", scope="dev")])))
        self.assertTrue(self.urgent(proj("a", True, [fnd(severity="high", scope="unknown")])))

    def test_unrated_advisories_follow_their_own_rule(self):
        p = proj("a", True, [fnd(severity="unknown")])
        self.assertFalse(self.urgent(p))
        self.assertTrue(self.urgent(p, unknown_on_exposed=True))
        self.assertFalse(self.urgent(proj("a", True, [fnd(severity="info")]), unknown_on_exposed=True))

    def test_ignored_does_not_count_and_stale_still_does(self):
        self.assertFalse(self.urgent(proj("a", True, [fnd(ignored={"reason": "r"})])))
        self.assertTrue(self.urgent(proj("a", True, [fnd(stale="2026-10-01")])))


class ExitCodeTest(unittest.TestCase):
    def code(self, *projects, strict=False, problems=()):
        return scan.exit_code(rep(*projects, problems=problems), RULES, strict)

    def test_clean_urgent_and_incomplete(self):
        self.assertEqual(self.code(proj("a", True)), 0)
        self.assertEqual(self.code(proj("a", True, [fnd()])), 1)
        failed = proj("a", True, [], [man(status="failed", detail="npm audit: ENOTFOUND")])
        self.assertEqual(self.code(failed), 2)                           # v2: 0, a failed audit read as clean
        self.assertEqual(self.code(failed, proj("b", True, [fnd()])), 1)
        self.assertEqual(self.code(proj("a"), problems=["roots not found: /mnt/usb"]), 2)

    def test_strict_also_fails_what_was_not_scanned(self):
        for status in ("unscanned", "partial"):
            p = proj("a", False, [], [man(status=status)])
            self.assertEqual(self.code(p), 0, status)
            self.assertEqual(self.code(p, strict=True), 2, status)
        quiet = proj("a", False, [], [man(), man("packages/ui/package-lock.json", "covered"), man("yarn.lock", "skipped")])
        self.assertEqual(self.code(quiet, strict=True), 0)


class DeployedPolicyTest(unittest.TestCase):
    def with_live(self, **dep):
        p = proj("api", True)
        p["deployed"] = dict({"status": "differs", "commit": "abc1234", "date": "2026-10-20", "source": "ref live",
                              "detail": None, "manifests": [man("uv.lock", ecosystem="python")], "findings": []}, **dep)
        return p

    def test_a_finding_only_in_the_live_commit_is_urgent(self):
        p = self.with_live(findings=[fnd(severity="high", manifest="uv.lock")])
        self.assertEqual([f["id"] for f in scan.urgent_findings(p, RULES)], [A])
        self.assertEqual(scan.exit_code(rep(p), RULES), 1)

    def test_same_finding_in_checkout_and_live_counts_once(self):
        p = self.with_live(findings=[fnd(severity="high")])
        p["findings"] = [fnd(severity="high")]
        self.assertEqual(len(scan.urgent_findings(p, RULES)), 1)

    def test_checkout_behind_live_does_not_count_its_own_findings(self):
        p = self.with_live(checkout="behind")
        p["findings"] = [fnd(severity="critical")]
        self.assertEqual(scan.urgent_findings(p, RULES), [])
        self.assertEqual(scan.exit_code(rep(p), RULES), 0)
        md = scan.render(rep(p), RULES, None)
        self.assertIn("| api | yes |  |  |", md)                       # the table counts what is live
        self.assertIn("behind what is live", md)
        p["deployed"]["manifests"] = [man("uv.lock", "failed", "python")]   # live could not be scanned: fall back
        self.assertEqual(len(scan.urgent_findings(p, RULES)), 1)

    def test_behind_note_tallies_only_what_the_old_checkout_alone_carries(self):
        p = self.with_live(checkout="behind", findings=[fnd(B, severity="high")])
        p["findings"] = [fnd(A, severity="critical"), fnd(B, severity="high")]   # B is live too, A is only here
        md = scan.render(rep(p), RULES, None)
        self.assertIn("is not counted (1 critical).", md)

    def test_change_list_follows_what_counts(self):
        prev = rep(self.with_live(findings=[fnd(A, severity="high")], checkout="behind"), generated="2026-10-01")
        now = self.with_live(checkout="behind")
        now["findings"] = [fnd(B, severity="high")]                    # only in the stale checkout
        d = scan.diff_reports(rep(now), prev)
        self.assertEqual(([f["id"] for _, f in d["fixed"]], d["new"], d["open"]), ([A], [], 0))

    def test_unknown_or_unscannable_live_commit_is_incomplete(self):
        self.assertEqual(scan.exit_code(rep(self.with_live(status="failed", detail="command failed", manifests=[])), RULES), 2)
        self.assertEqual(scan.exit_code(rep(self.with_live(manifests=[man("uv.lock", "failed", "python")])), RULES), 2)
        self.assertEqual(scan.exit_code(rep(self.with_live()), RULES), 0)


class CarryForwardTest(unittest.TestCase):
    def test_failed_audit_keeps_last_known_findings(self):
        # the reviewers' case: a high finding last month, the audit fails this month -> must not read as clean
        prev = rep(proj("site", True, [fnd(severity="high"), fnd(B, manifest="uv.lock")],
                        [man(), man("uv.lock", ecosystem="python")]), generated="2026-10-01")
        now = rep(proj("site", True, [], [man(status="failed", detail="registry down"), man("uv.lock", ecosystem="python")]))
        scan.carry_forward(now, prev)
        kept = now["projects"][0]["findings"]
        self.assertEqual([(f["id"], f["stale"]) for f in kept], [(A, "2026-10-01")])   # only the failed manifest's
        self.assertEqual(scan.exit_code(now, RULES), 1)
        d = scan.diff_reports(now, prev)
        self.assertEqual((len(d["new"]), len(d["unverified"])), (0, 1))
        self.assertEqual([f["id"] for _, f in d["fixed"]], [B])   # uv.lock was rescanned fine and B is gone

    def test_stale_date_is_the_last_time_it_was_really_seen(self):
        prev = rep(proj("site", True, [fnd(stale="2026-09-01", ignored={"reason": "old rule"})]), generated="2026-10-01")
        now = rep(proj("site", True, [], [man(status="failed")]))
        scan.carry_forward(now, prev)
        f = now["projects"][0]["findings"][0]
        self.assertEqual(f["stale"], "2026-09-01")
        self.assertNotIn("ignored", f)   # ignore rules are applied fresh each run

    def test_legacy_previous_report_is_left_alone(self):
        now = rep(proj("site", True, [], [man(status="failed")]))
        scan.carry_forward(now, [{"name": "site", "prod": []}])
        self.assertEqual(now["projects"][0]["findings"], [])
        self.assertIsNone(scan.diff_reports(now, [{"name": "site", "prod": []}]))


class DiffTest(unittest.TestCase):
    def test_new_fixed_and_still_open(self):
        prev = rep(proj("site", True, [fnd(A), fnd(B)]), generated="2026-10-01")
        now = rep(proj("site", True, [fnd(B), fnd(C)]))
        d = scan.diff_reports(now, prev)
        self.assertEqual(d["previous"], "2026-10-01")
        self.assertEqual(([f["id"] for _, f in d["new"]], [f["id"] for _, f in d["fixed"]], d["open"]), ([C], [A], 1))

    def test_an_advisory_that_changed_its_main_id_is_the_same_advisory(self):
        prev = rep(proj("api", True, [fnd("PYSEC-2030-1", aliases=["CVE-2030-0001"])]), generated="2026-10-01")
        now = rep(proj("api", True, [fnd(A, aliases=["CVE-2030-0001", "PYSEC-2030-1"])]))
        d = scan.diff_reports(now, prev)
        self.assertEqual((d["new"], d["fixed"], d["open"]), ([], [], 1))

    def test_gone_project_and_newly_ignored_are_not_fixed(self):
        prev = rep(proj("site", True, [fnd(A)]), proj("old", False, [fnd(B), fnd(C)]), generated="2026-10-01")
        now = rep(proj("site", True, [fnd(A, ignored={"reason": "accepted"})]))
        d = scan.diff_reports(now, prev)
        self.assertEqual((d["fixed"], d["gone"], d["ignored"]), ([], {"old": 2}, 1))

    def test_dev_findings_are_not_part_of_the_change_list(self):
        d = scan.diff_reports(rep(proj("site", True, [fnd(A, scope="dev")])), rep(proj("site", True, []), generated="2026-10-01"))
        self.assertEqual(d["new"], [])


class RenderTest(unittest.TestCase):
    def test_live_first_counts_links_and_change_list(self):
        prev = rep(proj("site", True, [fnd(severity="high")]), proj("old", False, [fnd(B)]), generated="2026-10-01")
        now = rep(proj("internal", False, [fnd(C)]), proj("site", True, [fnd(severity="high"), fnd(B, severity="unknown")]))
        md = scan.render(now, RULES, scan.diff_reports(now, prev))
        table = [l for l in md.splitlines() if l.startswith("| ") and "Project" not in l and "---" not in l]
        self.assertTrue(table[0].startswith("| site | yes"), table[0])
        self.assertIn("2 projects, 2 manifests", md)
        self.assertIn("**2 need action**", md)
        self.assertIn(f"[{A}](https://github.com/advisories/{A})", md)
        self.assertIn("## Since the last scan (2026-10-01)", md)
        self.assertIn("**New:** 2", md)
        self.assertIn("**Still open:** 1", md)
        self.assertIn("no longer found: old (1)", md)

    def test_scan_problems_are_loud(self):
        now = rep(proj("api", True, [fnd(stale="2026-10-01")], [man("uv.lock", "failed", "python", "OSV unreachable: timeout")]),
                  proj("rs", False, [], [man("Cargo.lock", "unscanned", "rust", "needs osv-scanner (brew install osv-scanner)")]),
                  problems=["roots not found: /mnt/usb"])
        md = scan.render(now, RULES, None)
        self.assertIn("## Scan problems", md)
        self.assertIn("api: uv.lock failed: OSV unreachable: timeout", md)
        self.assertIn("roots not found: /mnt/usb", md)
        self.assertIn("not re-checked since 2026-10-01", md)
        self.assertIn("## Not scanned", md)
        self.assertIn("rs: Cargo.lock: needs osv-scanner", md)
        self.assertIn("**1 manifest could not be scanned**", md)

    def test_ignored_and_scope_are_shown(self):
        p = proj("app", True, [fnd(A, ignored={"reason": "build-time only"}), fnd(B, severity="high", scope="unknown"),
                               fnd(C, scope="dev")])
        md = scan.render(rep(p), RULES, None)
        self.assertIn("ignored: build-time only", md)
        self.assertIn("scope not known", md)
        self.assertIn("dev-only: 1 critical", md)

    def test_advisories_are_grouped_by_package_and_long_lists_are_cut(self):
        ids = [f"GHSA-{i}{i}{i}{i}-aaaa-aaaa" for i in range(2, 9)]
        fs = [fnd(i, package="undici", severity="high") for i in ids] + [fnd(A, package="next")]
        fs[0]["fix"], fs[1]["fix"] = "6.21.2", "7.0.1"
        for f in fs[2:7]:
            f["fix"] = "6.5.0"
        md = scan.render(rep(proj("app", True, fs)), RULES, None)
        block = md[md.index("## app (LIVE)"):]
        self.assertIn("- **next** 1.0.0 · production · direct · 1 critical · fix: next@2", block)
        self.assertIn("- **undici** 1.0.0 · production · direct · 7 high · fix: 7.0.1", block)   # the fix that clears them all
        self.assertEqual(block.count("  - [GHSA-"), 6)             # 1 for next, 5 of undici's 7
        self.assertIn("  - and 2 more (in report.json)", block)
        self.assertLess(block.index("**next**"), block.index("**undici**"))   # worst first

    def test_legacy_previous_report_note(self):
        md = scan.render(rep(proj("a")), RULES, None, legacy_previous="2026-10-01")
        self.assertIn("2026-10-01", md)
        self.assertIn("older version", md)


class SarifTest(unittest.TestCase):
    def test_points_at_the_real_manifest_with_a_repo_relative_path(self):
        # v2 pointed every Python finding at requirements.txt, with absolute machine paths
        with tempfile.TemporaryDirectory() as t:
            api = Path(t) / "services" / "api"
            api.mkdir(parents=True)
            (api / "uv.lock").write_text('version = 1\n\n[[package]]\nname = "jinja2"\nversion = "3.1.2"\n')
            f = fnd(A, package="jinja2", severity="high", manifest="uv.lock")
            s = scan.sarif(rep(proj("repo/services/api", True, [f], [man("uv.lock", ecosystem="python")], path=str(api), root=t)), RULES)
        self.assertEqual(s["version"], "2.1.0")
        run = s["runs"][0]
        loc = run["results"][0]["locations"][0]["physicalLocation"]
        self.assertEqual(loc["artifactLocation"]["uri"], "services/api/uv.lock")
        self.assertEqual(loc["region"]["startLine"], 4)
        self.assertNotIn(t, json.dumps(s))
        self.assertEqual(run["results"][0]["ruleId"], A)
        self.assertEqual(run["results"][0]["level"], "error")
        self.assertEqual(run["tool"]["driver"]["rules"][0]["properties"]["security-severity"], "8.0")

    def test_which_findings_ci_receives(self):
        p = proj("app", True, [fnd(A, severity="moderate"), fnd(B, scope="dev"), fnd(C, ignored={"reason": "r"}),
                               fnd("GHSA-dddd-dddd-dddd", severity="unknown", scope="unknown"),
                               fnd("GHSA-eeee-eeee-eeee", severity="low", score=3.1)])
        s = scan.sarif(rep(p), RULES)
        got = {r["ruleId"]: r["level"] for r in s["runs"][0]["results"]}
        self.assertEqual(got, {A: "warning", "GHSA-dddd-dddd-dddd": "warning", "GHSA-eeee-eeee-eeee": "note"})
        sev = {r["id"]: r["properties"].get("security-severity") for r in s["runs"][0]["tool"]["driver"]["rules"]}
        self.assertEqual(sev, {A: "5.5", "GHSA-dddd-dddd-dddd": None, "GHSA-eeee-eeee-eeee": "3.1"})
        self.assertTrue(all(r["partialFingerprints"]["primaryLocationLineHash"] for r in s["runs"][0]["results"]))


if __name__ == "__main__":
    unittest.main()
