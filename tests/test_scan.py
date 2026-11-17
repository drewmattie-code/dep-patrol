import json, os, sys, tempfile, unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scan  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"


def entry(name, exposed, sev, path=None):
    return {"path": path or f"/x/{name}", "name": name, "kind": "npm", "exposed": exposed,
            "git": {"branch": "main", "commit": "", "dirty": False}, "dev_counts": {}, "error": None, "ignored": [],
            "prod": [scan.finding("next", sev, True, "<1", "next@1", ["RCE"], ["https://example.com/adv"],
                                  ids=["GHSA-aaaa"])] if sev else []}


class DiscoverTest(unittest.TestCase):
    def test_finds_projects_and_skips_node_modules(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "code"
            (root / "app" / "node_modules" / "dep").mkdir(parents=True)
            (root / "app" / "package-lock.json").write_text("{}")
            (root / "app" / "node_modules" / "dep" / "package-lock.json").write_text("{}")
            (root / "svc" / "api").mkdir(parents=True)
            (root / "svc" / "api" / "requirements.txt").write_text("flask==2.0.0\n")
            (root / "tool").mkdir()
            (root / "tool" / "Cargo.lock").write_text("")
            (root / "web").mkdir()
            (root / "web" / "yarn.lock").write_text("")
            got = {rel: kind for _, kind, rel in scan.discover([str(root)], 3, [])}
            self.assertEqual(got, {"code/app": "npm", "code/svc/api": "python", "code/tool": "rust", "code/web": "yarn"})

    def test_exclude_include_and_unlimited_depth(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            deep = root / "a" / "b" / "c" / "d" / "e"
            deep.mkdir(parents=True)
            (deep / "package-lock.json").write_text("{}")
            (root / "old-app").mkdir()
            (root / "old-app" / "package-lock.json").write_text("{}")
            self.assertEqual(len(scan.discover([str(root)], 3, ["old-*"])), 0)
            self.assertEqual(len(scan.discover([str(root)], None, ["old-*"])), 1)
            self.assertEqual([n for _, _, n in scan.discover([str(root)], None, [], ["old-*"])], [f"{root.name}/old-app"])

    def test_workspace_members_are_not_double_scanned(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "mono"
            (root / "packages" / "ui").mkdir(parents=True)
            (root / "package.json").write_text(json.dumps({"workspaces": ["packages/*"]}))
            (root / "package-lock.json").write_text("{}")
            (root / "packages" / "ui" / "package-lock.json").write_text("{}")
            self.assertEqual([n for _, _, n in scan.discover([str(root)], 3, [])], ["mono"])


class PythonPinsTest(unittest.TestCase):
    def test_requirements_unpinned_reported(self):
        with tempfile.TemporaryDirectory() as t:
            Path(t, "requirements.txt").write_text("Django==4.2.1\nrequests>=2\nuvicorn[standard]==0.30.0  # web\n-e .\n")
            pins, unpinned = scan.python_pins(t)
            self.assertEqual(pins, {"django": "4.2.1", "uvicorn": "0.30.0"})
            self.assertEqual(unpinned, ["requests"])

    def test_real_poetry_and_uv_locks(self):
        pins, _ = scan.python_pins(FIX / "poetry")
        self.assertEqual(pins.get("jinja2"), "3.1.2")
        self.assertEqual(pins.get("markupsafe"), "2.1.3")
        pins, _ = scan.python_pins(FIX / "uv")
        self.assertEqual(pins.get("requests"), "2.31.0")
        self.assertEqual(pins.get("urllib3"), "2.0.7")


class OsvTest(unittest.TestCase):
    def test_python_findings_offline_with_cache(self):
        batch = {"results": [{"vulns": [{"id": "GHSA-test-1"}]}, {}]}
        vuln = {"id": "GHSA-test-1", "summary": "Bad thing", "database_specific": {"severity": "HIGH"},
                "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "3.1.3"}]}]}]}
        calls = []

        def fake_http(url, payload=None, tries=4):
            calls.append(url)
            return batch if payload else vuln
        with tempfile.TemporaryDirectory() as t, mock.patch.object(scan, "CACHE_DIR", Path(t) / "cache"), \
                mock.patch.object(scan, "http_json", side_effect=fake_http):
            Path(t, "requirements.txt").write_text("jinja2==3.1.2\nzzz==1.0\n")
            out, _, note = scan.python_findings(t)
            self.assertEqual([(f["package"], f["severity"], f["fix"]) for f in out], [("jinja2", "high", "3.1.3")])
            self.assertIsNone(note)
            scan.python_findings(t)  # second run: the vuln detail comes from the cache
            self.assertEqual(sum(1 for c in calls if "/v1/vulns/" in c), 1)


class NpmTest(unittest.TestCase):
    def test_single_audit_split_prod_and_dev(self):
        audit = json.loads((FIX / "npm-audit.json").read_text())
        ls = {"dependencies": {"next": {"dependencies": {"postcss": {}}}}}

        def fake_run(cmd, cwd, timeout=300):
            return (ls, None) if cmd[1] == "ls" else (audit, None)
        with mock.patch.object(scan, "run_json", side_effect=fake_run):
            prod, dev, err = scan.npm_findings("/tmp")
        self.assertIsNone(err)
        self.assertEqual(sorted(f["package"] for f in prod), ["next", "postcss"])
        self.assertEqual(dev, {"high": 1})
        nxt = next(f for f in prod if f["package"] == "next")
        self.assertEqual(nxt["fix"], "next@16.4.6")
        self.assertIn("1112233", nxt["ids"])


class ExposureAndIgnoreTest(unittest.TestCase):
    def test_exposed_matching_is_precise(self):
        self.assertTrue(scan.is_exposed("/a/shop/web", "shop/web", ["shop/web"]))
        self.assertFalse(scan.is_exposed("/a/blog/web", "blog/web", ["shop/web"]))
        self.assertFalse(scan.is_exposed("/a/webapp", "webapp", ["web"]))
        self.assertTrue(scan.is_exposed("/a/web", "web", ["web"]))
        self.assertTrue(scan.is_exposed("/a/site-prod", "site-prod", ["*-prod"]))

    def test_ignore_rules(self):
        e = entry("app", True, "critical")
        scan.apply_ignores(e, [{"match": "GHSA-aaaa", "reason": "not reachable: build-time only"}])
        self.assertEqual(e["prod"], [])
        self.assertEqual(e["ignored"][0]["reason"], "not reachable: build-time only")


class ReportTest(unittest.TestCase):
    def test_urgency_rules_and_config(self):
        self.assertTrue(scan.urgent(entry("a", False, "critical")))
        self.assertTrue(scan.urgent(entry("b", True, "high")))
        self.assertFalse(scan.urgent(entry("c", False, "high")))
        self.assertFalse(scan.urgent(entry("d", True, None)))
        self.assertTrue(scan.urgent(entry("e", True, "moderate"), dict(scan.DEFAULT_URGENCY, moderate_on_exposed=True)))
        self.assertFalse(scan.urgent(entry("f", False, "critical"), dict(scan.DEFAULT_URGENCY, critical_always=False)))

    def test_live_first_links_and_diff(self):
        prev = ("2026-10-01", [entry("site", True, "high"), entry("old", False, "critical")])
        md = scan.render([entry("internal", False, "critical"), entry("site", True, "high")], "2026-11-01", prev=prev)
        table = [l for l in md.splitlines() if l.startswith("| ") and "Project" not in l]
        self.assertTrue(table[0].startswith("| site | yes"))
        self.assertIn("[next](https://example.com/adv)", md)
        self.assertIn("**New:** 1", md)
        self.assertIn("**Fixed:** 1", md)
        self.assertIn("**Still open:** 1", md)

    def test_sarif_shape(self):
        s = scan.sarif([entry("site", True, "critical")])
        self.assertEqual(s["version"], "2.1.0")
        r = s["runs"][0]["results"][0]
        self.assertEqual(r["ruleId"], "GHSA-aaaa")
        self.assertEqual(r["level"], "error")


class EndToEndTest(unittest.TestCase):
    def test_full_run_writes_reports_and_exit_codes(self):
        audit = json.loads((FIX / "npm-audit.json").read_text())

        def fake_run(cmd, cwd, timeout=300):
            if cmd[:2] == ["npm", "ls"]:
                return {"dependencies": {"next": {}}}, None
            return audit, None
        with tempfile.TemporaryDirectory() as t, mock.patch.object(scan, "run_json", side_effect=fake_run):
            code = Path(t) / "code"
            (code / "shop").mkdir(parents=True)
            (code / "shop" / "package-lock.json").write_text("{}")
            cfg = Path(t) / "cfg.json"
            cfg.write_text(json.dumps({"roots": [str(code)], "exposed": ["shop"], "out": str(Path(t) / "reports")}))
            rc = scan.main(["--config", str(cfg)])
            self.assertEqual(rc, 1)
            day = next((Path(t) / "reports").iterdir())
            md = (day / "report.md").read_text()
            self.assertIn("1 need action", md)
            self.assertIn("## code/shop (LIVE)", md)
            self.assertIn("## How this was scanned", md)
            self.assertTrue((day / "report.sarif").exists())
            self.assertTrue((day / "run.log").exists())
            self.assertEqual(scan.main(["--roots", str(Path(t) / "missing")]), 2)
            self.assertEqual(scan.main(["--config", str(cfg), "--dry-run"]), 0)


if __name__ == "__main__":
    unittest.main()
