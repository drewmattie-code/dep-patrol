import json, os, sys, tempfile, unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scan  # noqa: E402


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
            got = {rel: kind for _, kind, rel in scan.discover([str(root)], 3, [])}
            self.assertEqual(got, {"code/app": "npm", "code/svc/api": "python", "code/tool": "rust"})

    def test_exclude(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            (root / "old-app").mkdir()
            (root / "old-app" / "package-lock.json").write_text("{}")
            self.assertEqual(scan.discover([str(root)], 3, ["old-*"]), [])


class PythonPinsTest(unittest.TestCase):
    def test_requirements_and_locks(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)
            (p / "requirements.txt").write_text("Django==4.2.1\nrequests>=2\nuvicorn[standard]==0.30.0  # web\n")
            (p / "poetry.lock").write_text('[[package]]\nname = "Jinja2"\nversion = "3.1.2"\n')
            self.assertEqual(scan.python_pins(t), {"django": "4.2.1", "uvicorn": "0.30.0", "jinja2": "3.1.2"})


class ReportTest(unittest.TestCase):
    def entry(self, name, exposed, sev):
        return {"path": f"/x/{name}", "name": name, "kind": "npm", "exposed": exposed,
                "git": {"branch": "main", "commit": "", "dirty": False}, "dev_counts": {}, "error": None,
                "prod": [{"package": "next", "severity": sev, "direct": True, "range": "<1", "fix": "next@1",
                          "titles": ["RCE"], "urls": ["https://example.com/adv"], "via": []}] if sev else []}

    def test_urgency_rules(self):
        self.assertTrue(scan.urgent(self.entry("a", False, "critical")))
        self.assertTrue(scan.urgent(self.entry("b", True, "high")))
        self.assertFalse(scan.urgent(self.entry("c", False, "high")))
        self.assertFalse(scan.urgent(self.entry("d", True, None)))

    def test_live_apps_listed_first(self):
        md = scan.render([self.entry("internal", False, "critical"), self.entry("site", True, "high")], "2026-11-17")
        table = [l for l in md.splitlines() if l.startswith("| ") and "Project" not in l]
        self.assertTrue(table[0].startswith("| site | yes"))
        self.assertIn("2 need action", md)


if __name__ == "__main__":
    unittest.main()
