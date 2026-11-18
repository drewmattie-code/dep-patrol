"""Agent configs: the MCP servers an AI coding agent is set up to launch. Offline: a mocked OSV API and package index."""
import json, sys, tempfile, unittest, urllib.error
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import scan  # noqa: E402
from harness import FIX, NEEDS_TOML, Harness  # noqa: E402
from test_report import RULES, fnd, man, proj, rep  # noqa: E402

GITHUB = "@modelcontextprotocol/server-github"


def one(command, *args):
    """The single package a launch line names: (ecosystem, name, exact version, loose spec)."""
    pkgs, note = scan.launch_packages(command, list(args))
    assert len(pkgs) == 1 and note is None, (pkgs, note)
    return pkgs[0]["ecosystem"], pkgs[0]["name"], pkgs[0]["version"], pkgs[0]["loose"]


class LaunchTest(unittest.TestCase):
    def test_npx_pinned_scoped_package(self):
        self.assertEqual(one("npx", "-y", f"{GITHUB}@2025.4.8"), ("npm", GITHUB, "2025.4.8", None))

    def test_a_tag_no_version_or_a_range_is_loose(self):
        self.assertEqual(one("npx", "-y", "@playwright/mcp@latest", "--sandbox"), ("npm", "@playwright/mcp", None, "latest"))
        self.assertEqual(one("npx", "some-server"), ("npm", "some-server", None, ""))
        self.assertEqual(one("npx", "some-server@^1.2.0"), ("npm", "some-server", None, "^1.2.0"))
        self.assertEqual(one("npx", "some-server@1.2"), ("npm", "some-server", None, "1.2"))   # npm reads 1.2 as a range

    def test_full_path_to_the_runner(self):
        self.assertEqual(one("/opt/homebrew/bin/npx", "pkg@1.0.0"), ("npm", "pkg", "1.0.0", None))

    def test_the_package_flag_names_the_package_and_the_word_after_is_a_command(self):
        self.assertEqual(one("npx", "--package=@acme/tools@1.2.3", "run-it"), ("npm", "@acme/tools", "1.2.3", None))
        pkgs, note = scan.launch_packages("npx", ["-p", "a@1.0.0", "-p", "b@2.0.0", "-c", "a | b"])
        self.assertEqual(([(p["name"], p["version"]) for p in pkgs], note), ([("a", "1.0.0"), ("b", "2.0.0")], None))

    def test_other_node_runners(self):
        for cmd in (("bunx", "pkg@1.0.0"), ("pnpx", "pkg@1.0.0"), ("pnpm", "dlx", "pkg@1.0.0"), ("yarn", "dlx", "pkg@1.0.0"),
                    ("bun", "x", "pkg@1.0.0"), ("npm", "exec", "--", "pkg@1.0.0"), ("npm", "x", "pkg@1.0.0")):
            self.assertEqual(one(*cmd), ("npm", "pkg", "1.0.0", None), cmd)

    def test_a_flag_that_takes_a_value_is_not_read_as_the_package(self):
        self.assertEqual(one("npx", "--registry", "https://registry.npmjs.org", "pkg@1.0.0"), ("npm", "pkg", "1.0.0", None))
        self.assertEqual(one("uvx", "--python", "3.12", "mcp-server-git@2025.1.14"), ("PyPI", "mcp-server-git", "2025.1.14", None))

    def test_python_runners(self):
        self.assertEqual(one("uvx", "mcp-obsidian"), ("PyPI", "mcp-obsidian", None, ""))
        self.assertEqual(one("uvx", "mcp-obsidian@latest"), ("PyPI", "mcp-obsidian", None, "latest"))
        self.assertEqual(one("uvx", "mcp[cli]>=1.2"), ("PyPI", "mcp", None, ">=1.2"))
        self.assertEqual(one("uvx", "--from", "mcp-server-fetch==2025.1.17", "mcp-server-fetch"),
                         ("PyPI", "mcp-server-fetch", "2025.1.17", None))
        self.assertEqual(one("uv", "tool", "run", "mcp-server-time==0.6.2"), ("PyPI", "mcp-server-time", "0.6.2", None))
        self.assertEqual(one("pipx", "run", "--spec", "mcp-server-time==0.6.2", "mcp-server-time"),
                         ("PyPI", "mcp-server-time", "0.6.2", None))

    def test_with_adds_packages_to_the_launch(self):
        pkgs, note = scan.launch_packages("uvx", ["--with", "httpx==0.27.0", "mcp-server-fetch==2025.1.17"])
        self.assertEqual(sorted((p["name"], p["version"]) for p in pkgs), [("httpx", "0.27.0"), ("mcp-server-fetch", "2025.1.17")])
        self.assertIsNone(note)

    def test_what_is_not_a_registry_package_is_named_never_guessed(self):
        for cmd in (("node", "/srv/server.js"), ("docker", "run", "-i", "--rm", "ghcr.io/acme/mcp"),
                    ("bun", "run", "--cwd", "${CLAUDE_PLUGIN_ROOT}", "start"), ("uv", "run", "server.py"),
                    ("uv", "--directory", "/srv/app", "run", "server.py"), ("npx", "github:acme/mcp-server"),
                    ("npx", "./local-server"), ("npx", "acme/mcp-server"), ("npx", "https://example.com/server.tgz"),
                    ("uvx", "--from", "git+https://token@github.com/acme/mcp", "mcp"), ("npx",), ("npx", "-y"),
                    ("${PLUGIN_ROOT}/bin/server",), (None,)):
            pkgs, note = scan.launch_packages(cmd[0], list(cmd[1:]))
            self.assertEqual(pkgs, [], cmd)
            self.assertTrue(note, cmd)

    def test_a_note_never_repeats_the_arguments(self):
        # a git URL can carry a token, and the report is a file other tools read
        _, note = scan.launch_packages("uvx", ["--from", "git+https://token@github.com/acme/mcp", "mcp"])
        self.assertNotIn("token", note)
        self.assertNotIn("github.com", note)


class AgentServersTest(unittest.TestCase):
    def test_claude_code_user_config_holds_user_and_per_project_servers(self):
        s = {x["name"]: x for x in scan.agent_servers(FIX / "agent/claude.json")}
        self.assertEqual(set(s), {"browser", "search", "notes"})
        self.assertEqual((s["browser"]["command"], s["browser"]["args"]), ("npx", ["-y", "@playwright/mcp@latest", "--sandbox"]))
        self.assertEqual((s["notes"]["command"], s["notes"]["args"]), ("uvx", ["mcp-obsidian"]))
        self.assertTrue(s["search"]["url"].startswith("https://mcp.example.com/"))
        self.assertIsNone(s["search"]["command"])

    def test_mcp_json(self):
        self.assertEqual([x["name"] for x in scan.agent_servers(FIX / "agent/mcp.json")], ["github", "files", "local"])

    @NEEDS_TOML
    def test_codex_toml(self):
        s = {x["name"]: x for x in scan.agent_servers(FIX / "agent/codex.toml")}
        self.assertEqual(set(s), {"repl", "fetch"})
        self.assertEqual(s["fetch"]["args"], ["mcp-server-fetch==2025.1.17"])

    def test_a_config_with_no_servers_is_empty_and_a_non_object_is_an_error(self):
        with tempfile.TemporaryDirectory() as t:
            Path(t, "a.json").write_text('{"preferences": {"theme": "dark"}}')
            Path(t, "b.json").write_text("[1, 2]")
            self.assertEqual(scan.agent_servers(Path(t, "a.json")), [])
            with self.assertRaises(ValueError):
                scan.agent_servers(Path(t, "b.json"))


class McpScanTest(unittest.TestCase):
    ADV = {"id": "GHSA-mcp1-mcp1-mcp1", "summary": "server-github: fixture token leak",
           "database_specific": {"severity": "HIGH"},
           "affected": [{"package": {"name": GITHUB, "ecosystem": "npm"},
                         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2025.9.1"}]}]}]}

    def scan(self, config, vulnerable=(), newest=None, osv_down=False, index_down=False, name="mcp.json"):
        """Scan one config. vulnerable: {(package, version)}; newest: {package: what the index hands out today}."""
        calls = []

        def fake_http(url, payload=None, tries=4):
            calls.append((url, payload))
            if url.startswith(scan.OSV_API):
                if osv_down:
                    raise OSError("network down")
                if payload is not None:
                    return {"results": [{"vulns": [{"id": self.ADV["id"]}]} if (q["package"]["name"], q["version"]) in vulnerable
                                        else {} for q in payload["queries"]]}
                return self.ADV
            if index_down:
                raise OSError("index down")
            for pkg, ver in (newest or {}).items():
                if f"/{pkg}/" in url:
                    return {"name": pkg, "version": ver, "info": {"name": pkg, "version": ver}}
            raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
        with tempfile.TemporaryDirectory() as t, mock.patch.object(scan, "CACHE_DIR", Path(t) / "cache"), \
                mock.patch.object(scan, "http_json", side_effect=fake_http):
            Path(t, name).write_text(config if isinstance(config, str) else json.dumps(config))
            r = scan.mcp_scan(t, name)
        return r, calls

    def servers(self, **entries):
        return {"mcpServers": entries}

    def test_a_pinned_launch_is_checked_at_its_version(self):
        r, calls = self.scan((FIX / "agent/mcp.json").read_text(), vulnerable={(GITHUB, "2025.4.8")})
        self.assertEqual((r["status"], r["packages"], r["detail"]), ("scanned", 2, None))
        self.assertEqual(len(r["findings"]), 1)
        f = r["findings"][0]
        self.assertEqual((f["id"], f["package"], f["ecosystem"], f["versions"], f["severity"], f["fix"], f["manifest"]),
                         ("GHSA-mcp1-mcp1-mcp1", GITHUB, "npm", ["2025.4.8"], "high", "2025.9.1", "mcp.json"))
        self.assertEqual((f["scope"], f["direct"], f["via"]), ("agent-tool", False, ["MCP server github"]))
        batch = [p for url, p in calls if p is not None]
        self.assertEqual([(q["package"]["ecosystem"], q["package"]["name"], q["version"]) for q in batch[0]["queries"]],
                         [("npm", "@modelcontextprotocol/server-filesystem", "2025.8.21"), ("npm", GITHUB, "2025.4.8")])
        self.assertFalse([url for url, _ in calls if not url.startswith(scan.OSV_API)])   # nothing to ask a package index

    def test_every_server_is_listed_with_what_it_is(self):
        r, _ = self.scan((FIX / "agent/mcp.json").read_text())
        rows = {s["name"]: s for s in r["servers"]}
        self.assertEqual((rows["github"]["kind"], rows["github"]["packages"]),
                         ("package", [{"ecosystem": "npm", "name": GITHUB, "version": "2025.4.8", "pinned": True, "loose": None}]))
        self.assertEqual(rows["local"]["kind"], "other")
        self.assertIn("bun", rows["local"]["note"])

    def test_an_unpinned_launch_is_checked_at_the_newest_release_and_the_manifest_is_partial(self):
        cfg = self.servers(browser={"command": "npx", "args": ["-y", "@playwright/mcp@latest"]})
        r, calls = self.scan(cfg, vulnerable={("@playwright/mcp", "0.0.85")}, newest={"@playwright/mcp": "0.0.85"})
        self.assertEqual((r["status"], r["packages"]), ("partial", 1))
        self.assertEqual([(f["package"], f["versions"]) for f in r["findings"]], [("@playwright/mcp", ["0.0.85"])])
        self.assertIn("https://registry.npmjs.org/@playwright/mcp/latest", [url for url, _ in calls])
        for word in ("browser", "@playwright/mcp", "0.0.85", "newest"):
            self.assertIn(word, r["detail"])
        self.assertEqual(r["servers"][0]["packages"][0], {"ecosystem": "npm", "name": "@playwright/mcp", "version": "0.0.85",
                                                          "pinned": False, "loose": "latest"})

    def test_another_tag_is_asked_for_by_name(self):
        cfg = self.servers(edge={"command": "npx", "args": ["acme-mcp@next"]})
        r, calls = self.scan(cfg, newest={"acme-mcp": "3.0.0-beta.2"})
        self.assertIn("https://registry.npmjs.org/acme-mcp/next", [url for url, _ in calls])
        self.assertEqual(r["servers"][0]["packages"][0]["version"], "3.0.0-beta.2")

    def test_a_python_launch_asks_pypi(self):
        cfg = self.servers(notes={"command": "uvx", "args": ["mcp-obsidian"]})
        r, calls = self.scan(cfg, newest={"mcp-obsidian": "0.2.3"})
        self.assertEqual(r["status"], "partial")
        self.assertIn("https://pypi.org/pypi/mcp-obsidian/json", [url for url, _ in calls])
        batch = [p for _, p in calls if p is not None][0]
        self.assertEqual(batch["queries"], [{"package": {"name": "mcp-obsidian", "ecosystem": "PyPI"}, "version": "0.2.3"}])

    def test_a_range_cannot_be_resolved_so_it_is_named_as_not_checked(self):
        cfg = self.servers(old={"command": "npx", "args": ["acme-mcp@^1.2.0"]})
        r, calls = self.scan(cfg, newest={"acme-mcp": "9.9.9"})
        self.assertEqual((r["status"], r["packages"], calls), ("partial", 0, []))
        self.assertIn("old", r["detail"])
        self.assertIn("not checked", r["detail"])
        self.assertIsNone(r["servers"][0]["packages"][0]["version"])

    def test_a_package_the_public_index_does_not_have_is_named_not_failed(self):
        cfg = self.servers(inhouse={"command": "npx", "args": ["@acme-internal/mcp"]})
        r, _ = self.scan(cfg)
        self.assertEqual((r["status"], r["packages"], r["findings"]), ("partial", 0, []))
        self.assertIn("not on the public", r["detail"])

    def test_an_unreachable_index_or_osv_is_a_failure(self):
        loose = self.servers(browser={"command": "npx", "args": ["@playwright/mcp@latest"]})
        r, _ = self.scan(loose, index_down=True)
        self.assertEqual((r["status"], r["findings"]), ("failed", []))
        self.assertIn("index down", r["detail"])
        r, _ = self.scan((FIX / "agent/mcp.json").read_text(), osv_down=True)
        self.assertEqual(r["status"], "failed")
        self.assertIn("network down", r["detail"])

    def test_remote_servers_are_listed_by_host_and_nothing_is_asked(self):
        cfg = self.servers(search={"type": "http", "url": "https://mcp.example.com/v1/mcp?key=SECRET-TOKEN-123"})
        r, calls = self.scan(cfg)
        self.assertEqual((r["status"], r["packages"], calls), ("scanned", 0, []))
        self.assertEqual(r["servers"], [{"name": "search", "kind": "remote", "host": "mcp.example.com"}])

    def test_no_secret_from_the_config_reaches_the_result(self):
        r, _ = self.scan((FIX / "agent/claude.json").read_text(), newest={"@playwright/mcp": "0.0.85", "mcp-obsidian": "0.2.3"})
        self.assertEqual(r["status"], "partial")
        self.assertNotIn("SECRET", json.dumps(r))
        self.assertEqual({s["name"] for s in r["servers"]}, {"browser", "search", "notes"})

    def test_one_package_launched_by_two_servers_is_asked_once_and_names_both(self):
        launch = {"command": "npx", "args": [f"{GITHUB}@2025.4.8"]}
        r, calls = self.scan(self.servers(work=launch, personal=launch), vulnerable={(GITHUB, "2025.4.8")})
        self.assertEqual(len([p for _, p in calls if p is not None][0]["queries"]), 1)
        self.assertEqual(r["packages"], 1)
        merged = scan.merge_findings(r["findings"])
        self.assertEqual([f["via"] for f in merged], [["MCP server personal", "MCP server work"]])

    def test_an_unreadable_config_is_a_failure_and_an_empty_one_is_clean(self):
        r, _ = self.scan("{not json")
        self.assertEqual(r["status"], "failed")
        self.assertIn("could not read", r["detail"])
        r, calls = self.scan({"preferences": {}})
        self.assertEqual((r["status"], r["packages"], r["servers"], calls), ("scanned", 0, [], []))

    def test_an_entry_with_no_command_and_no_url_is_listed_as_unreadable(self):
        r, _ = self.scan(self.servers(odd={"transport": "stdio"}))
        self.assertEqual((r["servers"][0]["kind"], r["status"]), ("other", "scanned"))

    @NEEDS_TOML
    def test_a_codex_config(self):
        r, _ = self.scan((FIX / "agent/codex.toml").read_text(), name="config.toml")
        self.assertEqual((r["status"], r["packages"]), ("scanned", 1))
        self.assertEqual({s["name"]: s["kind"] for s in r["servers"]}, {"repl": "other", "fetch": "package"})

    def test_toml_without_a_reader_is_unscanned_not_silent(self):
        with mock.patch.object(scan, "tomllib", None):
            r, _ = self.scan((FIX / "agent/codex.toml").read_text(), name="config.toml")
        self.assertEqual(r["status"], "unscanned")
        self.assertIn("3.11", r["detail"])


class AgentPolicyTest(unittest.TestCase):
    def urgent(self, severity, **rules):
        p = proj("agent-tools", False, [fnd(severity=severity, scope="agent-tool", manifest=".claude.json")],
                 [man(".claude.json", ecosystem="mcp")])
        return bool(scan.urgent_findings(p, dict(RULES, **rules)))

    def test_a_high_in_an_agent_tool_needs_action_by_default(self):
        self.assertTrue(self.urgent("high"))
        self.assertTrue(self.urgent("critical"))
        self.assertFalse(self.urgent("moderate"))

    def test_the_rule_can_be_turned_off_and_a_critical_still_counts(self):
        self.assertFalse(self.urgent("high", high_on_agent_tools=False))
        self.assertTrue(self.urgent("critical", high_on_agent_tools=False))

    def test_the_rule_is_a_known_urgency_key(self):
        self.assertIs(scan.DEFAULT_URGENCY["high_on_agent_tools"], True)


class AgentRenderTest(unittest.TestCase):
    SERVERS = [
        {"name": "github", "kind": "package",
         "packages": [{"ecosystem": "npm", "name": GITHUB, "version": "2025.4.8", "pinned": True, "loose": None}]},
        {"name": "browser", "kind": "package",
         "packages": [{"ecosystem": "npm", "name": "@playwright/mcp", "version": "0.0.85", "pinned": False, "loose": "latest"}]},
        {"name": "old", "kind": "package",
         "packages": [{"ecosystem": "npm", "name": "acme-mcp", "version": None, "pinned": False, "loose": "^1.2.0"}]},
        {"name": "search", "kind": "remote", "host": "mcp.example.com"},
        {"name": "docs", "kind": "remote", "host": "docs.example.org"},
        {"name": "local", "kind": "other", "note": "local command (bun)"}]

    def render(self):
        m = man(".claude.json", "partial", "mcp", "1 unpinned launch")
        m["servers"] = self.SERVERS
        return scan.render(rep(proj("agent-tools", False, [], [m]), proj("site", True, [])), RULES, None)

    def test_the_report_lists_every_server_and_how_far_it_was_checked(self):
        md = self.render()
        section = md.split("## Agent tools", 1)[1].split("\n## ", 1)[0]
        self.assertIn("agent-tools `.claude.json`", section)
        self.assertIn(f"github: npm {GITHUB} 2025.4.8, pinned and checked", section)
        self.assertIn("browser: npm @playwright/mcp, unpinned (latest): newest release 0.0.85 checked", section)
        self.assertIn("old: npm acme-mcp, unpinned (^1.2.0): not checked", section)
        self.assertIn("remote, not checked: search (mcp.example.com), docs (docs.example.org)", section)
        self.assertIn("local: local command (bun), not checked", section)

    def test_the_headline_names_the_agent_tool_rule_only_when_agent_configs_were_scanned(self):
        self.assertIn("or a critical or high in a live app or an agent tool", self.render())
        plain = scan.render(rep(proj("site", True, [])), RULES, None)
        self.assertNotIn("agent tool", plain)
        self.assertNotIn("## Agent tools", plain)


class AgentRunTest(Harness):
    def agent_config(self, servers, rel="agent/claude.json"):
        f = self.tmp / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(json.dumps({"mcpServers": servers}))
        return str(f)

    def setUp(self):
        super().setUp()
        self.project("api", requirements="zzz==1.0\n")   # a root has to exist; this one is clean

    def test_agent_configs_are_one_project_and_a_high_needs_action(self):
        f = self.agent_config({"gh": {"command": "npx", "args": ["-y", "@acme/mcp@1.0.0"]}})
        self.vulnerable.add(("@acme/mcp", "1.0.0"))
        rc, out = self.main("--config", self.config(agent_configs=[f]))
        data, md, _ = self.report()
        self.assertEqual(rc, 1)
        self.assertEqual(data["warnings"], [])   # agent_configs is a known key
        p = {p["name"]: p for p in data["projects"]}["agent-tools"]
        self.assertEqual([(str(Path(p["path"]) / m["file"]), m["ecosystem"], m["status"]) for m in p["manifests"]],
                         [(f, "mcp", "scanned")])
        self.assertEqual([(x["package"], x["scope"], x["severity"]) for x in p["findings"]], [("@acme/mcp", "agent-tool", "high")])
        self.assertFalse(p["exposed"])
        self.assertIn("1 needs action: agent-tools", out)
        self.assertIn("## Agent tools", md)
        self.assertIn("through MCP server gh", md)
        rc, _ = self.main("--config", self.config(agent_configs=[f], urgency={"high_on_agent_tools": False}))
        self.assertEqual(rc, 0)

    def test_an_unpinned_launch_is_listed_as_not_fully_scanned_and_strict_fails_it(self):
        f = self.agent_config({"browser": {"command": "npx", "args": ["@acme/browser@latest"]}})
        self.newest["@acme/browser"] = "2.3.4"
        cfg = self.config(agent_configs=[f])
        rc, out = self.main("--config", cfg)
        _, md, _ = self.report()
        self.assertEqual(rc, 0)
        self.assertIn("1 manifest not fully scanned", out)
        self.assertIn("## Not scanned", md)
        self.assertIn("newest release 2.3.4 checked", md)
        self.assertEqual(self.main("--config", cfg, "--strict")[0], 2)

    def test_an_entry_that_matches_no_file_is_a_problem(self):
        # a config that moved would otherwise just stop being checked
        rc, out = self.main("--config", self.config(agent_configs=[str(self.tmp / "gone.json")]))
        data, md, _ = self.report()
        self.assertEqual(rc, 2)
        self.assertIn("gone.json", data["problems"][0])
        self.assertIn("## Scan problems", md)
        self.assertNotIn("agent-tools", [p["name"] for p in data["projects"]])

    def test_a_glob_entry_takes_every_file_it_matches(self):
        self.agent_config({"a": {"url": "https://a.example.com/mcp"}}, "plugins/one/1.0.0/.mcp.json")
        self.agent_config({"b": {"url": "https://b.example.com/mcp"}}, "plugins/two/2.1.0/.mcp.json")
        rc, _ = self.main("--config", self.config(agent_configs=[str(self.tmp / "plugins/*/*/.mcp.json")]))
        data, _, _ = self.report()
        p = {p["name"]: p for p in data["projects"]}["agent-tools"]
        self.assertEqual((rc, [m["status"] for m in p["manifests"]]), (0, ["scanned", "scanned"]))
        self.assertEqual(sorted(s["host"] for m in p["manifests"] for s in m["servers"]), ["a.example.com", "b.example.com"])

    def test_agent_configs_must_be_a_list_of_paths(self):
        rc, out = self.main("--config", self.config(agent_configs="~/.claude.json"))
        self.assertEqual(rc, 2)
        self.assertIn("agent_configs must be a list", out)

    def test_repo_mode_leaves_the_machine_agent_configs_alone(self):
        f = self.agent_config({"gh": {"command": "npx", "args": ["@acme/mcp@1.0.0"]}})
        self.vulnerable.add(("@acme/mcp", "1.0.0"))
        cfg = self.config(agent_configs=[f, str(self.tmp / "gone.json")])
        rc, out = self.main("--repo", str(self.code), "--config", cfg, "--json")
        data = json.loads(out)
        self.assertEqual((rc, data["problems"], [p["name"] for p in data["projects"]]), (0, [], ["code/api"]))

    def test_dry_run_lists_them_and_touches_no_network(self):
        f = self.agent_config({"gh": {"command": "npx", "args": ["@acme/mcp@latest"]}})
        rc, out = self.main("--config", self.config(agent_configs=[f]), "--dry-run")
        self.assertEqual(rc, 0)
        self.assertIn("2 projects, 2 manifests would be scanned", out)
        self.assertEqual(scan.http_json.call_count, 0)

    def test_exposed_only_skips_agent_tools(self):
        f = self.agent_config({"gh": {"command": "npx", "args": ["@acme/mcp@1.0.0"]}})
        self.main("--config", self.config(agent_configs=[f], exposed=["api"]), "--exposed-only")
        data, _, _ = self.report()
        self.assertEqual([p["name"] for p in data["projects"]], ["code/api"])

    def test_a_fixed_pin_shows_as_fixed_on_the_next_run(self):
        f = self.agent_config({"gh": {"command": "npx", "args": ["@acme/mcp@1.0.0"]}})
        self.vulnerable.add(("@acme/mcp", "1.0.0"))
        cfg = self.config(agent_configs=[f])
        with mock.patch.object(scan, "today", return_value="2026-10-01"):
            self.assertEqual(self.main("--config", cfg)[0], 1)
        self.agent_config({"gh": {"command": "npx", "args": ["@acme/mcp@1.0.1"]}})
        with mock.patch.object(scan, "today", return_value="2026-11-01"):
            self.assertEqual(self.main("--config", cfg)[0], 0)
        md = (self.tmp / "reports" / "2026-11-01" / "report.md").read_text()
        self.assertIn("**Fixed:** 1: agent-tools @acme/mcp", md)


if __name__ == "__main__":
    unittest.main()
