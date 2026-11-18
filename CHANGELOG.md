# Changelog

## 3.1.0 (2026-11-17)

The coding agent's own tools are now part of the patrol.

### New

- **Agent configs.** A new `agent_configs` list names the files that declare MCP servers (Claude Code's `~/.claude.json`, plugin `.mcp.json` files, Codex's `config.toml`, or any JSON file with an `mcpServers` map). The package each server is launched from is checked at OSV. These servers start straight from a registry (`npx -y some-server@latest`), so no lockfile exists for the folder scan to find.
  - A pinned launch is checked at its version.
  - An unpinned launch is checked at the newest release, looked up at the npm registry or PyPI, and its manifest is `partial`. A range, or a package the public index does not have, is named as not checked.
  - Remote servers are listed by host and local commands by name. Neither is checked.
  - They are reported as one project, `agent-tools`, and the report has an **Agent tools** section listing every server and how far it was checked.
- **`urgency.high_on_agent_tools`** (on by default): a critical or high advisory in an agent tool needs action. Findings there have the scope `agent-tool`.
- An `agent_configs` entry that matches no file is a scan problem (exit code 2), like an `exposed` entry that matches no project.

### Good to know

- Nothing changes until `agent_configs` is set. `--repo` and the GitHub Action ignore it.
- Only the launched package is checked, not what it installs underneath.
- Only the command, its arguments and the host of a URL are read from a server entry. Env values, headers and arguments never reach the report.
- With `agent_configs` set, the scan also talks to registry.npmjs.org and pypi.org, to ask for the newest release of an unpinned package. Only the package name is sent.
- To cover the lockfiles that Claude Code plugins and skills ship with, add `~/.claude/plugins/cache` and `~/.claude/skills` to `roots`. That needs no new version.

## 3.0.1 (2026-11-17)

- **A checkout that is behind the live commit no longer adds its own findings.** With a `deployed` entry, a stale branch of an app that has moved on kept the app on the "needs action" list for holes production had already closed. Now only what is live counts in that case, and the report says the checkout is behind. A checkout that is ahead of live, or on another line, still counts both.
- The table, the change list and the exit code all follow the same rule.

## 3.0.0 (2026-11-17)

The theme of this release is a report you can depend on. v2 could produce a believable report that had skipped an ecosystem, filed a production dependency under dev, or shown a finding as fixed when the scan had failed. Each of those is closed here, with a regression test.

### Scan accuracy

- **Every manifest is tracked.** A folder with a JS lockfile and Python manifests is now scanned on both sides. v2 kept one ecosystem per folder.
- **Workspace members are only skipped where they are really covered.** A member's JS lockfile is recorded as covered by the root. A Python project inside a workspace member is still scanned.
- **A failed audit is a failure.** Each scanner's answer is checked for the right shape. Empty output, an error object or a crash marks the manifest `failed`. v2 read empty output as zero findings.
- **One finding per advisory.** v2 kept one finding per package and cut its advisory list at ten. A package with more lost the rest.
- **npm scope comes from the lockfile, per installed copy.** v2 walked `npm ls` by package name, so the first copy seen decided for every copy. The new result is checked in CI against `npm audit --omit=dev`.
- **npm advisories listed once per release line are folded.** npm repeats an advisory for each affected line (6.x and 7.x). Reading only the first could file a production copy under dev.
- **Python scope and "direct" are worked out, not assumed.** `uv.lock` and `poetry.lock` are walked as a graph from the project's own dependencies, and pip-compile annotations are read. v2 marked every package as a direct production dependency.
- **Git and path packages are not sent to PyPI lookups.** That includes the project itself, which v2 looked up by name.
- **OSV severity reads CVSS 3 vectors.** Advisories with no database label are now scored instead of becoming "unknown". What is truly unrated is listed as Unrated, with the reason.
- **Copies of one advisory are one advisory.** GHSA, PYSEC and RUSTSEC records for the same CVE are folded, with the other ids kept as aliases.
- **Go projects are found by `go.mod`**, which is the file osv-scanner reads.
- **Requirements files pulled in with `-r` are read**, and a `requirements/` folder is part of its project. v2 skipped both without saying so.
- **OSV answers that come in pages are followed to the end.**

### Reports and exit codes

- **Exit codes are the same for every output format.** v2 returned 0 from `--json` before looking at the findings.
- **Exit code 2 means incomplete.** A failed manifest, a missing root, an unknown live commit or a crash. `--strict` adds anything left unscanned.
- **"Fixed" needs a successful rescan.** When a manifest fails, its last known findings are carried forward as "not re-checked" and still count.
- **Ignore rules are exact and per advisory.** v2 matched substrings and dropped the whole package.
- **SARIF points at the real manifest**, with paths relative to the repository and a line number. It holds every finding that counts, at any severity.
- **`--notify` also fires when the scan itself broke.**
- **An `exposed` or `deployed` entry that matches no project is a scan problem.** A live app whose folder moved no longer drops out of sight.
- **A crash exits 2.** v2 let Python's default exit code 1 through, which reads as "findings".

### New

- **Live versus merged.** A `deployed` config entry tells the scan how to find the live commit. When it differs from the checkout, the live commit's lockfiles are scanned too.
- **GitHub Action** (`uses: drewmattie-code/dep-patrol@v3`) and `--repo` mode for one repository.
- **`--verify-fixed`**: after a bump, say whether an advisory is gone, and refuse to say so when the scan did not run.
- **`bump-and-verify.sh --fixes`**, with support for pnpm, uv and pinned requirements files.
- **`smoke-check.sh`** for checks after a deploy.
- **`--exposed-only`** for a fast pass over the live apps, and `--max-depth`.

### Fixed in the helpers

- `record-rollback.sh` no longer writes `current=unknown` and exits 0. It records nothing and says STOP.
- `record-rollback.sh wrangler` took the oldest deployment in the list. It now takes the newest.
- `bump-and-verify.sh` stops when the lockfile is not committed.
- `install-schedule.sh` picks a Python that can read TOML lockfiles (3.11+), and has a `--dry-run`. Installed over ssh, v2 could schedule the old system Python.

### Upgrading from v2

- **`report.json` has a new shape** (`"schema": 3`: projects with `manifests` and `findings`). Anything that reads the old list needs updating.
- **The first v3 run has no change list**, because a v2 report cannot be compared advisory by advisory. The second run does.
- **Check your ignore rules.** Substring matches no longer work. Use `{"advisory": "GHSA-...", "reason": "..."}`. The old `match` key still works when it is an exact advisory id or package name. Rules that match nothing are listed under Warnings in the report.
- **Expect more "needs action" at first.** Findings with scope not known (Cargo, Go, Yarn, Bun) count as production, and advisories that v2 dropped or left unrated are now counted.
- **Check your `exposed` list.** An entry that matches no project is now a problem (exit code 2). Path patterns such as `shop/web` need a folder boundary and no longer match `myshop/web`.
- **Expect exit code 2 where v2 said 0**, when part of the scan could not run. A notify command now also runs in that case, and gets `DEP_PATROL_EXIT`.
- **`npm ls` is no longer used**, so projects do not need `node_modules` installed to be scanned.
- Run `git pull`, then `scripts/install-schedule.sh --dry-run`. If it names a Python older than 3.11, run `scripts/install-schedule.sh` again so `poetry.lock` and `uv.lock` keep being scanned.

## 2.0.0 (2026-11-17)

TOML lockfile parsing, OSV cache and backoff, osv-scanner for Yarn, Bun, Cargo and Go, workspace-aware discovery, configurable urgency and ignore rules, a diff against the last run, SARIF, `--dry-run`, helper scripts and offline tests.

## 1.0.0 (2026-11-17)

First version: monthly scan of every repo on a machine with npm audit and OSV, ranked by what is live, plus the patch playbook.
