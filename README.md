# dep-patrol

A vulnerability patrol for every repo on your machine and every repo in CI, packaged as a Claude Code skill and a GitHub Action.

AI coding tools make it easy to ship many small apps, and every one of them carries a dependency tree that keeps aging after launch. The typical failure looks like this. An app is clean on the day it ships. A few weeks later a framework flaw is published, such as "React2Shell" (CVE-2025-55182) in React Server Components and Next.js, and attackers can run code on the server and read its `.env`. Nothing in the app's code changed. Only the calendar did.

**dep-patrol** finds every lockfile under your code folders, audits each one, ranks the results by what is actually live on the internet, and gives your agent a careful playbook for patching production without breaking it.

It is built around one rule: **a scan that did not run is never reported as clean.**

## What it does

- **Finds every manifest** under the folders you name: lockfiles for npm, pnpm, Yarn, Bun, Cargo and Go, plus pinned Python requirements (including `requirements/` folders and `-r` includes), `poetry.lock` and `uv.lock`.
  - A folder with a JS lockfile and Python manifests gets both scanned.
  - JS workspaces are understood, so monorepo members aren't scanned twice.
- **Gives each manifest its own outcome**: scanned, partial, unscanned or failed. A registry outage or an unreadable lockfile shows up as a problem at the top of the report and in the exit code.
- **Tracks each advisory on its own.** A package with twelve advisories is twelve findings. Copies of one advisory across databases (GHSA, PYSEC, RUSTSEC) are folded together.
- **Says whether it ships.** Production and dev are told apart from the lockfile itself, per installed copy. When a format cannot say, the finding is marked "scope not known" and counted as production.
- **Ranks** live apps first, then by worst severity. You set what counts as urgent, and you can ignore a single advisory if you give a reason.
- **Checks what is live.** Tell it how to find the deployed commit and it scans that commit too. "The fix is merged, but production still runs the affected version" becomes a line in the report.
- **Remembers.** Each report opens with what is new, fixed or still open since the last run. "Fixed" needs a successful rescan. A manifest that failed this time keeps its last known findings.
- **Reports** in Markdown, JSON and SARIF, and alerts through any shell command you configure (desktop notification, Slack webhook, Telegram bot), both when something needs action and when the scan itself broke.
- **Runs in CI** as a GitHub Action that fails the job on findings and on an incomplete scan.
- **Patches safely.** `SKILL.md` is the agent's playbook, and helper scripts turn the risky steps into commands that refuse unsafe states:
  - `branch-from-deployed.sh` branches from what is actually deployed.
  - `bump-and-verify.sh` bumps, proves the named advisory is gone, then runs the test gate (npm, pnpm, uv, pinned requirements).
  - `record-rollback.sh` records what to roll back to, and refuses to record nothing.
  - `smoke-check.sh` checks production after the deploy.

## First run in five minutes

```bash
git clone --branch v3.0.0 https://github.com/drewmattie-code/dep-patrol ~/.claude/skills/dep-patrol
cd ~/.claude/skills/dep-patrol
python3 scripts/scan.py --roots ~/code --dry-run     # lists what it found, no network
python3 scripts/scan.py --roots ~/code               # the real thing
```

The dry run prints one line per project, then:

```
dry run: 14 projects, 17 manifests would be scanned
```

The real run prints a summary and the report path:

```
dep-patrol 2026-11-17: 14 projects, 17 manifests, 2 need action: code/shop (live), code/tools/rs. 3 manifests not fully scanned
report: /Users/you/.dep-patrol/reports/2026-11-17/report.md
```

Then make it yours:

```bash
mkdir -p ~/.dep-patrol && cp dep-patrol.example.json ~/.dep-patrol/config.json
# edit ~/.dep-patrol/config.json: your roots, which apps are live, how to find the live commit, how to notify you
scripts/install-schedule.sh                           # monthly, the 1st at 09:00
```

Or ask Claude Code: *"run the dependency patrol"*, *"does this CVE affect any of our apps?"*, *"patch whatever the scan flagged"*, *"is that fix actually live?"*.

## What a report looks like

This is a real run against a small test repository with three projects (folder paths trimmed):

```markdown
# Dependency scan, 2026-11-17

3 projects, 3 manifests. **2 need action** (a critical anywhere, or a critical or high in a live app).

| Project | Live | Critical | High | Moderate | Unrated | Scanned | Branch | Note |
|---|---|---|---|---|---|---|---|---|
| vulnerable/tools/rs | yes | 3 | 1 |  |  | yes | main |  |
| vulnerable/services/web | yes |  | 2 | 2 |  | yes | main | dev-only: 1 critical |
| vulnerable/services/api | yes |  |  | 5 |  | yes | main |  |

## vulnerable/tools/rs (LIVE)

- **smallvec** 0.6.9 · scope not known · 3 critical, 1 high · fix: 0.6.14
  - [GHSA-43w2-9j62-hq99](https://github.com/advisories/GHSA-43w2-9j62-hq99) critical: Buffer overflow in SmallVec::insert_many
  - [GHSA-69gw-hgj3-45m7](https://github.com/advisories/GHSA-69gw-hgj3-45m7) critical: Memory corruption in smallvec
  - [GHSA-mm7v-vpv8-xfc3](https://github.com/advisories/GHSA-mm7v-vpv8-xfc3) critical: Double free in smallvec
  - [GHSA-55m5-whcv-c49c](https://github.com/advisories/GHSA-55m5-whcv-c49c) high: Use of Uninitialized Resource in smallvec

## vulnerable/services/web (LIVE)

- **lodash** 4.17.20 · production · direct · 2 high · fix: lodash@4.18.1
  - [GHSA-35jh-r3h4-6jhm](https://github.com/advisories/GHSA-35jh-r3h4-6jhm) high: Command Injection in lodash
  - [GHSA-r5fr-rjxr-66jc](https://github.com/advisories/GHSA-r5fr-rjxr-66jc) high: lodash vulnerable to Code Injection via `_.template` imports key names
- plus 2 moderate (in report.json)
```

The critical in `services/web` is in a dev tool, so it is counted in the Note column and does not raise the alarm. When a scan cannot run, the report opens with a **Scan problems** section, and when a live commit differs from the checkout, the project's section says what is still in what is live.

## In CI

```yaml
name: dependencies
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  dep-patrol:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: drewmattie-code/dep-patrol@v3
```

The job fails when something needs action (exit code 1) and when the scan is incomplete (exit code 2). Findings go to GitHub code scanning, located at the real lockfile, and the full report goes to the job summary. In a repository, every project counts as live unless a config says otherwise. Inputs are listed in [`action.yml`](action.yml).

## Live versus merged

```json
"deployed": {
  "my-saas-app": {"ref": "origin/production"},
  "api-server": {"command": "curl -fsS https://api.example.com/healthz | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"version\"])'"}
}
```

With an entry like this, the scan finds the commit that is live. If it is not the commit you have checked out, the lockfiles from the live commit are read out of git and scanned as well. A vulnerability that is fixed in your checkout but still deployed keeps the app on the "needs action" list until the fix ships.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every manifest was scanned and nothing is urgent. |
| 1 | Something needs action. |
| 2 | The scan is incomplete: a manifest failed, a root is missing, a live commit could not be found, or the scanner crashed. With `--strict`, anything unscanned counts too. |

## Requirements

- Python 3.9+. Reading `poetry.lock` and `uv.lock` needs 3.11+ (or `pip install tomli`). On an older Python those lockfiles are reported as not scanned.
- npm for JavaScript projects. pnpm and `osv-scanner` are optional and widen the coverage.
- git, for the live commit check.
- Network access to the npm registry and api.osv.dev. Only package names and versions are sent, no source code.

## What it does not cover

- Maven, Gradle, Composer, Bundler, NuGet, `Pipfile.lock` and conda are not looked at. Run `osv-scanner` yourself for those.
- Requirements that are not pinned to an exact version cannot be audited. They are named in the report.
- A dependency scanner tells you a known-bad version is present. It doesn't find bugs in your own code, misconfigurations or leaked secrets. Pair it with a code review, and keep secrets out of files your app can serve.

## Tests

```bash
python3 -m unittest discover -s tests
```

The unit tests run offline: real-format lockfiles, recorded tool output, a mocked OSV API, real git repositories and stand-in CLIs for the shell helpers. CI also runs the Action against freshly built test repositories with known advisories, and checks its production list against npm's own `npm audit --omit=dev`.

See [CHANGELOG.md](CHANGELOG.md) for what changed in v3 and how to upgrade from v2.

MIT licensed. Thanks to the reviewers whose lists of gaps shaped v2 and v3.
