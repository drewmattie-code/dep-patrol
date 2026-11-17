# dep-patrol

A monthly vulnerability patrol for every repo on your machine, packaged as a Claude Code skill.

AI coding tools make it easy to ship many small apps, and every one of them carries a dependency tree that keeps aging after launch. The typical failure looks like this. An app is clean on the day it ships. A few weeks later a framework flaw is published, such as "React2Shell" (CVE-2025-55182) in React Server Components and Next.js, and attackers can run code on the server and read its `.env`. Nothing in the app's code changed. Only the calendar did.

**dep-patrol** finds every project under your code folders, audits its dependencies, ranks the results by what is actually live on the internet, and gives your agent a careful playbook for patching production without breaking it.

## What it does

- **Finds projects** under the folders you name:
  - lockfiles for npm, pnpm, Yarn, Bun, Cargo and Go;
  - pinned Python requirements, `poetry.lock` and `uv.lock`.

  It understands JS workspaces, so monorepo packages aren't scanned twice.
- **Audits** with these, and needs nothing extra for npm, pnpm or Python:
  - `npm audit`, with production dependencies ranked apart from dev tooling;
  - `pnpm audit`;
  - the free [OSV.dev](https://osv.dev) API for Python, cached and rate-limit friendly;
  - `osv-scanner` for everything else, when it's installed.
- **Ranks** live apps first, then by worst severity. You set what counts as urgent, and you can ignore a finding if you give a reason.
- **Reports** in Markdown, JSON and SARIF (for GitHub code scanning). Each report opens with what's new, fixed or still open since the last run.
- **Alerts** through any shell command you configure (desktop notification, Slack webhook, Telegram bot), and only when something needs action.
- **Schedules** itself monthly with launchd on macOS or cron on Linux.
- **Patches safely.** `SKILL.md` is the agent's playbook:
  - branch from what is actually deployed;
  - bump only what the advisory needs;
  - pass the full test gate;
  - record the rollback;
  - deploy and verify on production.

  Helper scripts (`branch-from-deployed.sh`, `bump-and-verify.sh`, `record-rollback.sh`) turn the risky steps into commands that refuse unsafe states.

It also covers the traps that cost real time, such as scheduled publishers that redeploy an old checkout, or scoped deploy tokens.

## Install

```bash
git clone https://github.com/drewmattie-code/dep-patrol ~/.claude/skills/dep-patrol
mkdir -p ~/.dep-patrol && cp ~/.claude/skills/dep-patrol/dep-patrol.example.json ~/.dep-patrol/config.json
# edit ~/.dep-patrol/config.json: your roots, which apps are live, how to notify you
~/.claude/skills/dep-patrol/scripts/install-schedule.sh
```

Run it once by hand:

```bash
python3 ~/.claude/skills/dep-patrol/scripts/scan.py --config ~/.dep-patrol/config.json
```

Or ask Claude Code: *"run the dependency patrol"*, *"does this CVE affect any of our apps?"*, *"patch whatever the scan flagged"*.

## Requirements

Python 3.9+ (3.11+ parses lockfiles with the built-in `tomllib`; on older Pythons install `tomli`). npm for JavaScript projects (pnpm optional). Network access to the npm registry and api.osv.dev. Only package names and versions are sent, no source code.

## Scope

A dependency scanner tells you a known-bad version is present. It doesn't find bugs in your own code, misconfigurations or leaked secrets. Pair it with a code review, and keep secrets out of files your app can serve.

MIT licensed.

## Tests

```bash
python3 -m unittest discover -s tests
```

The tests run offline: real-format lockfile fixtures, a recorded `npm audit` result, a mocked OSV API, and an end-to-end run that checks the report files and exit codes.

Thanks to an early reviewer whose list of limitations shaped v2.
