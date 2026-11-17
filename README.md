# dep-patrol

A monthly vulnerability patrol for every repo on your machine, packaged as a Claude Code skill.

AI coding tools make it easy to ship many small apps, and every one of them carries a dependency tree that keeps aging after launch. The typical failure looks like this. An app is clean on the day it ships. A few weeks later a framework flaw is published, such as "React2Shell" (CVE-2025-55182) in React Server Components and Next.js, and attackers can run code on the server and read its `.env`. Nothing in the app's code changed. Only the calendar did.

**dep-patrol** finds every project under your code folders, audits its dependencies, ranks the results by what is actually live on the internet, and gives your agent a careful playbook for patching production without breaking it.

## What it does

- **Finds projects** under the folders you name (`package-lock.json`, `pnpm-lock.yaml`, pinned Python requirements, `poetry.lock`, `uv.lock`). Other ecosystems are listed as unscanned, so the gaps are visible.
- **Audits** with `npm audit` (production dependencies ranked apart from dev tooling), `pnpm audit`, and the free [OSV.dev](https://osv.dev) API for Python. Nothing extra to install.
- **Ranks** live apps first, then by worst severity, and writes `report.md` and `report.json`.
- **Alerts** through any shell command you configure (desktop notification, Slack webhook, Telegram bot), and only when something needs action.
- **Schedules** itself monthly with launchd on macOS or cron on Linux.
- **Patches safely.** `SKILL.md` is the agent's playbook:
  - branch from what is actually deployed;
  - bump only what the advisory needs;
  - pass the full test gate;
  - record the rollback;
  - deploy and verify on production.

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

Python 3.9+. npm for JavaScript projects (pnpm optional). Network access to the npm registry and api.osv.dev. Only package names and versions are sent, no source code.

## Scope

A dependency scanner tells you a known-bad version is present. It doesn't find bugs in your own code, misconfigurations or leaked secrets. Pair it with a code review, and keep secrets out of files your app can serve.

MIT licensed.
