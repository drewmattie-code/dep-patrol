---
name: dep-patrol
description: Monthly (or on-demand) dependency vulnerability patrol across every repo on a machine, then a safe patch-and-deploy loop for what matters. Finds every project under your code folders, runs npm/pnpm audit and OSV.dev checks, ranks by what is live on the internet, and walks the fix (branch from what is deployed, bump, full test gate, deploy, verify on production). Use it whenever someone asks to scan repos for vulnerable dependencies, check whether a CVE or security post affects "our apps", audit packages, update vulnerable libraries, or run the monthly security scan, and when a news item names a package version (Next.js, React, lodash, axios, a Python library) that might be in use. Also use it before shipping an AI-built app: "it works" is not the definition of done.
---

# dep-patrol

AI-built apps ship fast and age fast. A framework release that was clean on launch day can carry an unauthenticated remote-code-execution hole six weeks later, and nothing in the code changed. This skill catches that on a schedule and fixes it without breaking production.

It has two halves: **scan** (cheap, automatic, monthly) and **patch** (careful, one live app at a time).

## 1. Scan

```bash
python3 scripts/scan.py --config ~/.dep-patrol/config.json            # report only
python3 scripts/scan.py --config ~/.dep-patrol/config.json --notify   # and alert if anything is urgent
python3 scripts/scan.py --roots ~/code ~/work                          # ad hoc, no config
```

It writes `report.md` and `report.json` under `~/.dep-patrol/reports/<date>/` and prints one summary line. Exit code 1 means something needs action.

- **npm** projects (`package-lock.json`): `npm audit --json --omit=dev`, so production dependencies are ranked separately from dev tooling. Dev-only findings are counted in the table, not listed.
- **pnpm** projects: `pnpm audit --prod` when pnpm is installed.
- **Python** (pinned `requirements*.txt`, `poetry.lock`, `uv.lock`): checked against the free OSV.dev API. Unpinned requirements can't be checked, and the report says so.
- **Everything else** (Rust, Go, yarn/bun-only): listed as unscanned so the gap is visible. Install `osv-scanner` if you need those covered.

"Needs action" means a **critical** anywhere in production dependencies, or a **critical/high** in an app marked live (`exposed` in the config).

### Config (`~/.dep-patrol/config.json`)

```json
{
  "roots": ["~/Projects", "~/code"],
  "max_depth": 3,
  "exclude": ["*/archive/*", "*-old"],
  "exposed": ["my-saas-app", "marketing-site/web"],
  "notify": "osascript -e 'display notification \"$DEP_PATROL_SUMMARY\" with title \"dep-patrol\"'"
}
```

`exposed` lists what is reachable from the internet (folder name, `repo/subfolder`, or full path). `notify` is any shell command. It gets `DEP_PATROL_SUMMARY` and `DEP_PATROL_REPORT` in its environment, so it can post to Slack, Telegram or email.

### Schedule it

`scripts/install-schedule.sh` installs a monthly job: launchd on macOS, a crontab line on Linux. It runs on the 1st at 09:00. On a Mac that was asleep, launchd runs it at the next wake.

Scan every machine that holds a **deployed** copy of a repo, because the copy on a laptop is often not what is live.

## 2. Triage the report

Work the report top-down. It is already sorted live-first, then worst-first. For each finding, answer three questions before touching anything:

1. **Is this the version that is actually running?** The checkout you scanned may be behind or ahead of production. Find the deployed commit (the platform's release list, the image tag, or the branch your deploy uses) and audit *that*. Live content that only exists on a newer branch is the classic trap: deploying an old checkout to fix a CVE silently rolls back features.
2. **Does the vulnerable code run in production?** A transitive dependency of a CLI, a test runner or a PDF tool that only runs locally is real but not urgent. Server frameworks (Next.js, Express, auth libraries) and anything that parses untrusted input are urgent.
3. **Is there a fix that isn't a major version?** Prefer the smallest patch that clears the advisory. A major bump is its own project. Note it and move on.

Also read the platform's logs. Exploit attempts against a fresh CVE are often already in your access or WAF logs, and seeing them changes the priority.

## 3. Patch, one live app at a time

For each urgent app:

1. **Branch from what is deployed**, not from whatever is checked out: `git switch -c security/<pkg>-<version> <deployed-ref>`.
2. **Bump only what the advisory needs**: `npm install --save-exact <pkg>@<fixed>`. For Next.js, bump `eslint-config-next` alongside it. Re-run `npm audit --omit=dev` and confirm the criticals are gone. Add any other *critical* in production dependencies that has a non-major fix, especially auth libraries.
3. **Gate**: typecheck, the full test suite, and a production build. All green or stop. If something was already broken before your bump, prove it by building the untouched deployed ref, then say so in the commit message rather than fixing unrelated code.
4. **Record the rollback** (current release or image ID) before you deploy.
5. **Deploy**, then **verify on production**: the home page and key routes return 200, the auth endpoints answer correctly (a wrong-password sign-in returns 401, the session endpoint returns 200), and the platform's logs show no new errors.
6. **Commit and push** with the advisory reference, so the next person can see why the version moved.

Do internal tools after the live apps, and always give a heads-up before restarting something people are using.

## 4. Gotchas that cost real time

- **Scheduled deploy jobs** (nightly publishers, cron builders) may push from a different machine or checkout. Patch *that* checkout, between runs, or the next scheduled run quietly redeploys the old version.
- **Deploy credentials differ by context.** A CLI that works in your shell may have no token under launchd, nohup or ssh. Look for the token file the scheduled job uses rather than logging in again.
- **Scoped cloud tokens**: a token that can deploy static pages often cannot deploy workers or functions. A failed deploy with an auth error is a scope problem, not an outage.
- **Lockfiles that aren't committed** mean a fresh install pulls newer transitive versions. The build can break for reasons unrelated to your bump. Check with the original lockfile before blaming the patch.
- **zsh arrays are 1-indexed.** Loops that pair files with upload slots by index silently shift by one. Run such loops in bash, and checksum what landed.

## 5. After the run

Write down which apps were patched, the release IDs, what was left and why (a major bump, a credential that needs a human, unrelated build breakage). Put it in the team's notes so next month's run starts from there.
