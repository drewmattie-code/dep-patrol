---
name: dep-patrol
description: Monthly (or on-demand) dependency vulnerability patrol across every repo on a machine, then a safe patch-and-deploy loop for what matters. Finds every lockfile under your code folders, audits each one (npm, pnpm, Python, and Yarn/Bun/Cargo/Go through osv-scanner), tracks every advisory on its own, ranks by what is live on the internet, can check the commit that is actually deployed, and walks the fix (branch from what is deployed, bump, prove the advisory is gone, full test gate, deploy, verify on production). Use it whenever someone asks to scan repos for vulnerable dependencies, check whether a CVE or security post affects "our apps", audit packages, update vulnerable libraries, run the monthly security scan, add a dependency check to CI, or confirm that a security fix is really live, and when a news item names a package version (Next.js, React, lodash, axios, a Python library) that might be in use. Also use it before shipping an AI-built app: "it works" is not the definition of done.
---

# dep-patrol

AI-built apps ship fast and age fast. A framework release that was clean on launch day can carry an unauthenticated remote-code-execution hole six weeks later, and nothing in the code changed. This skill catches that on a schedule and fixes it without breaking production.

It has two halves: **scan** (cheap, automatic, monthly) and **patch** (careful, one live app at a time).

One rule runs through all of it: **a scan that did not run is never reported as clean.** Every lockfile gets its own outcome, and a failure is loud.

## 1. Scan

```bash
python3 scripts/scan.py --config ~/.dep-patrol/config.json            # every root in the config
python3 scripts/scan.py --config ~/.dep-patrol/config.json --notify   # and alert when something needs you
python3 scripts/scan.py --roots ~/code ~/work                          # ad hoc, no config
python3 scripts/scan.py --config ~/.dep-patrol/config.json --dry-run  # list what would be scanned, no network
python3 scripts/scan.py --config ~/.dep-patrol/config.json --exposed-only   # just the live apps (fast)
python3 scripts/scan.py --repo . --out /tmp/dp                         # one repository: no depth limit, all of it counts as live
python3 scripts/scan.py --repo . --verify-fixed GHSA-xxxx-xxxx-xxxx    # after a bump: is that advisory gone?
```

A machine-wide run writes `report.md`, `report.json`, `report.sarif` and `run.log` under `~/.dep-patrol/reports/<date>/` and prints one summary line. A `--repo` run writes files only when you give `--out`, so a one-repo report never lands in the monthly folder.

**Exit codes**, the same for every output format (`--json` included):

- `0`: every manifest was scanned and nothing is urgent.
- `1`: something needs action.
- `2`: the scan is incomplete. A manifest failed, a root is missing, the live commit could not be found, or the scanner crashed. With `--strict`, anything left unscanned or partly scanned also counts.

`--notify` fires on 1 **and** on 2. A monthly job that quietly stopped working is a finding.

### What each manifest can be

| Status | Meaning |
|---|---|
| `scanned` | Every package in it was checked. |
| `partial` | The pinned packages were checked. Loose requirements (`requests>=2`) could not be, and are named. |
| `unscanned` | Nothing could be checked: no scanner on this machine for it, or nothing is pinned. The report says what to install or run. |
| `failed` | The scanner ran and broke (registry down, unreadable lockfile). Exit code 2. |
| `covered` | A JS lockfile inside a workspace member. The workspace root's lockfile holds its dependencies. |
| `skipped` | A second JS lockfile in the same folder. The one named by `packageManager` in `package.json` is scanned, or npm's by default. |

A folder with both a JS lockfile and Python manifests is one project with several manifests. All of them are scanned.

### What scans what

- **npm** (`package-lock.json`, `npm-shrinkwrap.json`): `npm audit --json`.
- **pnpm** (`pnpm-lock.yaml`): `pnpm audit --json`. Without pnpm it falls back to osv-scanner.
- **Python** (`requirements*.txt` with `==` pins, `poetry.lock`, `uv.lock`): the free OSV.dev API.
  - Advisory details are cached for 7 days in `~/.dep-patrol/cache/osv/`.
  - Calls back off on HTTP 429 and honour `Retry-After`.
  - Git and local-path packages are skipped and named, because they are not PyPI packages.
  - A `requirements/` folder (`base.txt`, `dev.txt`, `prod.txt`) belongs to the project above it. A file pulled in with `-r` is read as part of the file that includes it, unless it is scanned on its own.
- **Yarn, Bun, Cargo, Go** (`yarn.lock`, `bun.lock`, `Cargo.lock`, `go.mod`): `osv-scanner` when it is on PATH (`brew install osv-scanner`). Without it they are `unscanned`, with the command to run.
- **Not looked at:** Maven, Gradle, Composer, Bundler, NuGet, `Pipfile.lock`, conda. Run `osv-scanner scan source -r .` yourself for those. This is a hard boundary, so a clean report says nothing about them.

### What a finding is

One finding is **one advisory against one package in one manifest**. A package with 12 advisories is 12 findings, and ignoring one leaves 11. Copies of the same advisory (a GHSA, a PYSEC and a RUSTSEC record for one CVE) are folded into one, with the other ids kept as aliases.

**Scope** says whether it ships:

- `production` or `dev`, when the manifest can prove it:
  - npm: the lockfile's own `dev` flag, per installed copy. Two versions of one package are judged separately.
  - pnpm: the audit's `dev` flag.
  - `uv.lock`: the dependency graph from the project's own entry.
  - `poetry.lock`: its `groups` field, or the graph from `pyproject.toml`.
  - requirements files: the file name (`requirements-dev.txt` is dev, `requirements.txt` is production).
- `scope not known` when it cannot (Cargo, Go, Yarn, Bun, an old npm lockfile, a requirements file with an unusual name). **It counts as production.**

**Severity** comes from the advisory database's own label when there is one, else from a CVSS 3 vector. An advisory nobody has rated is `unknown` and is listed as **Unrated**. Rust and Go advisories are often unrated, so by default they are shown but do not raise the alarm (`urgency.unknown_on_exposed` turns that on). Rust "unmaintained" notices are `info`.

"Needs action" means a **critical** anywhere in production scope, or a **critical or high** in an app marked live. Dev-only findings are counted in the table and never urgent.

### Config (`~/.dep-patrol/config.json`)

```json
{
  "roots": ["~/Projects", "~/code"],
  "max_depth": 3,
  "exclude": ["*/archive/*", "*-old"],
  "exposed": ["my-saas-app", "marketing-site/web"],
  "deployed": {
    "my-saas-app": {"ref": "origin/production"},
    "marketing-site/web": {"command": "curl -fsS https://example.com/healthz | python3 -c 'import json,sys; print(json.load(sys.stdin)[\"version\"])'"}
  },
  "urgency": {"critical_always": true, "high_on_exposed": true, "moderate_on_exposed": false, "unknown_on_exposed": false},
  "ignore": [{"advisory": "GHSA-xxxx-xxxx-xxxx", "project": "my-saas-app", "reason": "build-time only, not shipped"}],
  "notify": "osascript -e 'display notification \"$DEP_PATROL_SUMMARY\" with title \"dep-patrol\"'"
}
```

- **`exposed`** lists what runs a server on the internet. A plain word must equal the folder name. `repo/sub` matches a path suffix, and `*-prod` is a glob.
  - Static exports don't count: no server means no server-side holes.
- **`deployed`** says how to learn which commit is live (see the next section). Keys match like `exposed`.
- An `exposed` or `deployed` entry that matches no project is a scan problem (exit code 2). A live app whose folder moved would otherwise just stop being treated as live.
- **`ignore`** rules need a `reason` and a target: `advisory` (an id, alias or advisory URL), `package`, or both.
  - Matching is exact. `"GHSA-xxxx"` does not match a longer id, and `"next"` does not match `next-auth`.
  - A `package` rule with no `advisory` hides every advisory for that package, including future ones. Prefer `advisory`.
  - Ignored findings stay in the report. A rule that matched nothing is listed under Warnings.
- **`max_depth: null`** scans without a depth limit.
- **`notify`** is any shell command. It gets `DEP_PATROL_SUMMARY`, `DEP_PATROL_REPORT` and `DEP_PATROL_EXIT` in its environment.
- **Unknown keys** are listed under Warnings.

### Live versus merged

Three clean checkouts say nothing about what customers are hitting. With a `deployed` entry, the scan finds the live commit and compares:

- `{"ref": "origin/production"}`: a branch or tag your deploy tracks.
- `{"command": "..."}`: any command that prints the live commit (or a tag) first. A health endpoint that returns the version works well.

When the live commit is this checkout, the report says so. When it differs, the manifests **as they were at the live commit** are read from git and scanned too. The report then shows what is still in what is live, even when this checkout is already fixed, and that counts as needing action.

If the live commit cannot be found (the command failed, or the commit is not in this checkout), that is an incomplete scan: exit code 2. Run `git fetch` and scan again.

### Reading the change list

Each report opens with what changed since the last one, advisory by advisory:

- **New** and **Still open** are what they say.
- **Fixed** means the manifest was scanned again and the advisory is gone. It is never inferred from silence.
- **Not re-checked** means the manifest failed this time. Its last known findings are carried forward, marked with the date they were last seen, and still count.
- A project that is no longer found is listed as such, not as fixed.

### Schedule it

`scripts/install-schedule.sh` installs a monthly job: launchd on macOS, a crontab line on Linux. It runs on the 1st at 09:00.

- On a Mac that was asleep, launchd runs it once at the next wake. `ThrottleInterval` stops repeated runs.
- It schedules a Python that can read `poetry.lock` and `uv.lock` (3.11+) when one is installed. `--dry-run` shows the choice.
- `scripts/uninstall-schedule.sh` removes it.
- The last run's output is in `~/.dep-patrol/last-run.log`.

Scan every machine that holds a **deployed** copy of a repo, because the copy on a laptop is often not what is live.

### In CI

The repository is also a GitHub Action. It scans the checkout, uploads SARIF to code scanning, writes the report to the job summary, and fails the job on exit code 1 or 2:

```yaml
permissions:
  contents: read
  security-events: write
steps:
  - uses: actions/checkout@v7
  - uses: drewmattie-code/dep-patrol@v3
```

Inputs: `path`, `config`, `strict` (default true), `upload-sarif` (default true), `category`, `install-osv-scanner` (default true). SARIF holds every finding that counts (production or scope not known, not ignored) at any severity, and points at the real manifest with a path relative to the repository.

## 2. Triage the report

Work the report top-down. Scan problems come first, then projects sorted live-first and worst-first. For each finding, answer three questions before touching anything:

1. **Is this the version that is actually running?** With a `deployed` entry the report answers it. Without one, find the deployed commit (the platform's release list, the image tag, or the branch your deploy uses) and audit *that*. Live content that only exists on a newer branch is the classic trap: deploying an old checkout to fix a CVE silently rolls back features.
2. **Does the vulnerable code run in production?** The scope column is the first answer. A transitive dependency of a CLI, a test runner or a PDF tool that only runs locally is real but not urgent. Server frameworks (Next.js, Express, auth libraries) and anything that parses untrusted input are urgent.
3. **Is there a fix that isn't a major version?** Prefer the smallest patch that clears the advisory. A major bump is its own project. Note it and move on.

Also read the platform's logs. Exploit attempts against a fresh CVE are often already in your access or WAF logs, and seeing them changes the priority.

## 3. Patch, one live app at a time

For each urgent app, prefer the helper scripts over improvised shell. They refuse unsafe states and stop at the first failure.

1. **Branch from what is deployed**, not from whatever is checked out:
   `scripts/branch-from-deployed.sh <deployed-ref> security/<pkg>-<version>`.
   It refuses to run over uncommitted work.
2. **Bump only what the advisory needs, and prove it**:
   `scripts/bump-and-verify.sh --fixes GHSA-xxxx-xxxx-xxxx next@16.4.6 eslint-config-next@16.4.6`.
   - It works for npm, pnpm, uv and pinned requirements files. The lockfile in the folder picks the tool.
   - `--fixes` names the advisories the bump is for. Each must be present before the bump (a wrong id stops here) and gone after it, in a scan that really ran. A bump that leaves the advisory open fails before the tests.
   - Then it runs typecheck, tests and build, and exits non-zero at the first failure. Set `TEST_CMD` or `BUILD_CMD` when the project uses other commands. Python has no default test command, and a bump with no tests exits 3.
   - It stops if the lockfile is not committed.
   - Add any other *critical* in production dependencies that has a non-major fix, especially auth libraries.
   - When a transitive package has a same-major fix but its parent pins an old range, an npm `overrides` entry is the surgical fix. Gate it the same way.
3. **If the gate fails**, check whether it already failed before your bump by building the untouched deployed ref. If it did, say so in the commit message rather than fixing unrelated code.
4. **Record the rollback** before you deploy: `scripts/record-rollback.sh fly <app>` (also `vercel`, `wrangler`, or `other <app> <release>`).
   If it cannot read what is live it says STOP and records nothing. Find the release yourself and pass it as the third argument. Do not deploy without a rollback target.
5. **Deploy**, then **verify on production**:
   `scripts/smoke-check.sh https://app.example.com/ https://app.example.com/api/session=401`.
   The home page and key routes return 200, a signed-out endpoint returns 401, and the platform's logs show no new errors.
6. **Commit and push** with the advisory reference, so the next person can see why the version moved.
7. **Scan again.** With a `deployed` entry, the next scan confirms the advisory is gone from what is live.

Do internal tools after the live apps, and always give a heads-up before restarting something people are using.

## 4. Gotchas that cost real time

- **Scheduled deploy jobs** (nightly publishers, cron builders) may push from a different machine or checkout. Patch *that* checkout, between runs, or the next scheduled run quietly redeploys the old version.
- **Deploy credentials differ by context.** A CLI that works in your shell may have no token under launchd, nohup or ssh. Look for the token file the scheduled job uses rather than logging in again.
- **Scoped cloud tokens**: a token that can deploy static pages often cannot deploy workers or functions. A failed deploy with an auth error is a scope problem, not an outage.
- **Lockfiles that aren't committed** mean a fresh install pulls newer transitive versions. The build can break for reasons unrelated to your bump. Check with the original lockfile before blaming the patch.
- **Bundled libraries with web workers** (MapLibre 6, PDF.js) can build fine and still fail at runtime when the worker file isn't shipped. Load the page that uses them and check the browser console, not just the build.
- **npm lists one advisory once per release line.** The same GHSA can appear with a 6.x range and a 7.x range. Reading only the first one can file a production copy under dev. The scanner folds them, so check its answer before trusting a hand count from `npm audit`.
- **Merged is not deployed.** A fix on `main` with production still on last week's image is the most common false "done". Add a `deployed` entry for every live app.
- **zsh arrays are 1-indexed.** Loops that pair files with upload slots by index silently shift by one. Run such loops in bash, and checksum what landed.

## 5. After the run

Write down which apps were patched, the release IDs, what was left and why (a major bump, a credential that needs a human, unrelated build breakage). Put it in the team's notes so next month's run starts from there.
