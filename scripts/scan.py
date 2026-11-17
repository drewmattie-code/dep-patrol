#!/usr/bin/env python3
"""dep-patrol: find every project under some folders, audit its dependencies, rank what matters.

Works with what a dev machine already has:
  * npm (package-lock.json): one `npm audit --json`, split into production vs dev using
    `npm ls --omit=dev` (local, no network).
  * pnpm (pnpm-lock.yaml): `pnpm audit --json --prod` when pnpm is installed.
  * Python (pinned requirements*.txt, poetry.lock, uv.lock): OSV.dev API, with a local cache.
  * Yarn / Bun / Cargo / Go: `osv-scanner` when it is on PATH; otherwise listed as unscanned
    with the exact command to cover them.

usage:
  scan.py --config dep-patrol.json             # scan, write report.md/.json/.sarif, print summary
  scan.py --roots ~/Projects ~/code            # ad hoc, no config
  scan.py --config dep-patrol.json --notify    # also run the config's notify command if anything is urgent
  scan.py --config dep-patrol.json --dry-run   # list what would be scanned, no network

Exit code: 0 nothing urgent, 1 something to fix, 2 scanner problem (no roots, or every audit failed).
"""
import argparse, datetime as dt, fnmatch, json, os, re, shutil, subprocess, sys, time, urllib.error, urllib.request
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

VERSION = "2.0.0"
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "out", ".venv", "venv", "env", "__pycache__",
             ".turbo", ".open-next", ".wrangler", ".cache", "coverage", "vendor", "target", ".worktrees", "worktrees"}
SEV_ORDER = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1, "info": 0, "unknown": 0}
CONFIG_KEYS = {"roots", "include", "exclude", "exposed", "max_depth", "notify", "out", "urgency", "ignore",
               "osv_cache_days", "_notes"}
DEFAULT_URGENCY = {"critical_always": True, "high_on_exposed": True, "moderate_on_exposed": False}
CACHE_DIR = Path(os.path.expanduser("~/.dep-patrol/cache/osv"))
LOG_LINES = []


def log(msg):
    line = f"{dt.datetime.now().strftime('%H:%M:%S')} {msg}"
    LOG_LINES.append(line)
    print(line, file=sys.stderr, flush=True)


# ------------------------------------------------------------------ config
def load_config(path, roots_override):
    cfg = {"roots": [], "include": [], "exclude": [], "exposed": [], "max_depth": 3, "ignore": [],
           "urgency": dict(DEFAULT_URGENCY), "osv_cache_days": 7}
    problems = []
    if path:
        with open(os.path.expanduser(path)) as fh:
            user = json.load(fh)
        unknown = set(user) - CONFIG_KEYS
        if unknown:
            problems.append(f"unknown config keys: {', '.join(sorted(unknown))}")
        urg = user.pop("urgency", {})
        cfg.update(user)
        cfg["urgency"].update(urg)
    if roots_override:
        cfg["roots"] = roots_override
    if not cfg["roots"]:
        problems.append("no roots: give --roots or set roots in the config")
    missing = [r for r in cfg["roots"] if not Path(os.path.expanduser(r)).is_dir()]
    if missing:
        problems.append(f"roots not found: {', '.join(missing)}")
    if cfg.get("notify") and not isinstance(cfg["notify"], str):
        problems.append("notify must be a shell command string")
    for ig in cfg["ignore"]:
        if not isinstance(ig, dict) or "match" not in ig or "reason" not in ig:
            problems.append(f"ignore entries need 'match' and 'reason': {ig}")
    return cfg, problems


# ------------------------------------------------------------------ discovery
def _kind(fs):
    if "package-lock.json" in fs:
        return "npm"
    if "pnpm-lock.yaml" in fs:
        return "pnpm"
    if "yarn.lock" in fs:
        return "yarn"
    if "bun.lock" in fs or "bun.lockb" in fs:
        return "bun"
    if {"poetry.lock", "uv.lock"} & fs or any(re.match(r"requirements.*\.txt$", f) for f in fs):
        return "python"
    if "Cargo.lock" in fs:
        return "rust"
    if "go.sum" in fs:
        return "go"
    return None


def _workspace_globs(proj):
    try:
        pkg = json.loads((Path(proj) / "package.json").read_text())
    except Exception:
        return []
    ws = pkg.get("workspaces")
    if isinstance(ws, dict):
        ws = ws.get("packages", [])
    return ws if isinstance(ws, list) else []


def discover(roots, max_depth, excludes, includes=()):
    """Return [(path, kind, name)] for every project. name is stable: relative to the root's parent."""
    found = {}
    for root in roots:
        root = Path(os.path.expanduser(root)).resolve()
        if not root.is_dir():
            continue
        base = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            p = Path(dirpath)
            depth = len(p.parts) - base
            keep_going = max_depth is None or depth < max_depth
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".") and keep_going]
            sp = str(p)
            if any(fnmatch.fnmatch(sp, pat) or fnmatch.fnmatch(p.name, pat) for pat in excludes):
                dirnames[:] = []
                continue
            if includes and not any(fnmatch.fnmatch(sp, pat) or fnmatch.fnmatch(p.name, pat) for pat in includes):
                continue
            kind = _kind(set(filenames))
            if kind:
                found[sp] = (kind, os.path.relpath(p, root.parent))
    # monorepos: a JS workspace root owns its member packages; drop members that have their own lockfile
    ws_roots = {path: _workspace_globs(path) for path, (k, _) in found.items() if k in ("npm", "pnpm", "yarn", "bun")}
    for path in list(found):
        for wroot, globs in ws_roots.items():
            if path != wroot and path.startswith(wroot + os.sep) and globs:
                rel = os.path.relpath(path, wroot)
                if any(fnmatch.fnmatch(rel, g.rstrip("/")) for g in globs):
                    found.pop(path, None)
                    break
    return sorted((k, v[0], v[1]) for k, v in found.items())


# ------------------------------------------------------------------ helpers
def run_json(cmd, cwd, timeout=300):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return None, str(e)
    try:
        return json.loads(r.stdout or "{}"), None
    except json.JSONDecodeError:
        return None, ((r.stderr or "") + (r.stdout or ""))[-200:].strip()


def tool_version(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip().splitlines()[0]
    except Exception:
        return None


def finding(package, severity, direct, rng, fix, titles, urls, ids=(), via=()):
    return {"package": package, "severity": (severity or "unknown").lower(), "direct": direct, "range": rng,
            "fix": fix, "titles": list(titles)[:6], "urls": list(urls)[:6], "ids": list(ids)[:10], "via": list(via)[:4]}


# ------------------------------------------------------------------ npm / pnpm
def npm_prod_names(proj):
    data, _ = run_json(["npm", "ls", "--omit=dev", "--all", "--json"], proj, timeout=120)
    names = set()

    def walk(node):
        for name, child in (node or {}).get("dependencies", {}).items():
            if name not in names:
                names.add(name)
                walk(child)
    walk(data or {})
    return names


def npm_findings(proj):
    """One npm audit for everything; production vs dev split from the local tree."""
    data, err = run_json(["npm", "audit", "--json"], proj)
    if data is None:
        return None, {}, err
    if "error" in data and "vulnerabilities" not in data:
        return None, {}, json.dumps(data["error"])[:200]
    prod_names = npm_prod_names(proj)
    prod, dev_counts = [], {}
    for name, v in (data.get("vulnerabilities") or {}).items():
        adv = [x for x in v.get("via", []) if isinstance(x, dict)]
        fix = v.get("fixAvailable")
        if isinstance(fix, dict):
            fix_s = f"{fix.get('name')}@{fix.get('version')}" + (" (major)" if fix.get("isSemVerMajor") else "")
        else:
            fix_s = "yes" if fix else "none"
        f = finding(name, v.get("severity"), bool(v.get("isDirect")), v.get("range", ""), fix_s,
                    sorted({a.get("title", "") for a in adv}), sorted({a.get("url", "") for a in adv if a.get("url")}),
                    ids=[str(a.get("source")) for a in adv if a.get("source")],
                    via=[x for x in v.get("via", []) if isinstance(x, str)])
        if name in prod_names or not prod_names:
            prod.append(f)
        else:
            dev_counts[f["severity"]] = dev_counts.get(f["severity"], 0) + 1
    return prod, dev_counts, None


def pnpm_findings(proj):
    if not shutil.which("pnpm"):
        return None, {}, "pnpm not installed (brew install pnpm, or run: npx osv-scanner -r .)"
    data, err = run_json(["pnpm", "audit", "--json", "--prod"], proj)
    if data is None:
        return None, {}, err
    out = [finding(a.get("module_name"), a.get("severity"), False, a.get("vulnerable_versions", ""),
                   a.get("patched_versions", "?"), [a.get("title", "")], [a.get("url", "")],
                   ids=[str(a.get("github_advisory_id") or a.get("id"))])
           for a in (data.get("advisories") or {}).values()]
    return out, {}, None


# ------------------------------------------------------------------ OSV (python) with cache + backoff
def http_json(url, payload=None, tries=4):
    for attempt in range(tries):
        req = urllib.request.Request(url, data=json.dumps(payload).encode() if payload is not None else None,
                                     headers={"Content-Type": "application/json", "User-Agent": f"dep-patrol/{VERSION}"})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and attempt < tries - 1:
                wait = float(e.headers.get("Retry-After") or 2 ** attempt)
                time.sleep(min(wait, 30))
                continue
            raise
        except urllib.error.URLError:
            if attempt < tries - 1:
                time.sleep(2 ** attempt)
                continue
            raise


def osv_vuln(vid, cache_days):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    f = CACHE_DIR / f"{re.sub(r'[^A-Za-z0-9._-]', '_', vid)}.json"
    if f.exists() and time.time() - f.stat().st_mtime < cache_days * 86400:
        return json.loads(f.read_text())
    v = http_json(f"https://api.osv.dev/v1/vulns/{vid}")
    f.write_text(json.dumps(v))
    return v


def osv_severity(v):
    sev = (v.get("database_specific") or {}).get("severity")
    if not sev:
        for a in v.get("affected", []):
            sev = (a.get("database_specific") or {}).get("severity") or sev
    return (sev or "unknown").lower()


def python_pins(proj):
    """Exact pins from requirements*.txt (==) and every package in poetry.lock / uv.lock (TOML)."""
    pins, unpinned = {}, []
    p = Path(proj)
    for f in sorted(p.glob("requirements*.txt")):
        for line in f.read_text(errors="ignore").splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "git+", "http")):
                continue
            m = re.match(r"^([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+!]+)", line)
            if m:
                pins[m.group(1).lower()] = m.group(3)
            else:
                n = re.match(r"^([A-Za-z0-9_.\-]+)", line)
                if n:
                    unpinned.append(n.group(1).lower())
    for lock in ("poetry.lock", "uv.lock"):
        f = p / lock
        if not f.exists():
            continue
        if tomllib:
            data = tomllib.loads(f.read_text(encoding="utf-8", errors="ignore"))
            for pkg in data.get("package", []):
                name, ver = (pkg.get("name") or "").lower(), pkg.get("version")
                if name and ver:
                    pins[name] = ver
        else:  # pragma: no cover  (Python < 3.11 without tomli)
            name = None
            for line in f.read_text(errors="ignore").splitlines():
                m = re.match(r'^name\s*=\s*"([^"]+)"', line)
                if m:
                    name = m.group(1).lower()
                    continue
                m = re.match(r'^version\s*=\s*"([^"]+)"', line)
                if m and name:
                    pins[name], name = m.group(1), None
    unpinned = [u for u in unpinned if u not in pins]
    return pins, unpinned


def python_findings(proj, cache_days=7):
    pins, unpinned = python_pins(proj)
    note = f"unpinned, not checked: {', '.join(unpinned[:8])}" if unpinned else None
    if not pins:
        return [], {}, note or "no pinned versions"
    names = sorted(pins)
    try:
        res = http_json("https://api.osv.dev/v1/querybatch",
                        {"queries": [{"package": {"name": n, "ecosystem": "PyPI"}, "version": pins[n]} for n in names]})
    except Exception as e:
        return None, {}, f"OSV unreachable: {e}"
    out = []
    for n, r in zip(names, res.get("results", [])):
        ids = [v["id"] for v in r.get("vulns", [])]
        if not ids:
            continue
        sevs, titles, urls, fixes = [], [], [], set()
        for vid in ids[:10]:
            try:
                v = osv_vuln(vid, cache_days)
            except Exception:
                continue
            sevs.append(osv_severity(v))
            titles.append((v.get("summary") or vid)[:140])
            urls.append(f"https://osv.dev/vulnerability/{vid}")
            for a in v.get("affected", []):
                for rg in a.get("ranges", []):
                    fixes.update(ev["fixed"] for ev in rg.get("events", []) if "fixed" in ev)
        worst = max(sevs or ["unknown"], key=lambda s: SEV_ORDER.get(s, 0))
        out.append(finding(n, worst, True, f"=={pins[n]}", ", ".join(sorted(fixes)[:3]) or "?", titles, urls, ids=ids))
    return out, {}, note


# ------------------------------------------------------------------ osv-scanner for everything else
def osv_scanner_findings(proj):
    if not shutil.which("osv-scanner"):
        return None, {}, f"not scanned: install osv-scanner (brew install osv-scanner), then: osv-scanner scan source -r {proj}"
    data, err = run_json(["osv-scanner", "scan", "source", "--format", "json", "-r", proj], proj, timeout=600)
    if data is None:
        return None, {}, err
    out = []
    for res in data.get("results", []):
        for pk in res.get("packages", []):
            info = pk.get("package", {})
            vulns = pk.get("vulnerabilities", [])
            if not vulns:
                continue
            sevs = [osv_severity(v) for v in vulns]
            worst = max(sevs or ["unknown"], key=lambda s: SEV_ORDER.get(s, 0))
            out.append(finding(info.get("name"), worst, False, info.get("version", ""), "see advisories",
                               [(v.get("summary") or v.get("id", ""))[:140] for v in vulns],
                               [f"https://osv.dev/vulnerability/{v.get('id')}" for v in vulns],
                               ids=[v.get("id") for v in vulns]))
    return out, {}, None


# ------------------------------------------------------------------ context
def git_info(proj):
    def g(*args):
        try:
            return subprocess.run(["git", *args], cwd=proj, capture_output=True, text=True, timeout=20).stdout.strip()
        except Exception:
            return ""
    return {"branch": g("rev-parse", "--abbrev-ref", "HEAD"), "commit": g("log", "-1", "--format=%h %cs"),
            "dirty": bool(g("status", "--porcelain"))}


def is_exposed(proj, name, patterns):
    """A pattern with a slash matches a path suffix ('repo/web'); a glob matches the folder name;
    a plain word must equal the folder name or the whole project name."""
    folder = Path(proj).name
    for p in patterns:
        p = p.strip().rstrip("/")
        if "/" in p:
            if proj.endswith("/" + p.lstrip("/")) or proj == os.path.expanduser(p) or name.endswith(p):
                return True
        elif any(ch in p for ch in "*?["):
            if fnmatch.fnmatch(folder, p):
                return True
        elif folder == p or name == p:
            return True
    return False


def apply_ignores(entry, ignores):
    kept, ignored = [], []
    for f in entry["prod"] or []:
        hay = [f["package"], *f["ids"], *f["urls"]]
        rule = next((ig for ig in ignores if any(ig["match"] == h or ig["match"] in h for h in hay)
                     and (not ig.get("project") or fnmatch.fnmatch(entry["name"], ig["project"]))), None)
        if rule:
            ignored.append({"package": f["package"], "reason": rule["reason"]})
        else:
            kept.append(f)
    entry["prod"] = kept if entry["prod"] is not None else None
    entry["ignored"] = ignored


# ------------------------------------------------------------------ scan + report
def scan(cfg, dry_run=False):
    projects = discover(cfg["roots"], cfg.get("max_depth", 3), cfg.get("exclude", []), cfg.get("include", []))
    log(f"found {len(projects)} projects")
    results = []
    for proj, kind, name in projects:
        entry = {"path": proj, "name": name, "kind": kind, "exposed": is_exposed(proj, name, cfg.get("exposed", [])),
                 "git": git_info(proj), "prod": [], "dev_counts": {}, "error": None, "ignored": [], "seconds": 0}
        if dry_run:
            log(f"  would scan {kind:7s} {name}{' (live)' if entry['exposed'] else ''}")
            results.append(entry)
            continue
        t0 = time.time()
        if kind == "npm":
            entry["prod"], entry["dev_counts"], entry["error"] = npm_findings(proj)
        elif kind == "pnpm":
            entry["prod"], entry["dev_counts"], entry["error"] = pnpm_findings(proj)
        elif kind == "python":
            entry["prod"], entry["dev_counts"], entry["error"] = python_findings(proj, cfg.get("osv_cache_days", 7))
        else:
            entry["prod"], entry["dev_counts"], entry["error"] = osv_scanner_findings(proj)
        entry["seconds"] = round(time.time() - t0, 1)
        apply_ignores(entry, cfg.get("ignore", []))
        log(f"  {kind:7s} {name} {entry['seconds']}s" + (f"  ({entry['error'][:80]})" if entry["error"] else ""))
        results.append(entry)
    return results


def worst(entry):
    return max([SEV_ORDER.get(f["severity"], 0) for f in (entry["prod"] or [])] or [0])


def urgent(entry, rules=DEFAULT_URGENCY):
    sev = {f["severity"] for f in (entry["prod"] or [])}
    if rules.get("critical_always", True) and "critical" in sev:
        return True
    if entry["exposed"]:
        if rules.get("high_on_exposed", True) and sev & {"critical", "high"}:
            return True
        if rules.get("moderate_on_exposed", False) and sev & {"critical", "high", "moderate", "medium"}:
            return True
    return False


def finding_keys(results):
    return {(e["name"], f["package"], f["severity"]) for e in results for f in (e["prod"] or [])
            if f["severity"] in ("critical", "high")}


def previous_report(out_root, today):
    dirs = sorted(d for d in out_root.glob("*") if d.is_dir() and d.name < today and (d / "report.json").exists())
    if not dirs:
        return None, None
    try:
        return dirs[-1].name, json.loads((dirs[-1] / "report.json").read_text())
    except Exception:
        return None, None


def render(results, when, rules=DEFAULT_URGENCY, prev=None, tools=None):
    rows = sorted(results, key=lambda e: (-int(e["exposed"]), -worst(e), e["name"]))
    nurg = sum(1 for e in results if urgent(e, rules))
    lines = [f"# Dependency scan, {when}", "",
             f"{len(results)} projects scanned. **{nurg} need action** (critical anywhere, or critical/high in a live app).", ""]
    if prev:
        pname, pres = prev
        now, before = finding_keys(results), finding_keys(pres)
        new, fixed = sorted(now - before), sorted(before - now)
        lines += [f"## Since the last scan ({pname})", "",
                  f"- **New:** {len(new)}" + (": " + ", ".join(f"{n} {p} ({s})" for n, p, s in new[:15]) if new else ""),
                  f"- **Fixed:** {len(fixed)}" + (": " + ", ".join(f"{n} {p}" for n, p, s in fixed[:15]) if fixed else ""),
                  f"- **Still open:** {len(now & before)}", ""]
    lines += ["| Project | Live | Critical | High | Moderate | Branch | Note |", "|---|---|---|---|---|---|---|"]
    for e in rows:
        c = {s: sum(1 for f in (e["prod"] or []) if f["severity"] == s) for s in ("critical", "high", "moderate")}
        note = (e["error"] or "")[:70]
        if e["dev_counts"]:
            note = (note + " dev-only: " + ", ".join(f"{k} {v}" for k, v in sorted(e["dev_counts"].items()))).strip()
        if e.get("ignored"):
            note = (note + f" ignored: {len(e['ignored'])}").strip()
        lines.append(f"| {e['name']} | {'yes' if e['exposed'] else ''} | {c['critical'] or ''} | {c['high'] or ''} | "
                     f"{c['moderate'] or ''} | {e['git']['branch']}{' (dirty)' if e['git']['dirty'] else ''} | {note} |")
    for e in rows:
        bad = [f for f in (e["prod"] or []) if f["severity"] in ("critical", "high")]
        if not bad:
            continue
        lines += ["", f"## {e['name']}{' (LIVE)' if e['exposed'] else ''}", f"`{e['path']}`", ""]
        for f in sorted(bad, key=lambda f: -SEV_ORDER.get(f["severity"], 0)):
            pkg = f"[{f['package']}]({f['urls'][0]})" if f["urls"] else f["package"]
            lines.append(f"- **{pkg}** {f['severity']}{' (direct)' if f['direct'] else ''}, affected {f['range']}, fix: {f['fix']}")
            for t, u in zip(f["titles"], f["urls"] + [""] * 10):
                lines.append(f"  - {t} {u}".rstrip())
            if f["via"]:
                lines.append(f"  - comes in through: {', '.join(f['via'])}")
        for ig in e.get("ignored", []):
            lines.append(f"- ignored {ig['package']}: {ig['reason']}")
    if tools:
        lines += ["", "## How this was scanned", ""] + [f"- {k}: {v}" for k, v in tools.items()]
    return "\n".join(lines) + "\n"


def sarif(results):
    """Minimal SARIF 2.1.0: one result per critical/high production finding, located at the lockfile."""
    level = {"critical": "error", "high": "error", "moderate": "warning", "medium": "warning", "low": "note"}
    rules, out = {}, []
    lock = {"npm": "package-lock.json", "pnpm": "pnpm-lock.yaml", "python": "requirements.txt", "yarn": "yarn.lock",
            "bun": "bun.lock", "rust": "Cargo.lock", "go": "go.sum"}
    for e in results:
        for f in e["prod"] or []:
            if f["severity"] not in ("critical", "high"):
                continue
            rid = (f["ids"] or [f["package"]])[0]
            rules.setdefault(rid, {"id": rid, "shortDescription": {"text": (f["titles"] or [f["package"]])[0][:200]},
                                   "helpUri": (f["urls"] or ["https://osv.dev"])[0]})
            out.append({"ruleId": rid, "level": level.get(f["severity"], "warning"),
                        "message": {"text": f"{f['package']} {f['range']} ({f['severity']}), fix: {f['fix']}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {
                            "uri": os.path.join(e["path"], lock.get(e["kind"], ""))}}}]})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "dep-patrol", "version": VERSION, "rules": list(rules.values())}},
                      "results": out}]}


def main(argv=None):
    ap = argparse.ArgumentParser(description="dep-patrol dependency scan")
    ap.add_argument("--config")
    ap.add_argument("--roots", nargs="*")
    ap.add_argument("--out", help="report folder (default ~/.dep-patrol/reports)")
    ap.add_argument("--notify", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="list what would be scanned; no network")
    ap.add_argument("--json", action="store_true", help="print the raw results as JSON on stdout")
    a = ap.parse_args(argv)
    cfg, problems = load_config(a.config, a.roots)
    for p in problems:
        log(f"config: {p}")
    if not cfg["roots"] or all(not Path(os.path.expanduser(r)).is_dir() for r in cfg["roots"]):
        return 2
    results = scan(cfg, dry_run=a.dry_run)
    if a.dry_run:
        print(f"dry run: {len(results)} projects would be scanned")
        return 0
    if a.json:
        print(json.dumps(results, indent=1))
        return 0
    scanned = [e for e in results if e["kind"] in ("npm", "pnpm", "python")]
    if scanned and all(e["prod"] is None for e in scanned):
        log("every audit failed: is the network or npm registry reachable?")
        return 2
    when = dt.date.today().isoformat()
    out_root = Path(os.path.expanduser(a.out or cfg.get("out") or "~/.dep-patrol/reports"))
    out = out_root / when
    out.mkdir(parents=True, exist_ok=True)
    tools = {"dep-patrol": VERSION, "npm": tool_version(["npm", "--version"]), "pnpm": tool_version(["pnpm", "--version"]),
             "osv-scanner": tool_version(["osv-scanner", "--version"]), "OSV API": "api.osv.dev (cached "
             f"{cfg.get('osv_cache_days', 7)} days in {CACHE_DIR})", "commands": "npm audit --json + npm ls --omit=dev; "
             "pnpm audit --json --prod; OSV querybatch; osv-scanner scan source -r"}
    prev = previous_report(out_root, when)
    md = render(results, when, cfg["urgency"], prev if prev[0] else None, tools)
    (out / "report.md").write_text(md)
    (out / "report.json").write_text(json.dumps(results, indent=1))
    (out / "report.sarif").write_text(json.dumps(sarif(results), indent=1))
    (out / "run.log").write_text("\n".join(LOG_LINES) + "\n")
    urg = [e for e in results if urgent(e, cfg["urgency"])]
    summary = f"dep-patrol {when}: {len(results)} projects, {len(urg)} need action"
    if urg:
        summary += ": " + ", ".join(f"{e['name']}{' (live)' if e['exposed'] else ''}" for e in urg[:12])
    print(summary)
    print(f"report: {out / 'report.md'}")
    if a.notify and urg and cfg.get("notify"):
        env = dict(os.environ, DEP_PATROL_SUMMARY=summary, DEP_PATROL_REPORT=str(out / "report.md"))
        subprocess.run(os.path.expandvars(cfg["notify"]), shell=True, env=env, timeout=60)
    return 1 if urg else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
