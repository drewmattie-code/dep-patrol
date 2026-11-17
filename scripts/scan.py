#!/usr/bin/env python3
"""dep-patrol: find every repo under some folders, audit its dependencies, rank what matters.

Zero installs beyond what a dev machine already has:
  * npm projects (package-lock.json) use `npm audit --json`, production deps first.
  * pnpm projects use `pnpm audit --json --prod` when pnpm is installed.
  * Python projects (requirements*.txt with pinned ==versions, poetry.lock, uv.lock) are checked
    against the free OSV.dev API.
Anything else found (Cargo.lock, go.sum, yarn.lock without npm lock, ...) is listed as unscanned,
so a gap is visible instead of silent.

usage:
  scan.py --config dep-patrol.json            # scan, write report.md + report.json, print summary
  scan.py --roots ~/Projects ~/code           # ad hoc, no config
  scan.py --config dep-patrol.json --notify   # also run the config's notify command if anything is urgent

Exit code: 0 nothing critical/high in production deps, 1 something to fix, 2 scanner error.
"""
import argparse, datetime as dt, fnmatch, json, os, re, shutil, subprocess, sys, urllib.request
from pathlib import Path

SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "out", ".venv", "venv", "env", "__pycache__",
             ".turbo", ".open-next", ".wrangler", ".cache", "coverage", "vendor", "target", ".worktrees", "worktrees"}
SEV_ORDER = {"critical": 4, "high": 3, "moderate": 2, "medium": 2, "low": 1, "info": 0, "unknown": 0}


def log(*a):
    print(*a, file=sys.stderr, flush=True)


# ------------------------------------------------------------------ discovery
def discover(roots, max_depth, excludes):
    """Yield (project_dir, kind) for every lockfile/manifest, newest-first unimportant."""
    found = {}
    for root in roots:
        root = Path(os.path.expanduser(root)).resolve()
        if not root.is_dir():
            log(f"[skip] {root} is not a folder")
            continue
        base_depth = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            p = Path(dirpath)
            depth = len(p.parts) - base_depth
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".") and depth < max_depth]
            if any(fnmatch.fnmatch(str(p), pat) or fnmatch.fnmatch(p.name, pat) for pat in excludes):
                dirnames[:] = []
                continue
            fs = set(filenames)
            kind = None
            if "package-lock.json" in fs:
                kind = "npm"
            elif "pnpm-lock.yaml" in fs:
                kind = "pnpm"
            elif "yarn.lock" in fs or "bun.lockb" in fs or "bun.lock" in fs:
                kind = "js-other"
            elif {"poetry.lock", "uv.lock"} & fs or any(re.match(r"requirements.*\.txt$", f) for f in fs):
                kind = "python"
            elif "Cargo.lock" in fs:
                kind = "rust"
            elif "go.sum" in fs:
                kind = "go"
            if kind:
                rel = os.path.relpath(p, root.parent)
                found[str(p)] = (kind, rel)
    return sorted((k, v[0], v[1]) for k, v in found.items())


# ------------------------------------------------------------------ npm / pnpm
def run_json(cmd, cwd, timeout=300):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return None, str(e)
    try:
        return json.loads(r.stdout or "{}"), None
    except json.JSONDecodeError:
        return None, (r.stderr or r.stdout)[-400:]


def npm_findings(proj, prod_only):
    cmd = ["npm", "audit", "--json"] + (["--omit=dev"] if prod_only else [])
    data, err = run_json(cmd, proj)
    if data is None:
        return None, err
    if "error" in data and "vulnerabilities" not in data:
        return None, json.dumps(data["error"])[:400]
    out = []
    for name, v in (data.get("vulnerabilities") or {}).items():
        advisories = [x for x in v.get("via", []) if isinstance(x, dict)]
        fix = v.get("fixAvailable")
        if isinstance(fix, dict):
            fix_s = f"{fix.get('name')}@{fix.get('version')}" + (" (major)" if fix.get("isSemVerMajor") else "")
        else:
            fix_s = "yes" if fix else "none"
        titles = sorted({a.get("title", "") for a in advisories})[:6]
        urls = sorted({a.get("url", "") for a in advisories if a.get("url")})[:6]
        out.append({
            "package": name, "severity": v.get("severity", "unknown"), "direct": bool(v.get("isDirect")),
            "range": v.get("range", ""), "fix": fix_s, "titles": titles, "urls": urls,
            "via": [x for x in v.get("via", []) if isinstance(x, str)][:4],
        })
    return out, None


def pnpm_findings(proj, prod_only):
    if not shutil.which("pnpm"):
        return None, "pnpm not installed"
    data, err = run_json(["pnpm", "audit", "--json"] + (["--prod"] if prod_only else []), proj)
    if data is None:
        return None, err
    out = []
    for adv in (data.get("advisories") or {}).values():
        out.append({"package": adv.get("module_name"), "severity": adv.get("severity", "unknown"), "direct": False,
                    "range": adv.get("vulnerable_versions", ""), "fix": adv.get("patched_versions", "?"),
                    "titles": [adv.get("title", "")], "urls": [adv.get("url", "")], "via": []})
    return out, None


# ------------------------------------------------------------------ python via OSV.dev
def python_pins(proj):
    pins = {}
    p = Path(proj)
    for f in p.glob("requirements*.txt"):
        for line in f.read_text(errors="ignore").splitlines():
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+!]+)", line)
            if m:
                pins[m.group(1).lower()] = m.group(3)
    for lock in ("poetry.lock", "uv.lock"):
        f = p / lock
        if f.exists():
            name = None
            for line in f.read_text(errors="ignore").splitlines():
                m = re.match(r'^name\s*=\s*"([^"]+)"', line)
                if m:
                    name = m.group(1).lower()
                    continue
                m = re.match(r'^version\s*=\s*"([^"]+)"', line)
                if m and name:
                    pins[name] = m.group(1)
                    name = None
    return pins


def osv_post(url, payload):
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def osv_severity(vuln):
    sev = (vuln.get("database_specific") or {}).get("severity")
    if sev:
        return sev.lower()
    for a in vuln.get("affected", []):
        s = (a.get("database_specific") or {}).get("severity")
        if s:
            return s.lower()
    return "unknown"


def python_findings(proj):
    pins = python_pins(proj)
    if not pins:
        return [], "no pinned versions (unpinned requirements cannot be checked)"
    names = sorted(pins)
    queries = [{"package": {"name": n, "ecosystem": "PyPI"}, "version": pins[n]} for n in names]
    try:
        res = osv_post("https://api.osv.dev/v1/querybatch", {"queries": queries})
    except Exception as e:
        return None, f"OSV query failed: {e}"
    out = []
    for n, r in zip(names, res.get("results", [])):
        ids = [v["id"] for v in r.get("vulns", [])]
        if not ids:
            continue
        sevs, titles, urls, fixes = [], [], [], set()
        for vid in ids[:8]:
            try:
                with urllib.request.urlopen(f"https://api.osv.dev/v1/vulns/{vid}", timeout=30) as resp:
                    v = json.load(resp)
            except Exception:
                continue
            sevs.append(osv_severity(v))
            titles.append((v.get("summary") or vid)[:140])
            urls.append(f"https://osv.dev/vulnerability/{vid}")
            for a in v.get("affected", []):
                for rg in a.get("ranges", []):
                    for ev in rg.get("events", []):
                        if "fixed" in ev:
                            fixes.add(ev["fixed"])
        worst = max(sevs or ["unknown"], key=lambda s: SEV_ORDER.get(s, 0))
        out.append({"package": n, "severity": worst, "direct": True, "range": f"=={pins[n]}",
                    "fix": ", ".join(sorted(fixes)[:3]) or "?", "titles": titles[:6], "urls": urls[:6], "via": []})
    return out, None


# ------------------------------------------------------------------ git + exposure context
def git_info(proj):
    def g(*args):
        try:
            return subprocess.run(["git", *args], cwd=proj, capture_output=True, text=True, timeout=20).stdout.strip()
        except Exception:
            return ""
    return {"branch": g("rev-parse", "--abbrev-ref", "HEAD"), "commit": g("log", "-1", "--format=%h %cs"),
            "dirty": bool(g("status", "--porcelain"))}


def is_exposed(proj, exposed_patterns):
    """A pattern matches the folder name, a path suffix (repo/web) or the full path."""
    name = Path(proj).name
    return any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(proj, p) or proj.endswith("/" + p.strip("/"))
               for p in exposed_patterns)


# ------------------------------------------------------------------ report
def scan(cfg):
    projects = discover(cfg["roots"], cfg.get("max_depth", 3), cfg.get("exclude", []))
    log(f"found {len(projects)} projects")
    results = []
    for proj, kind, rel in projects:
        log(f"  {kind:8s} {proj}")
        entry = {"path": proj, "name": rel, "kind": kind, "exposed": is_exposed(proj, cfg.get("exposed", [])),
                 "git": git_info(proj), "prod": [], "dev_counts": {}, "error": None}
        if kind == "npm":
            entry["prod"], entry["error"] = npm_findings(proj, prod_only=True)
            alln, _ = npm_findings(proj, prod_only=False)
            if alln is not None and entry["prod"] is not None:
                prodnames = {f["package"] for f in entry["prod"]}
                for f in alln:
                    if f["package"] not in prodnames:
                        entry["dev_counts"][f["severity"]] = entry["dev_counts"].get(f["severity"], 0) + 1
        elif kind == "pnpm":
            entry["prod"], entry["error"] = pnpm_findings(proj, prod_only=True)
        elif kind == "python":
            entry["prod"], entry["error"] = python_findings(proj)
        else:
            entry["prod"], entry["error"] = None, f"{kind}: not scanned by dep-patrol (install osv-scanner to cover it)"
        results.append(entry)
    return results


def worst(entry):
    return max([SEV_ORDER.get(f["severity"], 0) for f in (entry["prod"] or [])] or [0])


def urgent(entry):
    n = sum(1 for f in (entry["prod"] or []) if f["severity"] in ("critical", "high"))
    return n > 0 and (entry["exposed"] or any(f["severity"] == "critical" for f in entry["prod"] or []))


def render(results, when):
    rows = sorted(results, key=lambda e: (-int(e["exposed"]), -worst(e), e["name"]))
    lines = [f"# Dependency scan, {when}", ""]
    nurg = sum(1 for e in results if urgent(e))
    lines.append(f"{len(results)} projects scanned. **{nurg} need action** (critical anywhere, or critical/high in a live app).")
    lines += ["", "| Project | Live | Critical | High | Moderate | Branch | Note |", "|---|---|---|---|---|---|---|"]
    for e in rows:
        c = {s: sum(1 for f in (e["prod"] or []) if f["severity"] == s) for s in ("critical", "high", "moderate")}
        note = (e["error"] or "")[:60]
        if e["dev_counts"]:
            note = (note + " dev-only: " + ", ".join(f"{k} {v}" for k, v in sorted(e["dev_counts"].items()))).strip()
        lines.append(f"| {e['name']} | {'yes' if e['exposed'] else ''} | {c['critical'] or ''} | {c['high'] or ''} | "
                     f"{c['moderate'] or ''} | {e['git']['branch']}{' (dirty)' if e['git']['dirty'] else ''} | {note} |")
    for e in rows:
        bad = [f for f in (e["prod"] or []) if f["severity"] in ("critical", "high")]
        if not bad:
            continue
        lines += ["", f"## {e['name']}{' (LIVE)' if e['exposed'] else ''}", f"`{e['path']}`", ""]
        for f in sorted(bad, key=lambda f: -SEV_ORDER.get(f["severity"], 0)):
            lines.append(f"- **{f['package']}** {f['severity']}{' (direct)' if f['direct'] else ''}, affected {f['range']}, fix: {f['fix']}")
            for t, u in zip(f["titles"], f["urls"] + [""] * 10):
                lines.append(f"  - {t} {u}".rstrip())
            if f["via"]:
                lines.append(f"  - comes in through: {', '.join(f['via'])}")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config")
    ap.add_argument("--roots", nargs="*")
    ap.add_argument("--out", help="report folder (default ~/.dep-patrol/reports)")
    ap.add_argument("--notify", action="store_true")
    ap.add_argument("--json", action="store_true", help="print the raw results as JSON on stdout")
    a = ap.parse_args()
    cfg = {"roots": [], "exposed": [], "exclude": [], "max_depth": 3}
    if a.config:
        cfg.update(json.load(open(os.path.expanduser(a.config))))
    if a.roots:
        cfg["roots"] = a.roots
    if not cfg["roots"]:
        ap.error("give --roots or a config with roots")
    if not shutil.which("npm"):
        log("warning: npm not found, npm projects will error")
    results = scan(cfg)
    if a.json:
        print(json.dumps(results, indent=1))
        return 0
    when = dt.date.today().isoformat()
    out = Path(os.path.expanduser(a.out or cfg.get("out") or "~/.dep-patrol/reports")) / when
    out.mkdir(parents=True, exist_ok=True)
    md = render(results, when)
    (out / "report.md").write_text(md)
    (out / "report.json").write_text(json.dumps(results, indent=1))
    urg = [e for e in results if urgent(e)]
    summary = f"dep-patrol {when}: {len(results)} projects, {len(urg)} need action"
    if urg:
        summary += ": " + ", ".join(f"{e['name']}{' (live)' if e['exposed'] else ''}" for e in urg[:12])
    print(summary)
    print(f"report: {out / 'report.md'}")
    if a.notify and urg and cfg.get("notify"):
        env = dict(os.environ, DEP_PATROL_SUMMARY=summary, DEP_PATROL_REPORT=str(out / "report.md"))
        subprocess.run(cfg["notify"], shell=True, env=env, timeout=60)
    return 1 if urg else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(2)
