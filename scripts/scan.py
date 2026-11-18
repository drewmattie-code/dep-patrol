#!/usr/bin/env python3
"""dep-patrol: find every dependency manifest under some folders, audit each one, rank what matters.

Every manifest gets its own outcome (scanned, partial, unscanned, failed), every advisory is tracked on
its own, and a scan that did not run is never reported as clean.

Scanners, using what a dev machine already has:
  * npm (package-lock.json): `npm audit --json`; production vs dev read from the lockfile, per installed copy.
  * pnpm (pnpm-lock.yaml): `pnpm audit --json`.
  * Python (requirements*.txt, poetry.lock, uv.lock): the OSV.dev API, with a local cache.
  * Yarn, Bun, Cargo, Go: `osv-scanner` when it is on PATH; otherwise listed as not scanned, with the command.

usage:
  scan.py --config dep-patrol.json             # scan every root, write the report, print a summary
  scan.py --roots ~/Projects ~/code            # ad hoc, no config
  scan.py --repo .                             # one repository (CI): every project in it counts as live
  scan.py --config dep-patrol.json --notify    # also run the config's notify command when something needs you
  scan.py --config dep-patrol.json --dry-run   # list what would be scanned, no network
  scan.py --repo . --verify-fixed GHSA-xxxx    # after a bump: prove that advisory is gone

Exit code: 0 every manifest scanned and nothing urgent, 1 something to fix,
           2 the scan is incomplete (a manifest failed, a root is missing; with --strict also anything not scanned).
"""
import argparse, datetime as dt, fnmatch, hashlib, io, json, math, os, re, shutil, subprocess, sys, tarfile, tempfile, time
import urllib.error, urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

VERSION = "3.0.0"
SCHEMA = 3
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "out", ".venv", "venv", "env", "__pycache__",
             ".turbo", ".open-next", ".wrangler", ".cache", "coverage", "vendor", "target", ".worktrees", "worktrees"}
# an unrated advisory sorts above "low": it could be anything
SEV_ORDER = {"critical": 6, "high": 5, "moderate": 4, "unknown": 3, "low": 2, "info": 1}
# JS lockfiles in the order npm itself prefers them; one per folder is scanned
JS_LOCKS = {"npm-shrinkwrap.json": "npm", "package-lock.json": "npm", "pnpm-lock.yaml": "pnpm", "yarn.lock": "yarn",
            "bun.lock": "bun", "bun.lockb": "bun"}
OTHER_LOCKS = {"poetry.lock": "python", "uv.lock": "python", "Cargo.lock": "rust", "go.mod": "go"}
DEV_WORDS = {"dev", "develop", "development", "test", "tests", "testing", "lint", "docs", "doc", "ci", "typing",
             "bench", "benchmark", "benchmarks", "build", "tools", "tooling", "style", "qa", "check", "format"}
PROD_WORDS = {"prod", "production", "base", "main", "app", "server", "deploy", "runtime", "core"}
CACHE_DIR = Path(os.path.expanduser("~/.dep-patrol/cache/osv"))
DEFAULT_OUT = "~/.dep-patrol/reports"
OSV_API = "https://api.osv.dev/v1"
LOG_LINES = []


def log(msg):
    line = f"{dt.datetime.now().strftime('%H:%M:%S')} {msg}"
    LOG_LINES.append(line)
    print(line, file=sys.stderr, flush=True)


# ------------------------------------------------------------------ discovery
def _manifest(file, ecosystem, status="pending", detail=None):
    return {"file": file, "ecosystem": ecosystem, "status": status, "detail": detail}


def _package_json(folder):
    try:
        data = json.loads((Path(folder) / "package.json").read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def manifests_in(folder, filenames):
    """Every dependency manifest in one folder. Of several JS lockfiles only one is scanned; the rest are recorded."""
    fs = set(filenames)
    out = []
    js = [f for f in JS_LOCKS if f in fs]
    if js:
        chosen = js[0]
        if len(js) > 1:
            manager = str(_package_json(folder).get("packageManager") or "").split("@")[0]
            chosen = next((f for f in js if JS_LOCKS[f] == manager), chosen)
        for f in js:
            if f == chosen:
                out.append(_manifest(f, JS_LOCKS[f]))
            else:
                out.append(_manifest(f, JS_LOCKS[f], "skipped", f"extra lockfile: {chosen} is the one scanned "
                                     "(set packageManager in package.json to change that)"))
    for f in fs:
        if f in OTHER_LOCKS:
            out.append(_manifest(f, OTHER_LOCKS[f]))
        elif re.match(r"^requirements.*\.txt$", f):
            out.append(_manifest(f, "python"))
    try:   # the requirements/base.txt, dev.txt, prod.txt layout
        out += [_manifest(f"requirements/{f}", "python") for f in os.listdir(Path(folder) / "requirements") if f.endswith(".txt")]
    except OSError:
        pass
    return sorted(out, key=lambda m: m["file"])


def workspace_globs(folder):
    """Member globs of a JS workspace root: package.json `workspaces`, or pnpm-workspace.yaml `packages`."""
    ws = _package_json(folder).get("workspaces")
    if isinstance(ws, dict):
        ws = ws.get("packages", [])
    globs = [g for g in ws if isinstance(g, str)] if isinstance(ws, list) else []
    try:
        on = False
        for line in (Path(folder) / "pnpm-workspace.yaml").read_text().splitlines():
            if re.match(r"^packages\s*:", line):
                on = True
                globs += re.findall(r"['\"]([^'\"]+)['\"]", line.split(":", 1)[1])
            elif on and re.match(r"^\s+-\s", line):
                globs.append(line.split("-", 1)[1].split(" #")[0].strip().strip("'\""))
            elif on and line.strip() and not line[:1].isspace() and not line.startswith("#"):
                on = False
    except OSError:
        pass
    return globs


def glob_match(rel, globs):
    """Workspace glob match: `*` stays inside one path segment, `**` crosses them, `!pattern` excludes."""
    def rx(g):
        g = g.strip().lstrip("!").removeprefix("./").rstrip("/")
        parts = re.split(r"(\*\*/?|\*|\?)", g)
        return "^" + "".join(".*" if p.startswith("**") else "[^/]*" if p == "*" else "[^/]" if p == "?"
                             else re.escape(p) for p in parts) + "$"
    yes = any(re.match(rx(g), rel) for g in globs if not g.strip().startswith("!"))
    return yes and not any(re.match(rx(g), rel) for g in globs if g.strip().startswith("!"))


def discover(roots, max_depth, excludes, includes=()):
    """Return one project per folder that holds a manifest: {path, name, manifests}. name is stable:
    relative to the root's parent."""
    found = {}
    for root in roots:
        root = Path(os.path.expanduser(root)).resolve()
        if not root.is_dir():
            continue
        base = len(root.parts)
        for dirpath, dirnames, filenames in os.walk(root):
            p = Path(dirpath)
            keep_going = max_depth is None or len(p.parts) - base < max_depth
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".") and keep_going]
            sp = str(p)
            if any(fnmatch.fnmatch(sp, pat) or fnmatch.fnmatch(p.name, pat) for pat in excludes):
                dirnames[:] = []
                continue
            if includes and not any(fnmatch.fnmatch(sp, pat) or fnmatch.fnmatch(p.name, pat) for pat in includes):
                continue
            ms = manifests_in(p, filenames)
            if ms:
                found[sp] = {"path": sp, "name": os.path.relpath(p, root.parent), "manifests": ms}
                if any(m["file"].startswith("requirements/") for m in ms) and "requirements" in dirnames:
                    dirnames.remove("requirements")   # already counted as part of this project
    # A JS workspace root's lockfile holds its members' dependencies. A member's own JS lockfile is recorded
    # on the root as covered; anything else in the member (a Python side, say) is still scanned.
    for wroot in sorted(found):
        if wroot not in found or not any(m["file"] in JS_LOCKS and m["status"] == "pending"
                                         for m in found[wroot]["manifests"]):
            continue
        globs = workspace_globs(wroot)
        for path in sorted(found) if globs else []:
            if path == wroot or not path.startswith(wroot + os.sep) or path not in found:
                continue
            rel = os.path.relpath(path, wroot).replace(os.sep, "/")
            if not glob_match(rel, globs):
                continue
            rest = []
            for m in found[path]["manifests"]:
                if m["file"] in JS_LOCKS:
                    found[wroot]["manifests"].append(_manifest(f"{rel}/{m['file']}", m["ecosystem"], "covered",
                                                               "workspace member: its dependencies are in the root lockfile"))
                else:
                    rest.append(m)
            if rest:
                found[path]["manifests"] = rest
            else:
                del found[path]
    return [found[k] for k in sorted(found)]


# ------------------------------------------------------------------ helpers
def run(cmd, cwd, timeout=300):
    """Run a tool. Returns (exit code, stdout, stderr); the exit code is None when it could not run at all."""
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return None, "", f"{cmd[0]} timed out after {timeout}s"
    except OSError as e:
        return None, "", str(e)


def _json(text):
    try:
        return json.loads(text) if text and text.strip() else None
    except (json.JSONDecodeError, TypeError):
        return None


def _tail(*texts, n=240):
    for t in texts:
        t = " ".join((t or "").split())
        if t:
            return t[-n:]
    return ""


def tool_version(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip().splitlines()[0]
    except Exception:
        return None


def outcome(status, detail=None, findings=None, packages=None):
    """What happened to one manifest. status: scanned | partial | unscanned | failed."""
    return {"status": status, "detail": detail, "findings": findings or [], "packages": packages}


def _norm(name):
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def _loose_key(version):
    return tuple(int(x) for x in re.findall(r"\d+", str(version).split("+")[0]))


def advisory_url(aid):
    return f"https://github.com/advisories/{aid}" if aid.startswith("GHSA-") else f"https://osv.dev/vulnerability/{aid}"


def new_finding(aid, package, ecosystem, manifest, severity, scope, direct, versions, rng, fix, title, url,
                aliases=(), via=(), score=None, source=None):
    """One advisory against one package in one manifest."""
    sev = {"medium": "moderate"}.get(str(severity or "").lower(), str(severity or "").lower())
    return {"id": aid, "aliases": sorted({str(a) for a in aliases if a and str(a) != aid}), "package": package,
            "ecosystem": ecosystem, "manifest": manifest, "versions": sorted({str(v) for v in versions if v}, key=_loose_key),
            "severity": sev if sev in SEV_ORDER else "unknown", "severity_source": source, "score": score,
            "scope": scope, "direct": direct, "range": rng or "", "fix": fix or "", "title": (title or aid)[:200],
            "url": url or advisory_url(aid), "via": sorted(set(via))}


# ------------------------------------------------------------------ severity
_CVSS3 = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}, "AC": {"L": 0.77, "H": 0.44}, "UI": {"N": 0.85, "R": 0.62},
          "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
          "PR": {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}}


def cvss3_score(vector):
    """CVSS 3.0/3.1 base score from a vector string. None for anything else (CVSS 2, CVSS 4, damaged input)."""
    if not isinstance(vector, str) or not vector.startswith(("CVSS:3.0/", "CVSS:3.1/")):
        return None
    m = dict(part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        changed = {"U": False, "C": True}[m["S"]]
        iss = 1 - (1 - _CVSS3["CIA"][m["C"]]) * (1 - _CVSS3["CIA"][m["I"]]) * (1 - _CVSS3["CIA"][m["A"]])
        expl = 8.22 * _CVSS3["AV"][m["AV"]] * _CVSS3["AC"][m["AC"]] * _CVSS3["PR"][m["S"]][m["PR"]] * _CVSS3["UI"][m["UI"]]
    except KeyError:
        return None
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    base = min(1.08 * (impact + expl), 10) if changed else min(impact + expl, 10)
    i = round(base * 100000)   # the specification's Roundup: one decimal, always up, without float noise
    return i / 100000.0 if i % 10000 == 0 else (math.floor(i / 10000) + 1) / 10.0


def rating(score):
    return "critical" if score >= 9 else "high" if score >= 7 else "moderate" if score >= 4 else "low"


def osv_severity(v):
    """(severity, where it came from, score) for one OSV record. A label published by the advisory database wins;
    then a CVSS 3 vector; then a notice flag. What is left is "unknown", with the reason."""
    label = (v.get("database_specific") or {}).get("severity")
    vectors = [s.get("score") for s in v.get("severity") or [] if isinstance(s, dict)]
    notice = None
    for a in v.get("affected") or []:
        for spec in (a.get("ecosystem_specific") or {}, a.get("database_specific") or {}):
            label = label or spec.get("severity")
            vectors.append(spec.get("cvss"))
            notice = notice or spec.get("informational")
    if isinstance(label, str) and label.strip():
        label = {"medium": "moderate"}.get(label.lower(), label.lower())
        if label in SEV_ORDER:
            return label, "advisory", None
    scores = [s for s in (cvss3_score(x) for x in vectors) if s is not None]
    if scores:
        return rating(max(scores)), f"CVSS {max(scores)}", max(scores)
    if notice:
        return "info", f"notice: {notice}", None
    if any(isinstance(x, str) and x.startswith("CVSS:4") for x in vectors):
        return "unknown", "only a CVSS 4.0 vector, which is not scored here", None
    return "unknown", "no rating published", None


def _id_rank(aid):
    return 0 if aid.startswith("GHSA-") else 1 if aid.startswith(("PYSEC-", "RUSTSEC-", "GO-")) else 2


def group_advisories(vulns):
    """Fold OSV records that are copies of one advisory (GHSA + PYSEC + RUSTSEC of the same CVE) into one."""
    vulns = [v for v in vulns if v.get("id") and not v.get("withdrawn")]
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for v in vulns:
        for a in v.get("aliases") or []:
            parent[find(a)] = find(v["id"])
    groups = {}
    for v in vulns:
        groups.setdefault(find(v["id"]), []).append(v)
    out = []
    for recs in groups.values():
        recs.sort(key=lambda v: (_id_rank(v["id"]), v["id"]))
        sevs = [osv_severity(v) for v in recs]
        labelled = [s for s in sevs if s[1] == "advisory"]
        sev = labelled[0] if labelled else max(sevs, key=lambda s: (SEV_ORDER[s[0]], s[2] or 0))
        ids = {v["id"] for v in recs} | {a for v in recs for a in v.get("aliases") or []}
        aid = recs[0]["id"]
        out.append({"id": aid, "aliases": sorted(ids - {aid}), "severity": sev[0], "severity_source": sev[1],
                    "score": sev[2], "title": next((v["summary"] for v in recs if v.get("summary")), aid),
                    "url": advisory_url(aid), "records": recs})
    return sorted(out, key=lambda g: g["id"])


def _osv_fix(records, name, ecosystem, installed):
    """The lowest fixed version above what is installed, for this package in this ecosystem."""
    fixed = set()
    for v in records:
        for a in v.get("affected") or []:
            pk = a.get("package") or {}
            if pk.get("ecosystem") != ecosystem or _norm(pk.get("name", "")) != _norm(name):
                continue
            for rg in a.get("ranges") or []:
                if rg.get("type") != "GIT":
                    fixed.update(ev["fixed"] for ev in rg.get("events") or [] if ev.get("fixed"))
    if not fixed:
        return "none yet"
    later = sorted((f for f in fixed if _loose_key(f) > _loose_key(installed)), key=_loose_key)
    return later[0] if later else ", ".join(sorted(fixed, key=_loose_key)[:3])


# ------------------------------------------------------------------ semver ranges (npm advisories)
_SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")


def _semver_key(version):
    m = _SEMVER.match(str(version).strip())
    if not m:
        return None
    pre = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in m.group(4).split(".")) if m.group(4) else ()
    return int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if pre else 1, pre


def semver_satisfies(version, rng):
    """True/False for comparator ranges like '>=2.1.0 <4.1.11 || <1.0.0'. None when either side cannot be read,
    so callers can fall back to the safe answer instead of trusting a guess."""
    ver = _semver_key(version)
    if ver is None:
        return None
    rng = (rng or "").strip()
    if rng in ("", "*"):
        return True
    for alt in rng.split("||"):
        ok = True
        for comp in re.sub(r"(>=|<=|>|<|=)\s+", r"\1", alt).split():
            m = re.match(r"^(>=|<=|>|<|=)?(.+)$", comp)
            target = _semver_key(m.group(2))
            if target is None:
                return None
            op = m.group(1) or "="
            ok = ok and (ver >= target if op == ">=" else ver <= target if op == "<=" else ver > target if op == ">"
                         else ver < target if op == "<" else ver == target)
        if ok:
            return True
    return False


# ------------------------------------------------------------------ npm
def npm_parse(audit, lock, manifest):
    """One finding per advisory. Scope comes from the lockfile entry of each installed copy the advisory's
    range matches, so two versions of one package are judged separately."""
    vulns = audit.get("vulnerabilities") or {}
    pkgs = lock.get("packages") if isinstance(lock, dict) and isinstance(lock.get("packages"), dict) else None

    def direct_ancestors(name, seen):
        found = set()
        for up in (vulns.get(name) or {}).get("effects") or []:
            if up in seen:
                continue
            seen.add(up)
            found |= {up} if (vulns.get(up) or {}).get("isDirect") else (direct_ancestors(up, seen) or {up})
        return found

    out = []
    for name, e in vulns.items():
        nodes = [n for n in e.get("nodes") or [] if isinstance(n, str)]
        fx = e.get("fixAvailable")
        if isinstance(fx, dict):
            fix = f"{fx.get('name')}@{fx.get('version')}" + (" (major)" if fx.get("isSemVerMajor") else "")
        else:
            fix = "npm audit fix" if fx else "none yet"
        # npm lists one advisory once per affected release line (a 6.x range, a 7.x range): fold those together,
        # or the first line listed decides for every installed copy
        entries = {}
        for adv in e.get("via") or []:
            if not isinstance(adv, dict):
                continue   # a string here names another vulnerable package; that package carries its own advisories
            ghsa = re.search(r"GHSA(-[0-9a-z]{4}){3}", adv.get("url") or "", re.I)
            src = str(adv.get("source") or "")
            aid = "GHSA" + ghsa.group(0)[4:].lower() if ghsa else f"npm-{src}" if src else adv.get("url") or str(adv.get("title"))
            entries.setdefault((aid, adv.get("name") or name), []).append(adv)
        for (aid, package), advs in entries.items():
            ranges = [a.get("range") or "" for a in advs]
            hit = nodes
            if pkgs:
                hit = [n for n in nodes if n in pkgs
                       and any(semver_satisfies(pkgs[n].get("version", ""), r) is True for r in ranges)] or nodes
            if not pkgs or not hit or any(n not in pkgs for n in hit):
                scope = "unknown"
            else:
                scope = "dev" if all(pkgs[n].get("dev") for n in hit) else "production"   # devOptional can ship
            top = [n for n in hit if n.count("node_modules/") == 1]
            direct = bool(e.get("isDirect")) and bool(top or not hit)
            via = {n.split("node_modules/")[1].rstrip("/") for n in hit if n.count("node_modules/") > 1}
            if not direct and (top or not hit):
                via |= direct_ancestors(name, {name})
            worst = max(advs, key=lambda a: SEV_ORDER.get(str(a.get("severity")).lower(), 0))
            scores = [(a.get("cvss") or {}).get("score") for a in advs]
            out.append(new_finding(aid, package, "npm", manifest, worst.get("severity"), scope, direct,
                                   [pkgs[n].get("version") for n in hit] if pkgs else [], " || ".join(r for r in ranges if r),
                                   fix, worst.get("title"), worst.get("url"), aliases=[a.get("source") for a in advs],
                                   via=via, score=max((s for s in scores if s), default=None), source="advisory"))
    return out


def npm_scan(proj, file):
    rc, out, err = run(["npm", "audit", "--json"], proj)
    data = _json(out)
    if isinstance(data, dict) and isinstance(data.get("error"), dict) and "vulnerabilities" not in data:
        e = data["error"]
        return outcome("failed", f"npm audit: {e.get('code', '')} {e.get('summary') or e.get('message') or ''}".strip()[:300])
    if not (isinstance(data, dict) and isinstance(data.get("vulnerabilities"), dict) and "auditReportVersion" in data):
        return outcome("failed", "npm audit gave no usable report: " + (_tail(err, out) or f"exit {rc}"))
    try:
        lock = json.loads((Path(proj) / file).read_text())
    except Exception:
        lock = None
    has_table = isinstance(lock, dict) and isinstance(lock.get("packages"), dict)
    return outcome("scanned", None if has_table else "old lockfile format: production and dev could not be told apart",
                   npm_parse(data, lock, file), len(lock["packages"]) - 1 if has_table else None)


# ------------------------------------------------------------------ pnpm
def pnpm_parse(data, manifest):
    out = []
    for a in (data.get("advisories") or {}).values():
        found = [f for f in a.get("findings") or [] if isinstance(f, dict)]
        devs = [f.get("dev") for f in found]
        scope = "unknown" if not found or any(d is None for d in devs) else "dev" if all(devs) else "production"
        paths = [p.split(">") for f in found for p in f.get("paths") or []]
        aid = a.get("github_advisory_id") or f"npm-{a.get('id')}"
        out.append(new_finding(aid, a.get("module_name"), "npm", manifest, a.get("severity"), scope,
                               any(len(p) == 2 for p in paths) if paths else None, [f.get("version") for f in found],
                               a.get("vulnerable_versions"), a.get("patched_versions"), a.get("title"), a.get("url"),
                               aliases=[a.get("id"), *(a.get("cves") or [])], via={p[1] for p in paths if len(p) > 2},
                               source="advisory"))
    return out


def pnpm_scan(proj, file):
    if not shutil.which("pnpm"):
        if shutil.which("osv-scanner"):
            return osv_scanner_scan(proj, file)
        return outcome("unscanned", "pnpm is not installed: install it (npm i -g pnpm) or osv-scanner (brew install osv-scanner)")
    rc, out, err = run(["pnpm", "audit", "--json"], proj)
    data = _json(out)
    if isinstance(data, dict) and isinstance(data.get("error"), dict):
        return outcome("failed", f"pnpm audit: {data['error'].get('code', '')} {data['error'].get('message', '')}".strip()[:300])
    if not (isinstance(data, dict) and isinstance(data.get("advisories"), dict) and "metadata" in data):
        return outcome("failed", "pnpm audit gave no usable report: " + (_tail(err, out) or f"exit {rc}"))
    return outcome("scanned", None, pnpm_parse(data, file), (data.get("metadata") or {}).get("totalDependencies"))


# ------------------------------------------------------------------ Python: reading manifests
def _toml(path):
    if tomllib is None:
        raise RuntimeError("reading TOML lockfiles needs Python 3.11+ (or `pip install tomli`)")
    return tomllib.loads(Path(path).read_text(encoding="utf-8", errors="ignore"))


def _closure(start, edges):
    """Everything reachable from `start`. Items are (name, extras); edges(name, extras) yields more items."""
    seen, todo = set(), list(start)
    while todo:
        item = todo.pop()
        if item not in seen:
            seen.add(item)
            todo += edges(*item)
    return {name for name, _ in seen}


def _scanned_on_its_own(inc, parent):
    """Would discovery list this included file as a manifest of its own?"""
    return (inc.parent == parent.parent and bool(re.match(r"^requirements.*\.txt$", inc.name))) or (
        inc.parent.name == "requirements" and inc.suffix == ".txt")


def _read_requirements(path, seen=None):
    seen = (seen or set()) | {path.resolve()}
    words = set(re.split(r"[-_.]", path.stem.lower())) - {"requirements"}
    scope = "dev" if words & DEV_WORDS else "production" if not words or words & PROD_WORDS else "unknown"
    pkgs, unpinned, last, annotated = {}, [], None, False

    def note(body):   # pip-compile writes "# via flask" or "# via" plus one indented line per parent
        nonlocal annotated
        if body.startswith("via"):
            annotated, body = True, body[3:].strip()
            last.setdefault("via", [])
        if "via" in last and body:
            last["via"].append(body)

    for raw in path.read_text(errors="ignore").replace("\\\n", " ").splitlines():
        line, _, comment = raw.partition("#")
        if not line.strip():
            if last is not None and raw[:1].isspace():
                note(comment.strip())
            continue
        line = line.strip()
        last = None
        include = re.match(r"^(?:-r|--requirement)(?:\s+|=)(\S+)", line)
        if include:   # read it here, unless it is scanned as its own manifest; never skip it silently
            inc = path.parent / include.group(1)
            if not inc.is_file():
                unpinned.append(f"-r {include.group(1)} (file not found)")
            elif inc.resolve() not in seen and not _scanned_on_its_own(inc, path):
                more, info = _read_requirements(inc, seen)
                for p in more:
                    pkgs.setdefault(p["name"], dict(p, scope=scope))
                unpinned += [u for u in info["unpinned"] if u not in unpinned]
            continue
        if line.startswith(("-", "git+", "http:", "https:")):
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*==\s*([A-Za-z0-9._+!-]+)(\*?)", line)
        if m and not m.group(4):
            last = pkgs[_norm(m.group(1))] = {"name": _norm(m.group(1)), "version": m.group(3), "scope": scope, "direct": None}
            if comment.strip():
                note(comment.strip())
        else:
            n = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
            if n and _norm(n.group(1)) not in unpinned:
                unpinned.append(_norm(n.group(1)))
    for p in pkgs.values():
        via = p.pop("via", None)
        if annotated and via:   # direct = asked for by a requirements file or the project itself
            p["direct"] = any(v.startswith(("-r ", "-c ")) or re.search(r"\((pyproject\.toml|setup\.(py|cfg))\)", v) for v in via)
    return list(pkgs.values()), {"unpinned": [u for u in unpinned if u not in pkgs], "skipped": []}


def _read_uv(path):
    packages = [p for p in _toml(path).get("package") or [] if p.get("name") and p.get("version")]
    entries = {}
    for p in packages:
        entries.setdefault(_norm(p["name"]), []).append(p)

    def deps(items):
        return [(_norm(d["name"]), tuple(d.get("extra") or ())) for d in items or [] if d.get("name")]

    def edges(name, extras):
        out = []
        for p in entries.get(name, []):
            out += deps(p.get("dependencies"))
            for ex in extras:
                out += deps((p.get("optional-dependencies") or {}).get(ex))
        return out
    roots = [p for p in packages if {"editable", "virtual", "directory"} & set(p.get("source") or {})]
    prod, dev = [], []
    for r in roots:
        prod += deps(r.get("dependencies"))
        for extra, items in (r.get("optional-dependencies") or {}).items():   # an extra can ship, unless it is tooling
            (dev if _norm(extra) in DEV_WORDS else prod).extend(deps(items))
        for items in (r.get("dev-dependencies") or {}).values():
            dev += deps(items)
    in_prod, in_dev, direct = _closure(prod, edges), _closure(dev, edges), {n for n, _ in prod + dev}
    out, skipped = [], []
    for p in packages:
        name = _norm(p["name"])
        if "registry" not in (p.get("source") or {}):
            skipped.append(name)   # the project itself, git and path sources: not PyPI packages
            continue
        out.append({"name": name, "version": p["version"], "direct": name in direct if roots else None,
                    "scope": "production" if name in in_prod else "dev" if name in in_dev else "unknown"})
    return out, {"unpinned": [], "skipped": sorted(skipped)}


def _pyproject_direct(folder):
    """(production names, dev names) a pyproject.toml asks for directly, or (None, None) when it cannot be read."""
    try:
        data = _toml(Path(folder) / "pyproject.toml")
    except Exception:
        return None, None

    def req_names(items):
        return {_norm(m.group(1)) for m in (re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", x) for x in items or []
                                            if isinstance(x, str)) if m}
    project, poetry = data.get("project") or {}, (data.get("tool") or {}).get("poetry") or {}
    prod = req_names(project.get("dependencies")) | {_norm(k) for k in poetry.get("dependencies") or {} if k.lower() != "python"}
    dev = {_norm(k) for k in poetry.get("dev-dependencies") or {}}
    for extra, items in (project.get("optional-dependencies") or {}).items():
        (dev if _norm(extra) in DEV_WORDS else prod).update(req_names(items))
    for group in (poetry.get("group") or {}).values():
        dev |= {_norm(k) for k in (group or {}).get("dependencies") or {}}
    for items in (data.get("dependency-groups") or {}).values():
        dev |= req_names(items)
    return prod, dev


def _read_poetry(path):
    packages = [p for p in _toml(path).get("package") or [] if p.get("name") and p.get("version")]
    graph = {_norm(p["name"]): [(_norm(d), ()) for d in p.get("dependencies") or {}] for p in packages}
    prod, dev = _pyproject_direct(path.parent)
    known = prod is not None
    in_prod = _closure([(n, ()) for n in prod], lambda n, _: graph.get(n, [])) if known else set()
    in_dev = _closure([(n, ()) for n in dev], lambda n, _: graph.get(n, [])) if known else set()
    out, skipped = [], []
    for p in packages:
        name = _norm(p["name"])
        if (p.get("source") or {}).get("type") in ("git", "directory", "file", "url"):
            skipped.append(name)
            continue
        groups = p.get("groups") or ([p["category"]] if p.get("category") else None)   # Poetry 2, Poetry < 1.5
        if groups:
            scope = "production" if "main" in groups else "dev"
        else:
            scope = "production" if name in in_prod else "dev" if name in in_dev else "unknown"
        out.append({"name": name, "version": p["version"], "scope": scope,
                    "direct": name in prod | dev if known else None})
    return out, {"unpinned": [], "skipped": sorted(skipped)}


def python_packages(proj, file):
    """([{name, version, scope, direct}], {unpinned, skipped}) for one Python manifest."""
    path = Path(proj) / file
    reader = _read_uv if path.name == "uv.lock" else _read_poetry if path.name == "poetry.lock" else _read_requirements
    pkgs, info = reader(path)
    return sorted(pkgs, key=lambda p: (p["name"], _loose_key(p["version"]))), info


# ------------------------------------------------------------------ Python: OSV API with cache + backoff
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
    v = http_json(f"{OSV_API}/vulns/{vid}")
    f.write_text(json.dumps(v))
    return v


def python_scan(proj, file, cache_days=7):
    try:
        pkgs, info = python_packages(proj, file)
    except RuntimeError as e:   # no TOML reader on this Python
        return osv_scanner_scan(proj, file) if shutil.which("osv-scanner") else outcome("unscanned", str(e))
    except Exception as e:
        return outcome("failed", f"could not read {file}: {e}")
    notes = []
    if info["unpinned"]:
        notes.append(f"{_n(len(info['unpinned']), 'loose requirement')} not checked ({', '.join(info['unpinned'][:6])})")
    if info["skipped"]:
        notes.append(f"{len(info['skipped'])} not from a package index ({', '.join(info['skipped'][:4])})")
    if not pkgs:
        return outcome("unscanned", "; ".join(["nothing pinned to an exact version"] + notes), packages=0)
    results = []
    try:
        for i in range(0, len(pkgs), 500):
            chunk = pkgs[i:i + 500]
            res = http_json(f"{OSV_API}/querybatch", {"queries": [
                {"package": {"name": p["name"], "ecosystem": "PyPI"}, "version": p["version"]} for p in chunk]})
            got = res.get("results") if isinstance(res, dict) else None
            if not isinstance(got, list) or len(got) != len(chunk):
                return outcome("failed", f"OSV answered for {len(got) if isinstance(got, list) else 0} of {len(chunk)} "
                                         f"packages: {_tail(json.dumps(res), n=120)}")
            results += [r if isinstance(r, dict) else {} for r in got]
        # a package with very many advisories comes back in pages: follow them, or the tail is silently lost
        paged = [(i, r["next_page_token"]) for i, r in enumerate(results) if r.get("next_page_token")]
        for _ in range(25):
            if not paged:
                break
            res = http_json(f"{OSV_API}/querybatch", {"queries": [
                {"package": {"name": pkgs[i]["name"], "ecosystem": "PyPI"}, "version": pkgs[i]["version"], "page_token": tok}
                for i, tok in paged]})
            got = res.get("results") if isinstance(res, dict) else None
            if not isinstance(got, list) or len(got) != len(paged):
                return outcome("failed", "OSV gave an unusable answer while paging: " + _tail(json.dumps(res), n=120))
            nxt = []
            for (i, _tok), r in zip(paged, got):
                r = r if isinstance(r, dict) else {}
                results[i].setdefault("vulns", []).extend(r.get("vulns") or [])
                if r.get("next_page_token"):
                    nxt.append((i, r["next_page_token"]))
            paged = nxt
        if paged:
            return outcome("failed", "OSV kept paging without end")
    except Exception as e:
        return outcome("failed", f"OSV unreachable: {e}")
    hits = [[v["id"] for v in res.get("vulns") or [] if v.get("id")] for res in results]

    def detail(vid):
        try:
            return osv_vuln(vid, cache_days)
        except Exception:
            return None   # keep the advisory, with unknown severity, rather than drop it
    wanted = sorted({vid for ids in hits for vid in ids})
    with ThreadPoolExecutor(max_workers=8) as pool:
        details = dict(zip(wanted, pool.map(detail, wanted)))
    missing = sum(1 for v in details.values() if v is None)
    findings = []
    for p, ids in zip(pkgs, hits):
        for g in group_advisories([details[vid] or {"id": vid} for vid in ids]):
            findings.append(new_finding(g["id"], p["name"], "PyPI", file, g["severity"], p["scope"], p["direct"],
                                        [p["version"]], "", _osv_fix(g["records"], p["name"], "PyPI", p["version"]),
                                        g["title"], g["url"], aliases=g["aliases"], score=g["score"],
                                        source=g["severity_source"]))
    if missing:
        notes.append(f"details unavailable for {missing} advisories, shown as unknown severity")
    return outcome("partial" if info["unpinned"] else "scanned", "; ".join(notes) or None, findings, len(pkgs))


# ------------------------------------------------------------------ osv-scanner (Yarn, Bun, Cargo, Go)
def osv_scanner_parse(data, manifest):
    out = []
    for res in data.get("results") or []:
        for pk in res.get("packages") or []:
            info = pk.get("package") or {}
            vulns = {v["id"]: v for v in pk.get("vulnerabilities") or [] if v.get("id")}
            dep_groups = {_norm(g) for g in pk.get("dep_groups") or []}
            scope = "dev" if dep_groups and dep_groups <= DEV_WORDS else "unknown"   # most lockfiles do not say
            for g in pk.get("groups") or [{"ids": [i]} for i in vulns]:
                recs = sorted((vulns[i] for i in g.get("ids") or [] if i in vulns), key=lambda v: (_id_rank(v["id"]), v["id"]))
                if not recs:
                    continue
                sevs = [osv_severity(v) for v in recs]
                labelled = [s for s in sevs if s[1] == "advisory"]
                try:
                    top = float(g.get("max_severity") or "")
                except ValueError:
                    top = None
                if labelled:
                    sev = labelled[0]
                elif top is not None:
                    sev = (rating(top), f"CVSS {top}", top)
                else:
                    sev = max(sevs, key=lambda s: (SEV_ORDER[s[0]], s[2] or 0))
                aid = recs[0]["id"]
                ids = set(g.get("ids") or []) | set(g.get("aliases") or []) | {a for v in recs for a in v.get("aliases") or []}
                out.append(new_finding(aid, info.get("name"), info.get("ecosystem"), manifest, sev[0], scope, None,
                                       [info.get("version")], "",
                                       _osv_fix(recs, info.get("name"), info.get("ecosystem"), info.get("version")),
                                       next((v["summary"] for v in recs if v.get("summary")), aid), advisory_url(aid),
                                       aliases=ids, score=sev[2], source=sev[1]))
    return out


def osv_scanner_scan(proj, file):
    path = Path(proj) / file
    if not shutil.which("osv-scanner"):
        return outcome("unscanned", f"needs osv-scanner (brew install osv-scanner), then: osv-scanner scan source -L {path}")
    if path.name == "bun.lockb":
        return outcome("unscanned", "binary bun.lockb cannot be read: write a text lockfile with `bun install --save-text-lockfile`")
    rc, out, err = run(["osv-scanner", "scan", "source", "--format", "json", "--verbosity", "error", "-L", str(path)],
                       proj, timeout=600)
    data = _json(out)
    if rc not in (0, 1) or not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return outcome("failed", "osv-scanner: " + (_tail(err, out) or f"exit {rc}"))
    return outcome("scanned", None, osv_scanner_parse(data, file))


# ------------------------------------------------------------------ config
CONFIG_KEYS = {"roots", "include", "exclude", "exposed", "max_depth", "notify", "out", "urgency", "ignore",
               "osv_cache_days", "deployed", "_notes"}
# unknown_on_exposed is off by default: Rust and Go advisories are often published with no rating at all,
# so turning it on means a live Rust or Go app always needs action. Unrated advisories are always listed.
DEFAULT_URGENCY = {"critical_always": True, "high_on_exposed": True, "moderate_on_exposed": False,
                   "unknown_on_exposed": False}


def today():
    return dt.date.today().isoformat()


def _n(count, word):
    return f"{count} {word}{'' if count == 1 else 's'}"


def load_config(path, roots_override):
    """(config, problems, warnings). A problem means the scan cannot be trusted as complete; a warning is a nudge."""
    cfg = {"roots": [], "include": [], "exclude": [], "exposed": [], "max_depth": 3, "ignore": [], "deployed": {},
           "urgency": dict(DEFAULT_URGENCY), "osv_cache_days": 7}
    problems, warnings = [], []
    if path:
        try:
            with open(os.path.expanduser(path)) as fh:
                user = json.load(fh)
            if not isinstance(user, dict):
                raise ValueError("the config must be a JSON object")
        except (OSError, ValueError) as e:
            return cfg, [f"config {path}: {e}"], warnings
        if set(user) - CONFIG_KEYS:
            warnings.append(f"unknown config keys: {', '.join(sorted(set(user) - CONFIG_KEYS))}")
        urg = user.pop("urgency", None) or {}
        if set(urg) - set(DEFAULT_URGENCY):
            warnings.append(f"unknown urgency rules: {', '.join(sorted(set(urg) - set(DEFAULT_URGENCY)))}")
        cfg.update(user)
        cfg["urgency"].update(urg)
    if roots_override:
        cfg["roots"] = roots_override
    if not cfg["roots"]:
        problems.append("no roots: give --roots or --repo, or set roots in the config")
    missing = [r for r in cfg["roots"] if not Path(os.path.expanduser(r)).is_dir()]
    if missing:
        problems.append(f"roots not found: {', '.join(missing)}")
    if cfg.get("notify") and not isinstance(cfg["notify"], str):
        problems.append("notify must be a shell command string")
    good = []
    for ig in cfg["ignore"] or []:
        if isinstance(ig, dict) and ig.get("reason") and (ig.get("advisory") or ig.get("package") or ig.get("match")):
            good.append(ig)
        else:
            problems.append(f"ignore rules need a reason and an advisory, package or match: {json.dumps(ig)}")
    cfg["ignore"] = good
    return cfg, problems, warnings


# ------------------------------------------------------------------ context
def git_info(proj):
    def g(*args):
        rc, out, _ = run(["git", *args], proj, timeout=20)
        return out.strip() if rc == 0 else ""
    head = g("log", "-1", "--format=%h %cs").split()
    return {"branch": g("rev-parse", "--abbrev-ref", "HEAD"), "commit": head[0] if head else "",
            "date": head[1] if len(head) > 1 else "", "dirty": bool(g("status", "--porcelain")),
            "root": g("rev-parse", "--show-toplevel") or None}


def is_exposed(proj, name, patterns):
    """A pattern with a slash matches a path suffix ('repo/web'); a glob matches the folder name;
    a plain word must equal the folder name or the whole project name."""
    folder = Path(proj).name
    for p in patterns:
        p = p.strip().rstrip("/")
        if "/" in p:
            if proj.endswith("/" + p.lstrip("/")) or proj == os.path.expanduser(p) or name == p or name.endswith("/" + p):
                return True
        elif any(ch in p for ch in "*?["):
            if fnmatch.fnmatch(folder, p):
                return True
        elif folder == p or name == p:
            return True
    return False


# ------------------------------------------------------------------ scan
def merge_findings(findings):
    """One finding per advisory per package per manifest, however many installed copies carry it."""
    rank = {"production": 2, "unknown": 1, "dev": 0}
    out = {}
    for f in findings:
        key = (f["manifest"], f["package"], f["id"])
        g = out.get(key)
        if g is None:
            out[key] = f
            continue
        g["versions"] = sorted(set(g["versions"]) | set(f["versions"]), key=_loose_key)
        g["scope"] = max(g["scope"], f["scope"], key=lambda s: rank.get(s, 1))
        g["direct"] = True if True in (g["direct"], f["direct"]) else None if None in (g["direct"], f["direct"]) else False
        g["via"] = sorted(set(g["via"]) | set(f["via"]))
        g["aliases"] = sorted(set(g["aliases"]) | set(f["aliases"]))
    return list(out.values())


def scan_folder(path, manifests, cfg):
    """Scan every pending manifest of one folder in place; return its findings."""
    findings = []
    for m in manifests:
        if m["status"] != "pending":
            continue
        t0 = time.time()
        try:
            eco = m["ecosystem"]
            r = (npm_scan(path, m["file"]) if eco == "npm" else pnpm_scan(path, m["file"]) if eco == "pnpm"
                 else python_scan(path, m["file"], cfg.get("osv_cache_days", 7)) if eco == "python"
                 else osv_scanner_scan(path, m["file"]))
        except Exception as e:   # a bug in a scanner must not read as a clean manifest
            r = outcome("failed", f"scanner error: {type(e).__name__}: {e}")
        m.update(status=r["status"], detail=r["detail"], packages=r["packages"], seconds=round(time.time() - t0, 1))
        findings += r["findings"]
    return merge_findings(findings)


def scan(cfg, dry_run=False, exposed_only=False, all_exposed=False, problems=None):
    """Discover and scan. With a `problems` list, `exposed` and `deployed` entries that match no project are
    added to it: a live app whose folder moved would otherwise just stop being treated as live."""
    projects = discover(cfg["roots"], cfg.get("max_depth", 3), cfg.get("exclude", []), cfg.get("include", []))
    log(f"found {_n(len(projects), 'project')}")
    for key in ("exposed", "deployed") if problems is not None else ():
        for pattern in cfg.get(key) or []:
            if not any(is_exposed(p["path"], p["name"], [pattern]) for p in projects):
                problems.append(f"{key} entry '{pattern}' matches no project under the roots (moved, renamed or misspelt?)")
                log(f"config: {problems[-1]}")
    out = []
    for p in projects:
        p["exposed"] = all_exposed or is_exposed(p["path"], p["name"], cfg.get("exposed", []))
        if exposed_only and not p["exposed"]:
            continue
        p.update(git=git_info(p["path"]), findings=[], deployed=None)
        files = ", ".join(m["file"] for m in p["manifests"] if m["status"] == "pending")
        if dry_run:
            log(f"  would scan {p['name']}{' (live)' if p['exposed'] else ''}: {files}")
        else:
            p["findings"] = scan_folder(p["path"], p["manifests"], cfg)
            spec = deployed_spec(p, cfg.get("deployed"))
            if spec is not None:
                p["deployed"] = check_deployed(p, spec, cfg)
            bad = "; ".join(f"{m['file']} {m['status']}: {(m['detail'] or '')[:80]}" for m in p["manifests"]
                            if m["status"] in ("failed", "unscanned", "partial"))
            log(f"  {p['name']} [{files}] {round(sum(m.get('seconds', 0) for m in p['manifests']), 1)}s" + (f"  ({bad})" if bad else ""))
        out.append(p)
    return out


# ------------------------------------------------------------------ live versus merged
def deployed_spec(p, table):
    """The `deployed` config entry for this project (keys match like `exposed`), or None."""
    for key, spec in (table or {}).items():
        if is_exposed(p["path"], p["name"], [key]):
            return spec if isinstance(spec, dict) else {}
    return None


def _snapshot(root, sha, rel, tmp):
    """Write the manifests the project folder had at commit `sha` into tmp. Returns that folder, or None when the
    folder held no manifest then. Only manifests and package.json / pyproject.toml files are read, never the tree."""
    prefix = "" if rel in (".", "") else rel.replace(os.sep, "/").rstrip("/") + "/"
    rc, out, err = run(["git", "ls-tree", "-r", "--name-only", "-z", sha, "--", prefix or "."], root, timeout=60)
    if rc != 0:
        raise RuntimeError(_tail(err) or "git ls-tree failed")
    keep, has_manifest = [], False
    for path in out.split("\0"):
        if not path or "node_modules/" in path:
            continue
        name = path.rsplit("/", 1)[-1]
        inner = path[len(prefix):]
        if re.match(r"^requirements/[^/]+\.txt$", inner) or ("/" not in inner and (
                name in JS_LOCKS or name in OTHER_LOCKS or re.match(r"^requirements.*\.txt$", name))):
            keep.append(path)
            has_manifest = True
        elif name in ("package.json", "pyproject.toml", "pnpm-workspace.yaml"):
            keep.append(path)   # npm and pnpm need every workspace member's package.json; Poetry needs pyproject
    if not has_manifest:
        return None
    r = subprocess.run(["git", "archive", "--format=tar", sha, "--", *keep], cwd=root, capture_output=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(_tail(r.stderr.decode(errors="ignore")) or "git archive failed")
    with tarfile.open(fileobj=io.BytesIO(r.stdout)) as tar:
        try:
            tar.extractall(tmp, filter="data")
        except TypeError:   # Python before the extraction filters
            tar.extractall(tmp)
    return Path(tmp) / rel


def check_deployed(p, spec, cfg):
    """Which commit is live for this project, and what the same scan finds in it.
    status: same (live is this checkout) | differs (scanned separately) | failed (could not tell: an incomplete scan)."""
    dep = {"status": "failed", "commit": None, "date": None, "source": None, "detail": None, "manifests": [], "findings": []}
    root = (p.get("git") or {}).get("root")
    if not root:
        dep["detail"] = "not a git repository, so the live commit cannot be compared"
        return dep

    def g(*args):
        rc, out, _ = run(["git", *args], p["path"], timeout=30)
        return out.strip() if rc == 0 else ""
    if spec.get("ref"):
        dep["source"], want = f"ref {spec['ref']}", str(spec["ref"])
    elif spec.get("command"):
        dep["source"] = "command"
        try:
            r = subprocess.run(str(spec["command"]), shell=True, cwd=p["path"], capture_output=True, text=True, timeout=60)
        except subprocess.TimeoutExpired:
            dep["detail"] = "the deployed command timed out after 60s"
            return dep
        if r.returncode != 0:
            dep["detail"] = f"the deployed command failed (exit {r.returncode}): {_tail(r.stderr, r.stdout, n=160)}".rstrip(": ")
            return dep
        want = (r.stdout.split() or [""])[0]
        if not want:
            dep["detail"] = "the deployed command printed nothing"
            return dep
    else:
        dep["detail"] = "a deployed entry needs a ref or a command"
        return dep
    sha = "" if want.startswith("-") else g("rev-parse", "--verify", "--quiet", f"{want}^{{commit}}")
    if not sha:
        dep["detail"] = f"{want[:60]} is not in this checkout (git fetch, or check the ref)"
        return dep
    dep["commit"], dep["date"] = sha[:7], g("log", "-1", "--format=%cs", sha)
    if sha == g("rev-parse", "HEAD"):
        dep["status"] = "same"
        return dep
    dep["status"] = "differs"
    try:
        with tempfile.TemporaryDirectory(prefix="dep-patrol-live-") as tmp:
            folder = _snapshot(root, sha, os.path.relpath(p["path"], root), tmp)
            if folder is not None:
                dep["manifests"] = manifests_in(folder, os.listdir(folder))
                dep["findings"] = scan_folder(str(folder), dep["manifests"], cfg)
    except Exception as e:
        dep.update(status="failed", detail=f"could not read the live commit: {e}")
    return dep


# ------------------------------------------------------------------ policy: ignore, urgency, exit code
def _active(p):
    """Findings that count: not ignored, not dev-only. Scope unknown counts as production."""
    return [f for f in p["findings"] if not f.get("ignored") and f["scope"] != "dev"]


def _live(p):
    """Findings that count at the live commit, when it is not this checkout."""
    return [f for f in (p.get("deployed") or {}).get("findings") or [] if not f.get("ignored") and f["scope"] != "dev"]


def _rule_hits(rule, project, f):
    if rule.get("project") and not fnmatch.fnmatch(project, rule["project"]):
        return False
    ids = {str(x).lower() for x in (f["id"], *f["aliases"], f["url"])}
    adv, pkg, legacy = rule.get("advisory"), rule.get("package"), rule.get("match")
    if adv or pkg:
        return (not adv or str(adv).lower() in ids) and (not pkg or _norm(pkg) == _norm(f["package"]))
    return bool(legacy) and (str(legacy).lower() in ids or _norm(legacy) == _norm(f["package"]))


def apply_ignores(report, rules):
    """Mark ignored findings. Matching is exact: an advisory id, alias or URL, or a whole package name.
    Returns the rules that matched nothing, so stale or misspelt rules surface."""
    used = set()
    for p in report["projects"]:
        for f in p["findings"] + ((p.get("deployed") or {}).get("findings") or []):
            for i, rule in enumerate(rules):
                if _rule_hits(rule, p["name"], f):
                    f["ignored"] = {"reason": rule["reason"]}
                    used.add(i)
                    break
    return [r for i, r in enumerate(rules) if i not in used]


def urgent_findings(p, rules):
    """Findings that need action, from this checkout and from the live commit (each advisory once)."""
    out, seen = [], set()
    for f in _active(p) + _live(p):
        if (f["package"], f["id"]) in seen:
            continue
        seen.add((f["package"], f["id"]))
        s = f["severity"]
        if (s == "critical" and rules.get("critical_always", True)) or (p["exposed"] and (
                (s in ("critical", "high") and rules.get("high_on_exposed", True))
                or (s in ("critical", "high", "moderate") and rules.get("moderate_on_exposed", False))
                or (s == "unknown" and rules.get("unknown_on_exposed", False)))):
            out.append(f)
    return out


def exit_code(report, rules, strict=False):
    """1: something urgent. 2: the scan is incomplete. 0: every manifest scanned, nothing urgent."""
    if any(urgent_findings(p, rules) for p in report["projects"]):
        return 1
    live = [p["deployed"] for p in report["projects"] if p.get("deployed")]
    statuses = {m["status"] for p in report["projects"] for m in p["manifests"]}
    statuses |= {m["status"] for d in live for m in d["manifests"]} | {"failed" for d in live if d["status"] == "failed"}
    if report["problems"] or "failed" in statuses or (strict and statuses & {"unscanned", "partial"}):
        return 2
    return 0


# ------------------------------------------------------------------ memory: last report
def previous_report(out_root, when):
    dirs = sorted(d for d in out_root.glob("*") if d.is_dir() and d.name < when and (d / "report.json").exists())
    if not dirs:
        return None, None
    try:
        return dirs[-1].name, json.loads((dirs[-1] / "report.json").read_text())
    except Exception:
        return None, None


def _is_current(prev):
    return isinstance(prev, dict) and prev.get("schema") == SCHEMA and isinstance(prev.get("projects"), list)


def carry_forward(report, prev):
    """A manifest that could not be scanned this time keeps what the last report knew about it, marked stale.
    Without this, a failed audit would wipe a known finding and the project would read as clean."""
    if not _is_current(prev):
        return
    old = {p["name"]: p for p in prev["projects"]}
    for p in report["projects"]:
        o = old.get(p["name"])
        for m in p["manifests"] if o else []:
            if m["status"] in ("failed", "unscanned"):
                for f in o.get("findings") or []:
                    if f.get("manifest") == m["file"]:
                        g = {k: v for k, v in f.items() if k != "ignored"}
                        g["stale"] = f.get("stale") or prev.get("generated")
                        p["findings"].append(g)


def diff_reports(report, prev):
    """What changed since the last report, advisory by advisory. An advisory is only "fixed" when the manifest
    it was in was scanned again and it is gone. None when the last report is from an older schema."""
    if not _is_current(prev):
        return None

    def ids(f):
        return {f["id"], *f.get("aliases", [])}
    cur = {p["name"]: p for p in report["projects"]}
    d = {"previous": prev.get("generated"), "new": [], "fixed": [], "unverified": [], "open": 0, "gone": {}, "ignored": 0}
    matched = set()
    for old in prev["projects"]:
        olds, p = _active(old), cur.get(old["name"])
        if p is None:
            if olds:
                d["gone"][old["name"]] = len(olds)
            continue
        status = {m["file"]: m["status"] for m in p["manifests"]}
        for of in olds:
            same = [f for f in p["findings"] if f["package"] == of["package"] and ids(f) & ids(of)]
            live = [f for f in same if not f.get("ignored") and f["scope"] != "dev"]
            matched.update(id(f) for f in live)
            if live and not all(f.get("stale") for f in live):
                d["open"] += 1
            elif live or status.get(of.get("manifest")) in ("failed", "unscanned"):
                d["unverified"].append((p["name"], live[0] if live else of))
            elif any(f.get("ignored") for f in same):
                d["ignored"] += 1
            else:
                d["fixed"].append((p["name"], of))
    for p in report["projects"]:
        d["new"] += [(p["name"], f) for f in _active(p) if id(f) not in matched and not f.get("stale")]
    return d


# ------------------------------------------------------------------ report
def _counts(findings):
    """Unique advisories per severity (the same advisory in two manifests of a project counts once)."""
    seen, c = set(), {}
    for f in findings:
        if (f["package"], f["id"]) not in seen:
            seen.add((f["package"], f["id"]))
            c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c


def _worst(findings):
    return max([SEV_ORDER[f["severity"]] for f in findings] or [0])


def summarize(report, rules):
    projects = report["projects"]
    urg = [p for p in projects if urgent_findings(p, rules)]
    ms = [m for p in projects for m in p["manifests"]]
    failed = sum(1 for m in ms if m["status"] == "failed")
    loose = sum(1 for m in ms if m["status"] in ("unscanned", "partial"))
    s = (f"dep-patrol {report['generated']}: {_n(len(projects), 'project')}, {_n(len(ms), 'manifest')}, "
         f"{len(urg)} need{'s' if len(urg) == 1 else ''} action")
    if urg:
        s += ": " + ", ".join(f"{p['name']}{' (live)' if p['exposed'] else ''}" for p in urg[:12])
    if failed:
        s += f". {_n(failed, 'manifest')} could not be scanned"
    if report["problems"]:
        s += ". " + "; ".join(report["problems"])
    blind = [p["name"] for p in projects if (p.get("deployed") or {}).get("status") == "failed"]
    if blind:
        s += ". live commit unknown for " + ", ".join(blind[:6])
    if loose:
        s += f". {_n(loose, 'manifest')} not fully scanned"
    return s


def _best_fix(fs):
    """The fix that clears every advisory in the list: the highest version any of them asks for."""
    fixes = sorted({f["fix"] for f in fs if f["fix"]}, key=lambda x: (_loose_key(x), x))
    real = [x for x in fixes if x != "none yet"]
    if not real:
        return "none yet"
    return real[-1] + ("" if len(real) == len(fixes) else " (some have no fix yet)")


def _package_blocks(findings, many_manifests):
    """Report lines for findings: one block per package (worst first), its advisories underneath, at most five."""
    rank = {"production": 2, "unknown": 1, "dev": 0}
    by = {}
    for f in findings:
        by.setdefault(f["package"], []).append(f)
    lines = []
    for fs in sorted(by.values(), key=lambda fs: (-_worst(fs), fs[0]["package"])):
        fs = sorted(fs, key=lambda f: (-SEV_ORDER[f["severity"]], f["id"]))
        c = _counts(fs)
        scope = max((f["scope"] for f in fs), key=lambda x: rank.get(x, 1))
        versions = sorted({v for f in fs for v in f["versions"]}, key=_loose_key)
        via = sorted({v for f in fs for v in f["via"]})
        bits = [f"**{fs[0]['package']}** {', '.join(versions)}".rstrip(), "scope not known" if scope == "unknown" else scope]
        if any(f["direct"] for f in fs):
            bits.append("direct")
        elif via:
            bits.append("through " + ", ".join(via[:3]))
        if many_manifests:
            bits.append(", ".join(sorted({f["manifest"] for f in fs})))
        bits += [", ".join(f"{c[x]} {x}" for x in sorted(c, key=lambda x: -SEV_ORDER[x])), "fix: " + _best_fix(fs)]
        stale = sorted({f["stale"] for f in fs if f.get("stale")})
        if stale:
            bits.append(f"not re-checked since {stale[0]}")
        lines.append("- " + " · ".join(bits))
        for f in fs[:5]:
            why = f" ({f['severity_source']})" if f["severity"] == "unknown" and f.get("severity_source") else ""
            lines.append(f"  - [{f['id']}]({f['url']}) {f['severity']}{why}: {f['title']}")
        if len(fs) > 5:
            lines.append(f"  - and {len(fs) - 5} more (in report.json)")
    return lines


def render(report, rules, diff=None, tools=None, legacy_previous=None):
    projects = report["projects"]
    pairs = [(p, m) for p in projects for m in p["manifests"]]
    urg = [p for p in projects if urgent_findings(p, rules)]
    failed = [(p, m) for p, m in pairs if m["status"] == "failed"]
    loose = [(p, m) for p, m in pairs if m["status"] in ("unscanned", "partial")]
    head = (f"{_n(len(projects), 'project')}, {_n(len(pairs), 'manifest')}. **{len(urg)} need{'s' if len(urg) == 1 else ''} "
            "action** (a critical anywhere, or a critical or high in a live app).")
    if failed:
        head += f" **{_n(len(failed), 'manifest')} could not be scanned**, so this report is incomplete."
    if loose:
        head += f" {_n(len(loose), 'manifest')} not fully scanned (listed at the end)."
    lines = [f"# Dependency scan, {report['generated']}", "", head, ""]
    if diff:
        def names(items, with_sev=False):
            top = [(n, f) for n, f in items if f["severity"] in ("critical", "high", "unknown")][:15]
            return (": " + ", ".join(f"{n} {f['package']} {f['id']}" + (f" ({f['severity']})" if with_sev else "")
                                     for n, f in top)) if top else ""
        lines += [f"## Since the last scan ({diff['previous']})", "",
                  f"- **New:** {len(diff['new'])}{names(diff['new'], True)}",
                  f"- **Fixed:** {len(diff['fixed'])}{names(diff['fixed'])}",
                  f"- **Still open:** {diff['open']}"]
        if diff["unverified"]:
            lines.append(f"- **Not re-checked:** {len(diff['unverified'])} (their scan failed this time, so they still count)"
                         f"{names(diff['unverified'])}")
        if diff["ignored"]:
            lines.append(f"- Now ignored by a rule: {diff['ignored']}")
        if diff["gone"]:
            lines.append("- Projects no longer found: " + ", ".join(f"{n} ({c})" for n, c in sorted(diff["gone"].items())))
        lines.append("")
    elif legacy_previous:
        lines += [f"The previous report ({legacy_previous}) was written by an older version of dep-patrol, "
                  "so there is no change list this time.", ""]
    live = [(p, p["deployed"]) for p in projects if p.get("deployed")]
    live_problems = [f"- {p['name']}: live commit unknown: {d['detail']}" for p, d in live if d["status"] == "failed"]
    live_problems += [f"- {p['name']}: {m['file']} at the live commit {d['commit']} failed: {m['detail']}"
                      for p, d in live for m in d["manifests"] if m["status"] == "failed"]
    if failed or report["problems"] or live_problems:
        lines += ["## Scan problems", "", "These were not checked. Until they are, a quiet row below proves nothing about them.", ""]
        lines += [f"- {x}" for x in report["problems"]]
        lines += [f"- {p['name']}: {m['file']} failed: {m['detail']}" for p, m in failed] + live_problems
        lines.append("")
    lines += ["| Project | Live | Critical | High | Moderate | Unrated | Scanned | Branch | Note |", "|---|---|---|---|---|---|---|---|---|"]
    rows = sorted(projects, key=lambda p: (-int(p["exposed"]), -_worst(_active(p)), p["name"]))
    for p in rows:
        c = _counts(_active(p))
        not_ok = [f"{m['file']}: {'not scanned' if m['status'] == 'unscanned' else m['status']}" for m in p["manifests"]
                  if m["status"] in ("failed", "unscanned", "partial")]
        notes = []
        dev = _counts([f for f in p["findings"] if f["scope"] == "dev" and not f.get("ignored")])
        if dev:
            notes.append("dev-only: " + ", ".join(f"{dev[s]} {s}" for s in sorted(dev, key=lambda s: -SEV_ORDER[s])))
        if any(f.get("ignored") for f in p["findings"]):
            notes.append(f"ignored: {sum(1 for f in p['findings'] if f.get('ignored'))}")
        if any(f.get("stale") for f in p["findings"]):
            notes.append("has findings from an earlier scan")
        dep = p.get("deployed")
        if dep:
            notes.append({"same": f"live is this checkout ({dep['commit']})", "failed": "live commit unknown",
                          "differs": f"live is {dep['commit']}, not this checkout"}[dep["status"]])
        g = p.get("git") or {}
        lines.append(f"| {p['name']} | {'yes' if p['exposed'] else ''} | {c.get('critical', '')} | {c.get('high', '')} | "
                     f"{c.get('moderate', '')} | {c.get('unknown', '')} | {'; '.join(not_ok) or 'yes'} | "
                     f"{g.get('branch', '')}{' (dirty)' if g.get('dirty') else ''} | {'; '.join(notes)} |")
    for p in rows:
        act = _active(p)
        top = sorted((f for f in act if f["severity"] in ("critical", "high", "unknown")),
                     key=lambda f: (-SEV_ORDER[f["severity"]], f["package"], f["id"]))
        dep = p.get("deployed")
        ignored = [f for f in p["findings"] + ((dep or {}).get("findings") or []) if f.get("ignored")]
        differs = bool(dep) and dep["status"] == "differs"
        live_top = sorted((f for f in _live(p) if f["severity"] in ("critical", "high", "unknown")),
                          key=lambda f: (-SEV_ORDER[f["severity"]], f["package"], f["id"]))
        if not top and not ignored and not differs:
            continue
        g = p.get("git") or {}
        where = f"`{p['path']}`" + (f" · {g['branch']} @ {g['commit']} ({g['date']})" if g.get("commit") else "")
        lines += ["", f"## {p['name']}{' (LIVE)' if p['exposed'] else ''}", where, ""]
        many = len({f["manifest"] for f in p["findings"]}) > 1
        if differs:
            lines.append(f"**Live is {dep['commit']} ({dep['date']}), not this checkout.** " + (
                f"{_n(len(live_top), 'critical, high or unrated advisory').replace('advisorys', 'advisories')} still in what is live:"
                if live_top else "Nothing critical, high or unrated in what is live."))
            lines += _package_blocks(live_top, False)
            if top:
                lines += ["", "In this checkout:"]
        elif dep and dep["status"] == "same":
            lines += [f"Live is this checkout ({dep['commit']}).", ""]
        lines += _package_blocks(top, many)
        rest = _counts([f for f in act if f["severity"] in ("moderate", "low", "info")])
        if rest:
            lines.append("- plus " + ", ".join(f"{rest[s]} {s}" for s in ("moderate", "low", "info") if s in rest)
                         + " (in report.json)")
        lines += [f"- [{f['id']}]({f['url']}) {f['package']} ignored: {f['ignored']['reason']}" for f in ignored]
    if loose:
        lines += ["", "## Not scanned", "", "Nothing here was checked, or only part of it was.", ""]
        lines += [f"- {p['name']}: {m['file']}: {m['detail']}" for p, m in loose]
    quiet = {s: sum(1 for _, m in pairs if m["status"] == s) for s in ("covered", "skipped")}
    if quiet["covered"] or quiet["skipped"]:
        lines += ["", f"{_n(quiet['covered'], 'lockfile')} covered by a workspace root, "
                      f"{_n(quiet['skipped'], 'extra lockfile')} skipped (both listed in report.json)."]
    if report.get("warnings"):
        lines += ["", "## Warnings", ""] + [f"- {w}" for w in report["warnings"]]
    if tools:
        lines += ["", "## How this was scanned", ""] + [f"- {k}: {v}" for k, v in tools.items()]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------ SARIF
SARIF_LEVEL = {"critical": "error", "high": "error", "moderate": "warning", "unknown": "warning", "low": "note", "info": "note"}
SARIF_SCORE = {"critical": 9.5, "high": 8.0, "moderate": 5.5, "low": 2.0}


def _manifest_line(lines, package):
    """1-based line where a manifest names the package, or 1."""
    name = r"[-_.]+".join(re.escape(part) for part in re.split(r"[-_.]+", package) if part) or re.escape(package)
    pats = [rf'"(?:[^"]*/)?node_modules/{name}"\s*:', rf'^name\s*=\s*"{name}"', rf"^{name}\s*(\[[^\]]*\])?\s*==",
            rf'^"?{name}@', rf"^\s+'?/?{name}@", rf"^\s*{name}\s+v\d", rf'^\s+"{name}"\s*:']
    for pat in pats:
        rx = re.compile(pat, re.I)
        for i, line in enumerate(lines, 1):
            if rx.search(line):
                return i
    return 1


def sarif(report, rules):
    """SARIF 2.1.0 for code scanning. Holds every finding that counts (production or scope unknown, not ignored),
    at any severity; dev-only and ignored findings are left out. Each result points at the manifest it came from,
    with a path relative to the repository."""
    rule_table, results, texts = {}, [], {}
    for p in report["projects"]:
        base = (p.get("git") or {}).get("root") or p["path"]
        urgent_now = {id(f) for f in urgent_findings(p, rules)}
        for f in _active(p):
            path = os.path.join(p["path"], f["manifest"])
            uri = os.path.relpath(path, base).replace(os.sep, "/")
            if uri.startswith(".."):
                uri = f["manifest"]
            if path not in texts:
                try:
                    texts[path] = Path(path).read_text(errors="ignore").splitlines()
                except OSError:
                    texts[path] = []
            score = f.get("score") or SARIF_SCORE.get(f["severity"])
            props = {"tags": ["security", "dependency"]}
            if score:
                props["security-severity"] = f"{float(score):.1f}"
            rule_table.setdefault(f["id"], {"id": f["id"], "shortDescription": {"text": f["title"]}, "helpUri": f["url"],
                                            "help": {"text": f"{f['title']}\n{f['url']}"}, "properties": props})
            scope = "scope not known" if f["scope"] == "unknown" else f["scope"]
            results.append({
                "ruleId": f["id"], "level": SARIF_LEVEL[f["severity"]],
                "message": {"text": f"{f['package']} {', '.join(f['versions'])} in {p['name']} ({f['severity']}, {scope}): "
                                    f"{f['title']}. Fix: {f['fix']}."},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
                                                    "region": {"startLine": _manifest_line(texts[path], f["package"])}}}],
                "partialFingerprints": {"primaryLocationLineHash":
                                        hashlib.sha256(f"{f['id']}|{f['package']}|{uri}".encode()).hexdigest()[:32]},
                "properties": {"urgent": id(f) in urgent_now, "scope": f["scope"], "project": p["name"]}})
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "dep-patrol", "version": VERSION,
                                          "informationUri": "https://github.com/drewmattie-code/dep-patrol",
                                          "rules": list(rule_table.values())}}, "results": results}]}


# ------------------------------------------------------------------ main
def verify_fixed(projects, wanted):
    """Say whether each advisory is gone. "Gone" needs every manifest scanned: a bump verified by an audit
    that did not run proves nothing. Any copy counts as present, dev-only and ignored ones included."""
    pairs = [(p, m) for p in projects for m in p["manifests"] if m["status"] not in ("covered", "skipped")]
    blind = [f"{p['name']} {m['file']} {m['status']}" for p, m in pairs if m["status"] != "scanned"]
    rc = 0
    for want in wanted:
        hits = [(p, f) for p in projects for f in p["findings"]
                if want.lower() in {x.lower() for x in (f["id"], *f["aliases"])}]
        if hits:
            rc = 1
            for p, f in hits:
                print(f"{want}: still present in {p['name']} {f['manifest']} ({f['package']} {', '.join(f['versions'])}, {f['scope']})")
        elif blind or not pairs:
            rc = rc or 2
            print(f"{want}: cannot confirm: " + ("; ".join(blind[:5]) if blind else "no manifest was found to scan here"))
        else:
            print(f"{want}: gone ({_n(len(pairs), 'manifest')} scanned)")
    return rc


def main(argv=None):
    ap = argparse.ArgumentParser(description="dep-patrol dependency scan")
    ap.add_argument("--config")
    ap.add_argument("--roots", nargs="*", help="folders to search for projects")
    ap.add_argument("--repo", help="scan one repository: no depth limit, every project in it counts as live")
    ap.add_argument("--max-depth", type=int, help="how deep to look for projects under each root (0 = the root only)")
    ap.add_argument("--out", help="report folder (default ~/.dep-patrol/reports; with --repo nothing is written without it)")
    ap.add_argument("--sarif", help="also write the SARIF file to this path")
    ap.add_argument("--notify", action="store_true", help="run the config's notify command when the exit code is not 0")
    ap.add_argument("--dry-run", action="store_true", help="list what would be scanned; no network")
    ap.add_argument("--json", action="store_true", help="print the report as JSON on stdout; write no report files")
    ap.add_argument("--strict", action="store_true", help="exit 2 when anything was left unscanned or partly scanned")
    ap.add_argument("--exposed-only", action="store_true", help="scan only the projects marked live")
    ap.add_argument("--verify-fixed", nargs="+", metavar="ADVISORY",
                    help="after a bump: scan, then say for each advisory id whether it is gone. Exit 0 all gone, "
                         "1 one is still present, 2 cannot tell because part of the scan did not run")
    a = ap.parse_args(argv)
    del LOG_LINES[:]
    cfg, problems, warnings = load_config(a.config, [a.repo] if a.repo else a.roots)
    if a.repo:
        cfg["max_depth"] = None
    if a.max_depth is not None:
        cfg["max_depth"] = a.max_depth
    for note in problems + warnings:
        log(f"config: {note}")
    if not any(Path(os.path.expanduser(r)).is_dir() for r in cfg["roots"]):
        print("dep-patrol: nothing to scan: " + "; ".join(problems))
        return 2
    projects = scan(cfg, dry_run=a.dry_run, exposed_only=a.exposed_only, all_exposed=bool(a.repo) and not cfg["exposed"],
                    problems=None if a.repo else problems)   # a config shared with CI may list apps from other repos
    if a.dry_run:
        pending = sum(1 for p in projects for m in p["manifests"] if m["status"] == "pending")
        print(f"dry run: {_n(len(projects), 'project')}, {_n(pending, 'manifest')} would be scanned")
        return 0
    if a.verify_fixed:
        return verify_fixed(projects, a.verify_fixed)
    report = {"schema": SCHEMA, "version": VERSION, "generated": today(), "problems": problems, "warnings": warnings,
              "projects": projects}
    # A one-repo run must never land in the machine-wide report folder: it would become "the last scan"
    # and the next monthly change list would be nonsense. With --repo, files are written only when --out says where.
    out_dir = a.out or (None if a.repo else cfg.get("out") or DEFAULT_OUT)
    out_root = Path(os.path.expanduser(out_dir)) if out_dir else None
    prev_name, prev = previous_report(out_root, report["generated"]) if out_root else (None, None)
    carry_forward(report, prev)
    warnings += [f"ignore rule matched nothing (remove it or check the spelling): {json.dumps(r)}"
                 for r in apply_ignores(report, cfg["ignore"])]
    rules = cfg["urgency"]
    rc = exit_code(report, rules, a.strict)
    summary = summarize(report, rules)
    if a.sarif:
        Path(a.sarif).parent.mkdir(parents=True, exist_ok=True)
        Path(a.sarif).write_text(json.dumps(sarif(report, rules), indent=1))
    wrote = None
    if a.json:
        print(json.dumps(report, indent=1))
    elif out_root is None:
        print(summary)
        print("no report files written (add --out DIR to keep the report)")
    else:
        out = wrote = out_root / report["generated"]
        out.mkdir(parents=True, exist_ok=True)
        tools = {"dep-patrol": VERSION, "npm": tool_version(["npm", "--version"]),
                 "pnpm": tool_version(["pnpm", "--version"]), "osv-scanner": tool_version(["osv-scanner", "--version"]),
                 "OSV API": f"api.osv.dev (cached {cfg.get('osv_cache_days', 7)} days in {CACHE_DIR})",
                 "commands": "npm audit --json (scope from the lockfile); pnpm audit --json; OSV querybatch; "
                             "osv-scanner scan source -L <lockfile>"}
        diff = diff_reports(report, prev)
        md = render(report, rules, diff, tools, legacy_previous=prev_name if prev is not None and diff is None else None)
        (out / "report.md").write_text(md)
        (out / "report.json").write_text(json.dumps(report, indent=1))
        (out / "report.sarif").write_text(json.dumps(sarif(report, rules), indent=1))
        (out / "run.log").write_text("\n".join(LOG_LINES) + "\n")
        print(summary)
        print(f"report: {out / 'report.md'}")
    if a.notify and rc != 0 and cfg.get("notify"):
        env = dict(os.environ, DEP_PATROL_SUMMARY=summary, DEP_PATROL_EXIT=str(rc),
                   DEP_PATROL_REPORT=str(wrote / "report.md") if wrote else "")
        subprocess.run(os.path.expandvars(cfg["notify"]), shell=True, env=env, timeout=60)
    return rc


def entry(argv=None):
    """Command-line entry. A crash is exit 2 (the scan did not complete), never 1 (which means findings)."""
    try:
        return main(argv)
    except KeyboardInterrupt:
        return 2
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"dep-patrol crashed, so nothing here was verified: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(entry())
