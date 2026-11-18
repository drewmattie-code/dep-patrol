#!/usr/bin/env python3
"""Check one live run against what is known about its fixture.

usage: check.py <vulnerable|clean|broken> <exit code> <report folder> <fixture folder>

Advisory databases only grow, so the vulnerable fixture is checked for "at least these", never for exact totals.
"""
import json, re, subprocess, sys
from pathlib import Path

name, code, report_dir, fixture = sys.argv[1], int(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4])
report = json.loads(next(report_dir.rglob("report.json")).read_text())
sarif = json.loads(next(report_dir.rglob("*.sarif")).read_text())
projects = {p["name"].split("/", 1)[-1] if "/" in p["name"] else ".": p for p in report["projects"]}
problems = []


def expect(ok, what):
    print(("ok    " if ok else "WRONG ") + what)
    if not ok:
        problems.append(what)


def find(project, package, advisory):
    for f in projects.get(project, {}).get("findings", []):
        if f["package"] == package and advisory in [f["id"], *f["aliases"]]:
            return f
    return None


statuses = {f"{k}/{m['file']}": m["status"] for k, p in projects.items() for m in p["manifests"]}
if name == "vulnerable":
    expect(code == 1, f"exit code 1 (got {code})")
    expect(statuses == {"services/web/package-lock.json": "scanned", "services/api/requirements.txt": "scanned",
                        "tools/rs/Cargo.lock": "scanned"}, f"all three manifests scanned: {statuses}")
    lodash = find("services/web", "lodash", "GHSA-35jh-r3h4-6jhm")
    expect(bool(lodash) and (lodash["scope"], lodash["direct"], lodash["versions"]) == ("production", True, ["4.17.20"]),
           "lodash advisory: production, direct, version 4.17.20")
    minimist = find("services/web", "minimist", "GHSA-xvch-5gv4-984h")
    expect(bool(minimist) and minimist["scope"] == "dev", "minimist advisory: dev scope")
    jinja = find("services/api", "jinja2", "GHSA-h5c8-rqwp-cp95")
    expect(bool(jinja) and (jinja["manifest"], jinja["ecosystem"]) == ("requirements.txt", "PyPI"), "jinja2 advisory from requirements.txt")
    expect(bool(jinja) and "PYSEC" in " ".join(jinja["aliases"]), "the PYSEC copy is folded into the GHSA advisory")
    expect(bool(find("tools/rs", "smallvec", "RUSTSEC-2019-0009")), "smallvec advisory from Cargo.lock (osv-scanner)")
    # the scanner's production list must equal npm's own answer
    out = subprocess.run(["npm", "audit", "--omit=dev", "--json"], cwd=fixture / "services/web", capture_output=True, text=True).stdout
    theirs = {(n, re.search(r"GHSA(-[0-9a-z]{4}){3}", a["url"]).group(0)) for n, e in json.loads(out)["vulnerabilities"].items()
              for a in e["via"] if isinstance(a, dict)}
    mine = {(f["package"], f["id"]) for f in projects["services/web"]["findings"] if f["scope"] != "dev"}
    expect(mine == theirs and len(mine) > 0, f"production advisories equal `npm audit --omit=dev` ({len(mine)} of {len(theirs)})")
    results = sarif["runs"][0]["results"]
    uris = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results}
    expect(uris == {"services/web/package-lock.json", "services/api/requirements.txt", "tools/rs/Cargo.lock"},
           f"SARIF paths are relative to the repository: {sorted(uris)}")
    expect(str(fixture) not in json.dumps(sarif), "no machine path anywhere in the SARIF")
    expect("GHSA-35jh-r3h4-6jhm" in {r["ruleId"] for r in results} and "GHSA-xvch-5gv4-984h" not in {r["ruleId"] for r in results},
           "SARIF has the production advisory and leaves the dev-only one out")
    line = next(r["locations"][0]["physicalLocation"]["region"]["startLine"] for r in results if r["ruleId"] == "GHSA-35jh-r3h4-6jhm")
    lock = (fixture / "services/web/package-lock.json").read_text().splitlines()
    expect("node_modules/lodash" in lock[line - 1], f"SARIF line {line} is the lodash entry of the lockfile")
elif name == "clean":
    expect(code == 0, f"exit code 0 (got {code})")
    expect(statuses == {"./package-lock.json": "scanned"}, f"the manifest was scanned: {statuses}")
    expect(sum(len(p["findings"]) for p in projects.values()) == 0, "no findings")
    expect(sarif["runs"][0]["results"] == [], "empty SARIF")
elif name == "broken":
    expect(code == 2, f"exit code 2 (got {code}): a lockfile that cannot be audited must not pass")
    expect(statuses == {"./package-lock.json": "failed"}, f"the manifest is marked failed: {statuses}")
    expect("Scan problems" in next(report_dir.rglob("report.md")).read_text(), "the report says so")
else:
    sys.exit(f"unknown fixture {name}")
sys.exit(1 if problems else 0)
