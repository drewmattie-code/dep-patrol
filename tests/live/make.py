#!/usr/bin/env python3
"""Build the fixture repositories for the live checks (the ones that use the real npm registry and OSV).

usage: make.py <folder>

They are generated at run time on purpose: this repository should not carry real vulnerable manifests.
  vulnerable/  a git repo with three projects, each pinned to a version with a long-published advisory
  clean/       a project with no dependencies
  broken/      a lockfile that cannot be read
"""
import json, subprocess, sys
from pathlib import Path

root = Path(sys.argv[1])


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def npm_lock(folder):
    subprocess.run(["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
                   cwd=folder, check=True, capture_output=True)


v = root / "vulnerable"
write(v / "services/web/package.json", json.dumps({
    "name": "web", "version": "1.0.0", "private": True,
    "dependencies": {"lodash": "4.17.20"},        # GHSA-35jh-r3h4-6jhm, command injection, fixed in 4.17.21
    "devDependencies": {"minimist": "1.2.5"}}))   # GHSA-xvch-5gv4-984h, prototype pollution, fixed in 1.2.6
npm_lock(v / "services/web")
write(v / "services/api/requirements.txt", "jinja2==3.1.2\n")   # GHSA-h5c8-rqwp-cp95, fixed in 3.1.3
write(v / "tools/rs/Cargo.lock", '''version = 3

[[package]]
name = "smallvec"
version = "0.6.9"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c4488ae950c49d403731982257768f48fada354a5203fe81f9bb6f43ca9002be"
''')                                                            # RUSTSEC-2019-0009, fixed in 0.6.10
git = ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.com"]
for cmd in (["init", "-q", "-b", "main"], ["add", "-A"], ["commit", "-q", "-m", "fixture"]):
    subprocess.run(git + cmd, cwd=v, check=True, capture_output=True)

write(root / "clean/package.json", json.dumps({"name": "clean", "version": "1.0.0", "private": True}))
npm_lock(root / "clean")

write(root / "broken/package.json", json.dumps({"name": "broken", "version": "1.0.0", "private": True}))
write(root / "broken/package-lock.json", "{ this is not a lockfile")
print(f"fixtures written to {root}")
