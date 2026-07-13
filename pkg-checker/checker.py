"""
Part 04 — Package Name Checker
Owner: Taz

Detects misspelled package names and typosquatting attacks in
requirements.txt (PyPI) and package.json (npm) files.

Writes findings into scan-state.json using the same format as
core/state.py so Parts 02, 03, and 06 can read them without any
special handling — they look identical to core-scanner findings.

Standalone usage (run from repo root):
    python pkg-checker/checker.py --file requirements.txt
    python pkg-checker/checker.py --file package.json
    python pkg-checker/checker.py --package requets --ecosystem pypi
    python pkg-checker/checker.py --watch requirements.txt,package.json

Integration hook (called by Part 03 VS Code extension):
    from pkg_checker.checker import run_check
    findings = run_check(file_path, state_path="scan-state.json")
"""

import json
import os
import sys
import time
import argparse

# ── Import shared state helpers from core/state.py ───────────────────────────
# Works whether you run this from the repo root or from pkg-checker/
_CORE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "core")
sys.path.insert(0, _CORE_PATH)
import state as scan_state  # load_state, save_state, recompute_stats

# ── Try optional dependencies ─────────────────────────────────────────────────
try:
    import requests as http
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[pkg-checker] WARNING: 'requests' not installed. Registry checks disabled.")
    print("[pkg-checker] Fix: pip install requests")

try:
    import Levenshtein
    def edit_distance(a, b):
        return Levenshtein.distance(a.lower(), b.lower())
except ImportError:
    from difflib import SequenceMatcher
    def edit_distance(a, b):
        ratio = SequenceMatcher(None, a.lower(), b.lower()).ratio()
        return int(round((1 - ratio) * max(len(a), len(b))))

# ── Known trusted packages ────────────────────────────────────────────────────
# The packages most commonly targeted by typosquatting.
# An incoming package name within TYPOSQUAT_THRESHOLD edits of one of
# these is flagged as suspicious.

KNOWN_PYPI_PACKAGES = [
    "requests", "numpy", "pandas", "flask", "django", "fastapi",
    "tensorflow", "torch", "sklearn", "scikit-learn", "scipy",
    "boto3", "botocore", "awscli", "paramiko", "cryptography",
    "pillow", "matplotlib", "seaborn", "sqlalchemy", "celery",
    "redis", "pymongo", "psycopg2", "aiohttp", "httpx",
    "pydantic", "uvicorn", "gunicorn", "pytest", "setuptools",
    "wheel", "pip", "virtualenv", "black", "flake8", "mypy",
    "rich", "click", "typer", "loguru", "dotenv", "python-dotenv",
    "beautifulsoup4", "scrapy", "selenium", "playwright",
    "openai", "anthropic", "langchain", "transformers", "tokenizers",
    "colorama", "tqdm", "arrow", "pendulum", "pyyaml", "toml",
    "jinja2", "markupsafe", "werkzeug", "itsdangerous",
    "semgrep", "bandit", "safety", "pip-audit",
]

KNOWN_NPM_PACKAGES = [
    "express", "react", "vue", "angular", "lodash", "axios",
    "webpack", "babel", "eslint", "prettier", "typescript",
    "jest", "mocha", "chai", "nodemon", "dotenv", "cors",
    "mongoose", "sequelize", "knex", "pg", "mysql2", "redis",
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "helmet",
    "morgan", "chalk", "yargs", "commander", "inquirer",
    "moment", "dayjs", "uuid", "nanoid", "zod", "yup",
    "socket.io", "ws", "got", "node-fetch", "superagent",
    "multer", "sharp", "jimp", "pdf-lib", "xlsx",
    "next", "nuxt", "gatsby", "remix", "vite", "rollup",
    "tailwindcss", "postcss", "autoprefixer", "sass",
    "redux", "zustand", "mobx", "recoil", "jotai",
    "react-router", "react-query", "swr", "formik", "react-hook-form",
    "semver", "cross-env", "concurrently", "rimraf", "dotenv-cli",
]

# Edit distance at or below this = suspicious
TYPOSQUAT_THRESHOLD = 2

# ── Ecosystem detection ───────────────────────────────────────────────────────

def detect_ecosystem(file_path):
    """
    Returns 'pypi' or 'npm' based on the filename.
    """
    filename = os.path.basename(file_path).lower()
    if filename == "requirements.txt":
        return "pypi"
    if filename == "package.json":
        return "npm"
    return "unknown"

# ── File parsers ──────────────────────────────────────────────────────────────

def parse_requirements_txt(file_path):
    """
    Reads requirements.txt and returns a list of package name strings.
    Strips version specifiers (==, >=, etc) and extras (requests[security]).
    """
    packages = []
    if not os.path.exists(file_path):
        print(f"[pkg-checker] File not found: {file_path}")
        return packages

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            for sep in ["==", ">=", "<=", "!=", "~=", ">"]:
                if sep in line:
                    line = line.split(sep)[0].strip()
                    break
            line = line.split("[")[0].strip()
            if line:
                packages.append(line)

    return packages

def parse_package_json(file_path):
    """
    Reads package.json and returns a list of package name strings
    from both dependencies and devDependencies.
    """
    packages = []
    if not os.path.exists(file_path):
        print(f"[pkg-checker] File not found: {file_path}")
        return packages

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        deps     = data.get("dependencies", {})
        dev_deps = data.get("devDependencies", {})
        packages = list(deps.keys()) + list(dev_deps.keys())
    except json.JSONDecodeError as e:
        print(f"[pkg-checker] Could not parse {file_path}: {e}")

    return packages

# ── Similarity check ──────────────────────────────────────────────────────────

def find_closest_known(package_name, ecosystem="pypi"):
    """
    Returns the closest known package name and its edit distance.
    """
    known_list = KNOWN_PYPI_PACKAGES if ecosystem == "pypi" else KNOWN_NPM_PACKAGES
    closest, min_dist = None, 9999

    for known in known_list:
        dist = edit_distance(package_name, known)
        if dist < min_dist:
            min_dist = dist
            closest = known

    return {"name": closest, "distance": min_dist} if closest else None

# ── Registry check ────────────────────────────────────────────────────────────

def exists_on_registry(package_name, ecosystem="pypi", timeout=5):
    """
    Checks if the package exists on PyPI or npm.
    Returns True (exists), False (does not exist), None (could not check).
    """
    if not REQUESTS_AVAILABLE:
        return None

    try:
        if ecosystem == "pypi":
            url = f"https://pypi.org/pypi/{package_name}/json"
        else:
            url = f"https://registry.npmjs.org/{package_name}"

        response = http.get(url, timeout=timeout)
        return response.status_code == 200

    except Exception as e:
        print(f"[pkg-checker] Registry check failed for '{package_name}': {e}")
        return None

# ── Finding builder — matches core/state.py's format exactly ─────────────────

def _next_finding_id(state):
    """
    Generates the next finding ID in "F-XXXX" format,
    continuing from wherever the existing findings left off.
    """
    existing = state.get("findings", [])
    return f"F-{len(existing) + 1:04d}"

def build_finding(package_name, similar_to, distance, ecosystem,
                  registry_exists, severity, state):
    """
    Builds a finding dict in the exact format used by core/state.py.
    This makes Part 4 findings indistinguishable from Part 1 findings
    so Parts 2, 3, and 6 need no special handling.
    """
    # Registry status for message
    if registry_exists is False:
        reg_note = f"Package does NOT exist on the {ecosystem} registry — likely malicious."
    elif registry_exists is True:
        reg_note = f"Package exists on registry but name is suspiciously close to '{similar_to}'."
    else:
        reg_note = "Registry status could not be verified (no internet or timeout)."

    return {
        "id":           _next_finding_id(state),
        "rule_id":      f"pkg-checker.typosquatting.{package_name}",
        "type":         "typosquatting",
        "severity":     severity,               # "High" / "Critical" — capitalised to match core
        "message":      (
            f"Possible typosquatting: '{package_name}' is {distance} character(s) away "
            f"from the well-known {ecosystem} package '{similar_to}'. {reg_note} "
            f"Verify the correct package name before installing."
        ),
        "file_path":    "requirements.txt" if ecosystem == "pypi" else "package.json",
        "start_line":   0,
        "end_line":     0,
        "code_snippet": package_name,
        "status":       "open",
        "source":       "pkg-checker",
        "explanation":  None,                   # Left None — Part 02 fills this
        "metadata": {
            "suspicious_package": package_name,
            "similar_to":         similar_to,
            "edit_distance":      distance,
            "ecosystem":          ecosystem,
            "registry_exists":    registry_exists,
            "category":           "supply-chain",
            "cwe":                "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
            "references": [
                "https://owasp.org/www-community/attacks/Typosquatting",
                "https://pypi.org" if ecosystem == "pypi" else "https://npmjs.com",
            ],
        },
    }

# ── Core check logic ──────────────────────────────────────────────────────────

def check_single_package(package_name, ecosystem="pypi", state=None):
    """
    Runs all checks on one package name.
    Returns a finding dict if suspicious, None if safe.
    `state` is passed in so the finding ID can be assigned correctly.
    """
    package_name = package_name.strip()
    if not package_name:
        return None

    similar = find_closest_known(package_name, ecosystem)

    # Exact match to a known package = safe
    if similar and similar["distance"] == 0:
        return None

    # Within threshold = suspicious
    if similar and similar["distance"] <= TYPOSQUAT_THRESHOLD:
        registry_exists = exists_on_registry(package_name, ecosystem)

        if registry_exists is False:
            severity = "Critical"
        elif similar["distance"] == 1:
            severity = "High"
        else:
            severity = "Medium"

        return build_finding(
            package_name=package_name,
            similar_to=similar["name"],
            distance=similar["distance"],
            ecosystem=ecosystem,
            registry_exists=registry_exists,
            severity=severity,
            state=state or {"findings": []},
        )

    return None

def check_file(file_path, state=None, ecosystem=None):
    """
    Reads a package file and checks all packages in it.
    Returns a list of findings (empty if everything looks safe).
    """
    if ecosystem is None:
        ecosystem = detect_ecosystem(file_path)

    if ecosystem == "unknown":
        print(f"[pkg-checker] Unrecognised file: {file_path}. Expected requirements.txt or package.json.")
        return []

    print(f"[pkg-checker] Checking {file_path} ({ecosystem})...")

    packages = parse_requirements_txt(file_path) if ecosystem == "pypi" \
               else parse_package_json(file_path)

    print(f"[pkg-checker] {len(packages)} package(s) to check")

    findings = []
    working_state = state or {"findings": []}

    for pkg in packages:
        finding = check_single_package(pkg, ecosystem, working_state)
        if finding:
            findings.append(finding)
            # Update working state so next ID is correct
            working_state["findings"].append(finding)
            print(f"[pkg-checker] ⚠  FLAGGED: {pkg} → similar to '{finding['metadata']['similar_to']}' [{finding['severity']}]")
        else:
            print(f"[pkg-checker] ✓  OK: {pkg}")

    return findings

# ── State write ───────────────────────────────────────────────────────────────

def write_findings_to_state(findings, state_path="scan-state.json"):
    """
    Appends findings to scan-state.json and recomputes stats.
    Uses core/state.py helpers to stay in sync with the rest of the project.

    Deduplicates — if the same package was flagged in a previous run and
    is still open, it will not be added again (matches Part 01's behaviour).
    """
    if not findings:
        return

    state = scan_state.load_state(state_path)
    existing = state.get("findings", [])

    # Build dedup set of open findings by rule_id (package name is in rule_id)
    open_rule_ids = {
        e["rule_id"]
        for e in existing
        if e.get("status") == "open"
    }

    added = 0
    next_index = len(existing) + 1

    for finding in findings:
        if finding["rule_id"] in open_rule_ids:
            print(f"[pkg-checker] Skipping duplicate: {finding['rule_id']}")
            continue

        # Reassign ID based on the actual current state length
        finding["id"] = f"F-{next_index:04d}"
        existing.append(finding)
        open_rule_ids.add(finding["rule_id"])
        next_index += 1
        added += 1

    state["findings"] = existing
    scan_state.recompute_stats(state)
    scan_state.save_state(state, state_path)

    print(f"[pkg-checker] Added {added} new finding(s) to {state_path}")

# ── Integration hook for Part 03 ──────────────────────────────────────────────

def run_check(file_path, state_path="scan-state.json"):
    """
    THE MAIN INTEGRATION POINT — Part 03 (VS Code extension) calls this.

    On every file save of requirements.txt or package.json, Part 03
    calls this function. It handles everything: parses the file, checks
    all packages, writes findings to scan-state.json, and returns the
    list of new findings so Part 03 can show them immediately.

    Usage from Part 03:
        import sys
        sys.path.insert(0, "pkg-checker")
        from checker import run_check
        new_findings = run_check("requirements.txt", "scan-state.json")
    """
    state = scan_state.load_state(state_path)
    findings = check_file(file_path, state=state)
    write_findings_to_state(findings, state_path)
    return findings

# ── File watcher (standalone mode only) ──────────────────────────────────────

def watch_files(watch_paths, state_path="scan-state.json", interval=3):
    """
    Watches files for changes and re-runs check_file when they change.
    Only used when running Part 04 as a standalone watcher process.
    Part 03 uses VS Code's own file watcher instead.
    """
    print(f"[pkg-checker] Watching {len(watch_paths)} file(s). Ctrl+C to stop.\n")
    last_modified = {p: os.path.getmtime(p) if os.path.exists(p) else None
                     for p in watch_paths}

    try:
        while True:
            for path in watch_paths:
                if not os.path.exists(path):
                    continue
                mtime = os.path.getmtime(path)
                if last_modified.get(path) != mtime:
                    print(f"\n[pkg-checker] Change detected: {path}")
                    run_check(path, state_path)
                    last_modified[path] = mtime
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[pkg-checker] Watcher stopped.")

# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Ctrl+Alt+Delulu — Part 04: Package Name Checker"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--file",    help="Path to requirements.txt or package.json")
    group.add_argument("--package", help="Check a single package name")
    group.add_argument("--watch",   help="Comma-separated files to watch for changes")

    parser.add_argument("--ecosystem", choices=["pypi", "npm"],
                        help="Force ecosystem (auto-detected from filename if omitted)")
    parser.add_argument("--state",    default="scan-state.json",
                        help="Path to scan-state.json (default: scan-state.json)")
    parser.add_argument("--no-write", action="store_true",
                        help="Run checks but do not write to scan-state.json")

    args = parser.parse_args()
    print("\n[ctrl+alt+delulu] Part 04 — Package Name Checker\n")

    if args.file:
        state = scan_state.load_state(args.state)
        findings = check_file(args.file, state=state, ecosystem=args.ecosystem)
        if not args.no_write and findings:
            write_findings_to_state(findings, args.state)
        _print_results(findings)

    elif args.package:
        ecosystem = args.ecosystem or "pypi"
        finding = check_single_package(args.package, ecosystem)
        findings = [finding] if finding else []
        if not args.no_write and findings:
            write_findings_to_state(findings, args.state)
        _print_results(findings)

    elif args.watch:
        paths = [p.strip() for p in args.watch.split(",")]
        watch_files(paths, args.state)

def _print_results(findings):
    print()
    if not findings:
        print("  ✓  No suspicious packages found.\n")
        return
    print(f"  ⚠  {len(findings)} suspicious package(s) flagged:\n")
    for f in findings:
        print(f"  [{f['severity'].upper()}] {f['message'][:100]}...")
        print(f"  → Source: {f['metadata']['similar_to']} (edit distance: {f['metadata']['edit_distance']})")
        print()

if __name__ == "__main__":
    main()
