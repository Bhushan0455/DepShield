"""
DepShield Backend — Flask API server.

Endpoints:
  POST /api/scan       — Clone a GitHub repo and analyze its dependencies
  POST /api/scan-file  — Analyze an uploaded package.json / package-lock.json
  GET  /api/health     — Health check
"""

import os
import json
import shutil
import tempfile
import requests
import re
from flask import Flask, request, jsonify
from flask_cors import CORS
try:
    from .analyzer import analyze_manifest
except (ImportError, ValueError):
    from analyzer import analyze_manifest

app = Flask(__name__)
CORS(app)

# --- SCAN CONFIGURATION -------------------------------------------------------
EXCLUDED_DIRS = {
    "node_modules", ".git", "dist", "build", "coverage",
    "examples", "example", "test", "__tests__", "tests",
    "docs", "scripts", "fixtures", "bench", "benchmarks",
    "errors", ".next", ".turbo", "out", ".cache", ".yarn",
    ".github", ".vscode", "e2e", "cypress", "__mocks__",
    "__snapshots__", ".husky", ".changeset", ".devcontainer",
    "turbopack", "crates",
}
MAX_SCAN_FILES = 5000
MAX_FILE_SIZE = 100 * 1024  # 100 KB — skip minified/generated bundles

# Check if git is available
GIT_AVAILABLE = False
try:
    from git import Repo
    import subprocess
    subprocess.check_output(["git", "--version"])
    GIT_AVAILABLE = True
except Exception:
    print("[DepShield] Warning: git executable not found. GitHub URL scanning will be limited.")


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "git": GIT_AVAILABLE})


def fetch_github_api(repo_url):
    """
    Attempt to fetch package-lock.json or package.json via GitHub REST API.
    Works for public repos without needing 'git clone'.
    """
    # Parse owner/repo from URL
    # https://github.com/owner/repo -> owner/repo
    match = re.search(r"github\.com/([^/]+)/([^/.]+)", repo_url)
    if not match:
        return None, None
    
    owner, repo = match.groups()
    base_url = f"https://raw.githubusercontent.com/{owner}/{repo}/main"
    
    for filename in ["package-lock.json", "package.json"]:
        try:
            r = requests.get(f"{base_url}/{filename}", timeout=10)
            if r.status_code == 200:
                return filename, r.json()
        except Exception:
            # Fallback to 'master' if 'main' fails
            try:
                r = requests.get(f"https://raw.githubusercontent.com/{owner}/{repo}/master/{filename}", timeout=10)
                if r.status_code == 200:
                    return filename, r.json()
            except Exception:
                continue
    return None, None

def scan_codebase_usage(directory, restrict_to_names=None):
    """
    Scan JS/TS files in a directory to find require() and import statements.
    Returns a rich dict:  { pkg_name: { "count": int, "files": [str], "apis": [str] } }

    If restrict_to_names is provided (a set), only track those package names
    to avoid wasted work on irrelevant packages.
    """
    import time
    t0 = time.time()

    # Rich structure per package
    usage_data = {}   # pkg -> { "count": int, "files": [], "apis": set() }
    files_scanned = 0
    files_skipped_size = 0

    # Match: import ... from 'pkg' or import ... from "pkg"
    import_re = re.compile(r"import\s+.*?from\s+['\"]([^'\"]+)['\"]", re.MULTILINE)
    # Match: require('pkg') or require("pkg")
    require_re = re.compile(r"require\(['\"]([^'\"]+)['\"]\)", re.MULTILINE)
    # Match destructured imports:  import { pipe, on, emit } from 'pkg'
    destructure_re = re.compile(r"import\s*\{([^}]+)\}\s*from\s*['\"]([^'\"]+)['\"]", re.MULTILINE)
    # Match: pkg.method(  or  variable.method(  — we'll scope to known pkgs later
    method_call_re = re.compile(r"\.(\w+)\s*\(", re.MULTILINE)

    def _normalize_pkg(raw):
        """Extract the npm package name from an import specifier."""
        pkg = raw.split('/')[0]
        if raw.startswith('@'):
            parts = raw.split('/')
            if len(parts) >= 2:
                pkg = f"{parts[0]}/{parts[1]}"
        return pkg if not pkg.startswith('.') else None

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        if files_scanned >= MAX_SCAN_FILES:
            print(f"[DepShield] Usage scan hit file cap ({MAX_SCAN_FILES}), stopping walk.")
            break

        for file in files:
            if not file.endswith((".js", ".jsx", ".ts", ".tsx")):
                continue

            path = os.path.join(root, file)
            try:
                fsize = os.path.getsize(path)
                if fsize > MAX_FILE_SIZE:
                    files_skipped_size += 1
                    continue

                files_scanned += 1
                if files_scanned > MAX_SCAN_FILES:
                    break

                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # Relativize path for clean display
                rel_path = os.path.relpath(path, directory).replace("\\", "/")

                found_pkgs = set()
                file_apis = {}  # pkg -> set of api names found in this file

                # --- Destructured imports (highest quality API signal) ---
                for m in destructure_re.finditer(content):
                    names_str, raw_pkg = m.group(1), m.group(2)
                    pkg = _normalize_pkg(raw_pkg)
                    if pkg:
                        found_pkgs.add(pkg)
                        apis = {n.strip().split(" as ")[0].strip() for n in names_str.split(",")}
                        apis = {a for a in apis if a and a.isidentifier()}
                        file_apis.setdefault(pkg, set()).update(apis)

                # --- Regular import from ---
                for m in import_re.finditer(content):
                    pkg = _normalize_pkg(m.group(1))
                    if pkg:
                        found_pkgs.add(pkg)

                # --- require() ---
                for m in require_re.finditer(content):
                    pkg = _normalize_pkg(m.group(1))
                    if pkg:
                        found_pkgs.add(pkg)

                # --- Method call extraction (lightweight heuristic) ---
                # Look for lines that contain a known package variable and .method()
                for m in method_call_re.finditer(content):
                    method_name = m.group(1)
                    # Only keep useful method names (skip common JS built-ins)
                    if method_name in ("then", "catch", "finally", "map", "filter",
                                       "reduce", "forEach", "push", "pop", "shift",
                                       "length", "log", "error", "warn", "stringify",
                                       "parse", "keys", "values", "entries", "toString",
                                       "indexOf", "slice", "splice", "join", "split",
                                       "replace", "trim", "toLowerCase", "toUpperCase",
                                       "includes", "startsWith", "endsWith", "default",
                                       "prototype", "apply", "call", "bind"):
                        continue
                    # Attribute to a found pkg if line contains pkg reference
                    line_start = content.rfind("\n", 0, m.start()) + 1
                    line = content[line_start:content.find("\n", m.start())]
                    for pkg in found_pkgs:
                        short = pkg.split("/")[-1]  # @scope/name -> name
                        if short in line or pkg in line:
                            file_apis.setdefault(pkg, set()).add(method_name)
                            break

                # If restricting, only keep matches that are in our target set
                if restrict_to_names is not None:
                    found_pkgs = found_pkgs & restrict_to_names

                for pkg in found_pkgs:
                    if pkg not in usage_data:
                        usage_data[pkg] = {"count": 0, "files": [], "apis": set()}
                    usage_data[pkg]["count"] += 1
                    if len(usage_data[pkg]["files"]) < 8:  # Cap file list
                        usage_data[pkg]["files"].append(rel_path)
                    if pkg in file_apis:
                        usage_data[pkg]["apis"].update(file_apis[pkg])
            except Exception:
                pass

    # Convert api sets to sorted lists and cap at 12 items
    for pkg in usage_data:
        apis = sorted(usage_data[pkg]["apis"])[:12]
        usage_data[pkg]["apis"] = apis

    elapsed = time.time() - t0
    print(f"[DepShield Timing] Codebase Usage Scan: {elapsed:.2f}s "
          f"({files_scanned} files scanned, {files_skipped_size} skipped by size)")
    return usage_data


@app.route("/api/scan", methods=["POST"])
def scan_repo():
    """
    Clone a GitHub repo, find package.json or package-lock.json, analyze it.
    Body: { "repoUrl": "...", "scanMode": "quick" | "deep" }
    """
    data = request.get_json(force=True)
    repo_url = data.get("repoUrl", "").strip()
    scan_mode = data.get("scanMode", "quick").lower()
    if scan_mode not in ("quick", "deep"):
        scan_mode = "quick"

    import time
    t_start = time.time()

    if not repo_url:
        return jsonify({"error": "repoUrl is required"}), 400

    print(f"\n[DepShield] === Scan started (mode={scan_mode}) ===")
    print(f"[DepShield] Target: {repo_url}")

    if not GIT_AVAILABLE:
        print(f"[DepShield] Git unavailable, trying GitHub API for {repo_url}...")
        filename, content = fetch_github_api(repo_url)
        if content:
            deps = analyze_manifest(filename, content, usage_map=None, scan_mode=scan_mode)
            print(f"[DepShield Timing] Total via GitHub API: {time.time() - t_start:.2f}s")
            return jsonify(deps)
        return jsonify({"error": "Git is not installed and GitHub API fetch failed. URL scanning is unavailable in this environment. Please use 'Upload File' instead."}), 501

    # Normalize GitHub URL
    if not repo_url.endswith(".git"):
        repo_url_git = repo_url.rstrip("/") + ".git"
    else:
        repo_url_git = repo_url

    tmp_dir = tempfile.mkdtemp(prefix="depshield_")

    try:
        t1 = time.time()
        print(f"[DepShield] Cloning {repo_url} ...")

        # Use subprocess for clone to handle Windows long-path issues
        # --no-checkout avoids checking out 7000+ files when we only need manifests
        import subprocess
        clone_cmd = [
            "git", "-c", "core.longPaths=true",
            "clone", "--depth=1", "--no-checkout",
            repo_url_git, tmp_dir
        ]
        result = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            raise Exception(f"Git clone failed: {result.stderr.strip()}")

        # Restore manifest files individually — some repos may not have package-lock.json
        for fname in ["package.json", "package-lock.json", "yarn.lock"]:
            res = subprocess.run(
                ["git", "-c", "core.longPaths=true", "checkout", "HEAD", "--", fname],
                cwd=tmp_dir, capture_output=True, text=True, timeout=30
            )
            if res.returncode == 0:
                print(f"[DepShield] Restored {fname}")
            else:
                print(f"[DepShield] {fname} not found in repo (skipped)")

        # For deep scan, also checkout source files (but git handles long paths now)
        if scan_mode == "deep":
            subprocess.run(
                ["git", "-c", "core.longPaths=true", "checkout"],
                cwd=tmp_dir, capture_output=True, text=True, timeout=120
            )

        t_clone = time.time()
        print(f"[DepShield Timing] Git Clone: {t_clone - t1:.2f}s (no-checkout={scan_mode != 'deep'})")

        # Look for manifest
        t_manifest = time.time()
        lock_path = os.path.join(tmp_dir, "package-lock.json")
        pkg_path = os.path.join(tmp_dir, "package.json")

        if os.path.exists(lock_path):
            manifest_path = lock_path
            filename = "package-lock.json"
        elif os.path.exists(pkg_path):
            manifest_path = pkg_path
            filename = "package.json"
        else:
            return jsonify({"error": "No package.json or package-lock.json found in repository"}), 400

        print(f"[DepShield Timing] Manifest Discovery: {time.time() - t_manifest:.4f}s")
        print(f"[DepShield] Found {filename}, analyzing...")

        with open(manifest_path, "r", encoding="utf-8") as f:
            content = json.load(f)

        # Monorepo detection
        root_pkg_path = os.path.join(tmp_dir, "package.json")
        is_monorepo = False
        if os.path.exists(root_pkg_path):
            try:
                with open(root_pkg_path, "r", encoding="utf-8") as pf:
                    root_pkg = json.load(pf)
                if root_pkg.get("workspaces"):
                    is_monorepo = True
                    ws = root_pkg["workspaces"]
                    if isinstance(ws, dict):
                        ws = ws.get("packages", [])
                    print(f"[DepShield] Monorepo detected - workspaces: {ws}")
            except Exception:
                pass

        # Codebase usage scan - only in deep mode
        usage_map = None
        if scan_mode == "deep":
            print(f"[DepShield] Running deep codebase usage scan...")
            usage_map = scan_codebase_usage(tmp_dir)
        else:
            print(f"[DepShield] Quick mode - skipping codebase usage scan")

        t_analysis = time.time()
        deps = analyze_manifest(filename, content, usage_map=usage_map, scan_mode=scan_mode)
        t_done = time.time()

        print(f"[DepShield] Done - {len(deps)} dependencies scanned")
        print(f"[DepShield Timing] Analyze Manifest: {t_done - t_analysis:.2f}s")
        print(f"[DepShield Timing] === Total Scan: {t_done - t_start:.2f}s (mode={scan_mode}) ===")

        return jsonify(deps)

    except Exception as e:
        print(f"[DepShield] Error: {e}")
        return jsonify({"error": str(e)}), 500

    finally:
        # Cleanup cloned repo
        try:
            shutil.rmtree(tmp_dir, ignore_errors=True)
        except Exception:
            pass


@app.route("/api/scan-file", methods=["POST"])
def scan_file():
    """
    Analyze a raw package.json or package-lock.json content.
    Body: { "filename": "package.json", "content": { ... } }
    """
    data = request.get_json(force=True)
    content = data.get("content")
    filename = data.get("filename", "package.json")

    if not content:
        return jsonify({"error": "content is required"}), 400

    # Parse if string
    if isinstance(content, str):
        try:
            content = json.loads(content)
        except json.JSONDecodeError:
            return jsonify({"error": "Invalid JSON content"}), 400

    scan_mode = data.get("scanMode", "quick").lower()
    if scan_mode not in ("quick", "deep"):
        scan_mode = "quick"

    import time
    t_start = time.time()

    try:
        print(f"\n[DepShield] Scanning file: {filename} (mode={scan_mode})")
        deps = analyze_manifest(filename, content, usage_map=None, scan_mode=scan_mode)
        print(f"[DepShield] Done - {len(deps)} dependencies scanned")
        print(f"[DepShield Timing] Total File Scan: {time.time() - t_start:.2f}s")
        return jsonify(deps)
    except Exception as e:
        print(f"[DepShield] Error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[DepShield] Backend running at http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
