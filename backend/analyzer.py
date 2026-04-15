"""
DepShield Analyzer — Real dependency scanning engine.

Pipeline:
  1. Parse manifest (package.json or package-lock.json)
  2. Query OSV API for vulnerability data  
  3. Query npm registry for package metadata
  4. Calculate risk scores, classify severity
  5. Build origin traces
  6. Generate fix recommendations
  7. Return data in the exact format the frontend DEPS expects
"""

import requests
import time
import math
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# ─── CONSTANTS ─────────────────────────────────────────────────────────────────
CONCURRENCY = 50
ONE_YEAR_SECS = 365 * 24 * 60 * 60

# Metadata caches to prevent redundant external API calls
OSV_CACHE = {}
NPM_CACHE = {}

SEV_COLORS = {
    "CRITICAL": "var(--red)",
    "HIGH":     "var(--orange)",
    "MEDIUM":   "var(--yellow)",
    "LOW":      "var(--amber)",
    "SAFE":     "var(--teal)",
}

# Known safe-alternative suggestions
ALTERNATIVES = {
    "lodash":              [{"name": "lodash-es", "cmd": "npm install lodash-es"}],
    "moment":              [{"name": "dayjs", "cmd": "npm install dayjs"}, {"name": "date-fns", "cmd": "npm install date-fns"}],
    "request":             [{"name": "axios", "cmd": "npm install axios"}, {"name": "node-fetch", "cmd": "npm install node-fetch"}],
    "underscore":          [{"name": "lodash-es", "cmd": "npm install lodash-es"}],
    "node-uuid":           [{"name": "uuid", "cmd": "npm install uuid"}],
    "minimist":            [{"name": "yargs", "cmd": "npm install yargs"}],
    "colors":              [{"name": "chalk", "cmd": "npm install chalk"}],
    "serialize-javascript":[{"name": "json-stringify-safe", "cmd": "npm install json-stringify-safe"}],
    "handlebars":          [{"name": "mustache", "cmd": "npm install mustache"}, {"name": "eta", "cmd": "npm install eta"}],
    "marked":              [{"name": "remark", "cmd": "npm install remark"}],
}

# ─── HELPERS ───────────────────────────────────────────────────────────────────

def _time_ago(date_str):
    """Convert ISO date string to human-readable 'X ago' format."""
    if not date_str:
        return "unknown"
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        seconds = (datetime.now(timezone.utc) - dt).total_seconds()
        if seconds < 0:
            return "today"
        years = seconds / 31536000
        if years > 1:
            return f"{int(years)} years ago"
        months = seconds / 2592000
        if months > 1:
            return f"{int(months)} months ago"
        days = seconds / 86400
        if days > 1:
            return f"{int(days)} days ago"
        return "today"
    except Exception:
        return "unknown"


def _clean_version(v):
    """Strip semver prefixes like ^, ~, >= etc."""
    return re.sub(r"[\^~>=<*\s]", "", str(v)).split(" ")[0] or "0.0.0"


def _score_to_sev(score):
    """Map CVSS-like score (0-10) to severity string."""
    if score >= 8:
        return "CRITICAL"
    if score >= 6:
        return "HIGH"
    if score >= 4:
        return "MEDIUM"
    if score >= 2:
        return "LOW"
    return "SAFE"


def _effort(score, depth):
    if depth > 2 or score >= 8:
        return "Hard"
    if depth > 1 or score >= 5:
        return "Medium"
    return "Easy"


# ─── API QUERIES ───────────────────────────────────────────────────────────────

def query_osv(name, version):
    """Query the OSV vulnerability database for a specific package@version."""
    try:
        r = requests.post(
            "https://api.osv.dev/v1/query",
            json={"version": version, "package": {"name": name, "ecosystem": "npm"}},
            timeout=10,
        )
        r.raise_for_status()
        vulns = r.json().get("vulns", [])
        results = []
        for v in vulns:
            vid = v.get("id", "")
            # Try to extract CVSS score from severity
            cvss = 0.0
            for sev_entry in v.get("severity", []):
                if sev_entry.get("type") == "CVSS_V3":
                    score_str = sev_entry.get("score", "")
                    # CVSS vector string — extract base score
                    # Sometimes it's just a number, sometimes a vector
                    try:
                        cvss = float(score_str)
                    except (ValueError, TypeError):
                        # Try to parse from vector
                        pass
            
            # Fallback: derive from database_specific severity
            db_sev = (v.get("database_specific", {}).get("severity", "") or "").upper()
            if cvss == 0.0:
                if db_sev == "CRITICAL":
                    cvss = 9.0
                elif db_sev == "HIGH":
                    cvss = 7.5
                elif db_sev == "MODERATE" or db_sev == "MEDIUM":
                    cvss = 5.5
                elif db_sev == "LOW":
                    cvss = 3.0
                else:
                    cvss = 5.0

            desc_text = v.get("details") or v.get("summary", "No details available.")
            # Truncate long descriptions securely but leave enough for UI
            if len(desc_text) > 800:
                desc_text = desc_text[:797] + "..."

            results.append({
                "id": vid,
                "cvss": cvss,
                "severity": db_sev or _score_to_sev(cvss),
                "summary": desc_text,
                "url": f"https://osv.dev/vulnerability/{vid}",
            })
        return results
    except Exception:
        return []

def fetch_osv_batch(deps_list):
    """Fetch OSV data for a list of packages in bulk and store in OSV_CACHE."""
    CHUNK_SIZE = 1000
    queries = []
    keys = []
    
    for d in deps_list:
        name = d["name"]
        version = d["version"]
        cache_key = f"{name}@{version}"
        if cache_key not in OSV_CACHE:
            queries.append({"package": {"name": name, "ecosystem": "npm"}, "version": version})
            keys.append(cache_key)

    for i in range(0, len(queries), CHUNK_SIZE):
        chunk = queries[i:i + CHUNK_SIZE]
        chunk_keys = keys[i:i + CHUNK_SIZE]
        try:
            r = requests.post("https://api.osv.dev/v1/querybatch", json={"queries": chunk}, timeout=15)
            r.raise_for_status()
            results = r.json().get("results", [])
            for j, res in enumerate(results):
                vulns = res.get("vulns", [])
                
                if not vulns:
                    OSV_CACHE[chunk_keys[j]] = []
                    continue
                
                # The OSV querybatch endpoint intentionally strips the `details` and `summary` 
                # fields to conserve bandwidth. Because vulnerabilities are rare, we can 
                # afford to fetch the full record synchronously to get the verbose description.
                try:
                    pkg_id = chunk_keys[j]
                    pkg_name, pkg_version = pkg_id.rsplit("@", 1)
                    full_vulns = query_osv(pkg_name, pkg_version)
                    OSV_CACHE[chunk_keys[j]] = full_vulns
                except Exception as e:
                    # Fallback to empty if single fetch fails
                    OSV_CACHE[chunk_keys[j]] = []
                    
        except Exception as e:
            print(f"[DepShield] OSV Batch query failed: {e}")
            for k in chunk_keys:
                if k not in OSV_CACHE:
                    OSV_CACHE[k] = []


def query_npm_meta(name):
    """Fetch latest version, dates, license, maintainer info from npm registry."""
    if name in NPM_CACHE:
        return NPM_CACHE[name]
    try:
        r = requests.get(f"https://registry.npmjs.org/{name}", timeout=10)
        r.raise_for_status()
        data = r.json()
        latest = (data.get("dist-tags") or {}).get("latest")
        modified = (data.get("time") or {}).get("modified")
        res = {
            "latest": latest,
            "modified": modified,
            "license": data.get("license") or "Unknown",
            "description": data.get("description") or "",
            "homepage": data.get("homepage"),
            "maintainers": len(data.get("maintainers") or []),
        }
        NPM_CACHE[name] = res
        return res
    except Exception:
        return None


def prefetch_npm_metadata(dep_names):
    """Pre-fetch npm metadata for all unique package names in parallel."""
    to_fetch = [n for n in dep_names if n not in NPM_CACHE]
    if not to_fetch:
        return
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = {executor.submit(query_npm_meta, name): name for name in to_fetch}
        for f in as_completed(futures):
            pass  # Results are cached in NPM_CACHE by query_npm_meta


# ─── CORE ANALYZER ─────────────────────────────────────────────────────────────

# Core folders that signal high-impact usage
CORE_FOLDERS = {"src", "app", "server", "api", "lib", "routes", "middleware", "services", "controllers", "utils", "core", "modules"}

def _analyze_single(dep_info):
    """Analyze a single dependency: query OSV + npm, compute scores."""
    name = dep_info["name"]
    version = dep_info["version"]
    depth = dep_info.get("depth", 1)
    origin = dep_info.get("origin", [name])
    project_type = dep_info.get("project_type", "Node.js (General)")
    usage_count = dep_info.get("usage_count", -1)
    usage_files = dep_info.get("usage_files", [])
    used_apis = dep_info.get("used_apis", [])

    vulns = OSV_CACHE.get(f"{name}@{version}", [])
    meta = query_npm_meta(name)

    # ── Compute CVSS-like score (max of individual CVEs) ──
    max_cvss = 0.0
    if vulns:
        max_cvss = max(v["cvss"] for v in vulns)

    score = max_cvss

    # Bump for outdated
    is_outdated = False
    if meta and meta["latest"] and meta["latest"] != version:
        is_outdated = True
        if score < 2:
            score = max(score, 1.0)

    # Determine maintainer status
    maint = "Active"
    if meta and meta["modified"]:
        try:
            mod_dt = datetime.fromisoformat(meta["modified"].replace("Z", "+00:00"))
            age_secs = (datetime.now(timezone.utc) - mod_dt).total_seconds()
            if age_secs > ONE_YEAR_SECS * 3:
                maint = "Abandoned"
                score = max(score, 2.5)
            elif age_secs > ONE_YEAR_SECS:
                maint = "Inactive"
        except Exception:
            pass
    if not meta:
        maint = "Inactive"

    # Transitive vs Direct weighting
    if depth > 1:
        score = score * 0.8

    # Final clamp
    score = round(min(10.0, float(score)), 1)
    sev = _score_to_sev(score)

    # ── Version analysis helpers ──
    def get_semver(v):
        v = _clean_version(v)
        parts = str(v).split('.')
        return [
            int(parts[0]) if len(parts) > 0 and parts[0].isdigit() else 0,
            int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0,
            int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0,
        ]

    cur_sem = get_semver(version)
    lat_sem = get_semver(meta["latest"]) if meta and meta.get("latest") else cur_sem
    current_major, current_minor = cur_sem[0], cur_sem[1]
    latest_major, latest_minor = lat_sem[0], lat_sem[1]

    # ── Breakage Risk + Reasons ──
    breakage_risk = "LOW"
    breakage_reason = []

    if latest_major > current_major:
        breakage_risk = "HIGH"
        breakage_reason.append(f"Major version jump detected (v{current_major} → v{latest_major})")
    elif is_outdated and latest_minor > current_minor:
        breakage_risk = "MEDIUM"
        breakage_reason.append(f"Minor version update available (v{current_minor} → v{latest_minor})")
    elif is_outdated:
        breakage_risk = "MEDIUM"
        breakage_reason.append("Patch update available")
    else:
        breakage_reason.append("No version change required")

    if maint == "Abandoned":
        breakage_reason.append("Package appears abandoned (no updates in 3+ years)")
        if breakage_risk == "LOW":
            breakage_risk = "MEDIUM"
    elif maint == "Inactive":
        breakage_reason.append("Package has been inactive for over 1 year")

    if len(used_apis) > 0 and breakage_risk == "HIGH":
        breakage_reason.append(f"Project uses {len(used_apis)} API(s) that may change in major update")
    elif len(used_apis) > 0:
        breakage_reason.append("No deprecated API usage detected")
    elif usage_count > 0:
        breakage_reason.append("Usage is shallow (no specific API calls detected)")

    if depth > 2:
        breakage_reason.append(f"Deeply transitive dependency (depth {depth})")
    elif depth > 1:
        breakage_reason.append("Transitive dependency")
    else:
        breakage_reason.append("Direct dependency")

    # ── Impact Level ──
    core_file_count = 0
    for fp in usage_files:
        top_folder = fp.split("/")[0] if "/" in fp else ""
        if top_folder in CORE_FOLDERS:
            core_file_count += 1

    impact_level = "LOW"
    impact_reason = ""
    if usage_count <= 0:
        impact_level = "LOW"
        impact_reason = "No direct imports detected in codebase"
    elif usage_count >= 10:
        impact_level = "HIGH"
        impact_reason = f"Used across {usage_count} files"
        if core_file_count > 0:
            impact_reason += f" ({core_file_count} in core modules)"
    elif usage_count >= 3 or core_file_count >= 2:
        impact_level = "MEDIUM"
        impact_reason = f"Used in {usage_count} file(s)"
        if core_file_count > 0:
            impact_reason += f" ({core_file_count} in core modules)"
    else:
        impact_level = "LOW"
        impact_reason = f"Used in {usage_count} file(s) only"

    if depth == 1:
        if impact_level == "LOW" and usage_count > 0:
            impact_level = "MEDIUM"
            impact_reason += " — direct project dependency"
    elif depth > 2 and impact_level != "HIGH":
        impact_reason += " — deeply nested transitive"

    # ── Confidence ──
    confidence = "HIGH"
    conf_signals = 0
    if usage_count >= 0:
        conf_signals += 1  # usage data available
    if meta:
        conf_signals += 1  # npm metadata available
    if meta and meta.get("latest"):
        conf_signals += 1  # version comparison possible

    if conf_signals >= 3:
        confidence = "HIGH"
    elif conf_signals >= 2:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    # ── Smart Advisor (context-aware) ──
    advisor_parts = []

    # Upgrade safety
    if not is_outdated and not vulns:
        advisor_parts.append("This dependency is up to date with no known vulnerabilities.")
    elif vulns and breakage_risk == "HIGH":
        advisor_parts.append(f"⚠ {len(vulns)} known vulnerability(s) found, but upgrading requires a major version jump (v{current_major} → v{latest_major}). Test thoroughly before upgrading.")
    elif vulns and breakage_risk != "HIGH":
        advisor_parts.append(f"⚠ {len(vulns)} known vulnerability(s) found. A safe patch/minor upgrade to v{meta['latest'] if meta else version} is available.")
    elif is_outdated and breakage_risk == "HIGH":
        advisor_parts.append(f"A major update (v{latest_major}) is available. Review the changelog for breaking API changes before upgrading.")
    elif is_outdated:
        advisor_parts.append("Safe to upgrade — only a minor/patch version change is needed.")

    # Maintenance health
    if maint == "Abandoned":
        alts = ALTERNATIVES.get(name, [])
        if alts:
            alt_names = ", ".join(a["name"] for a in alts[:2])
            advisor_parts.append(f"This package is abandoned. Consider migrating to {alt_names}.")
        else:
            advisor_parts.append("This package appears abandoned — evaluate if a maintained alternative exists.")

    # API-aware context
    if used_apis and breakage_risk == "HIGH":
        api_str = ", ".join(used_apis[:5])
        advisor_parts.append(f"Your codebase uses [{api_str}] — verify these APIs exist in v{latest_major}.")
    elif used_apis and breakage_risk != "HIGH":
        advisor_parts.append(f"Detected API usage ({', '.join(used_apis[:4])}) is unlikely to break on minor updates.")

    # Project type context
    if project_type and project_type != "Node.js (General)":
        advisor_parts.append(f"Project type: {project_type}.")

    # Impact awareness
    if impact_level == "HIGH":
        advisor_parts.append(f"High impact — used in {usage_count} files across core modules. Upgrade carefully.")
    elif usage_count == 0 and depth == 1:
        advisor_parts.append("No imports detected — this dependency may be unused. Consider removing it.")

    reco = " ".join(advisor_parts) if advisor_parts else "No specific recommendation."

    # CVE IDs list
    cve_ids = [v["id"] for v in vulns]

    # Description
    desc_text = ""
    if vulns:
        # Try to find a vulnerability with an actual description
        for v in vulns:
            if v["summary"] and v["summary"] != "No details available.":
                desc_text = v["summary"]
                break
        
        if not desc_text:
            desc_text = vulns[0]["summary"]
            
        desc = desc_text
        if len(vulns) > 1:
            desc += f" (+{len(vulns)-1} more)"
    elif is_outdated:
        meta_desc = (meta["description"] if meta else "") or ""
        desc = f"Outdated package. {meta_desc}"
    else:
        meta_desc = (meta["description"] if meta else "") or ""
        desc = f"No known vulnerabilities. {meta_desc}"

    # Fix
    latest = (meta["latest"] if meta else None) or version
    fix_cmd = ""
    fixv = latest
    if sev != "SAFE" and is_outdated:
        fix_cmd = f"npm install {name}@{latest}"
    elif sev != "SAFE" and vulns:
        fix_cmd = f"npm install {name}@{latest}"

    # Alternatives
    alts = ALTERNATIVES.get(name, [])

    # Updated date
    updated = ""
    if meta and meta["modified"]:
        try:
            updated = meta["modified"][:10]
        except Exception:
            updated = _time_ago(meta["modified"])

    # Size for graph node
    sz = max(6, min(32, 8 + len(name)))

    return {
        "name": name,
        "version": version,
        "latest": latest,
        "sev": sev,
        "score": score,
        "cves": cve_ids,
        "vulns": len(vulns),
        "desc": desc,
        "updated": updated,
        "maint": maint,
        "origin": origin,
        "fix": fix_cmd,
        "fixv": fixv,
        "alts": alts,
        "effort": _effort(score, depth),
        "sz": sz,
        "col": SEV_COLORS.get(sev, "var(--teal)"),
        "breakage_risk": breakage_risk,
        "breakage_reason": breakage_reason,
        "usage_count": usage_count,
        "usage_files": usage_files[:6],
        "used_apis": used_apis[:10],
        "impact_level": impact_level,
        "impact_reason": impact_reason,
        "confidence": confidence,
        "reco": reco,
    }


def analyze_manifest(filename, content, usage_map=None, scan_mode="quick"):
    """
    Analyze a parsed package.json or package-lock.json.
    Returns list of dep objects in the exact DEPS format the frontend expects.

    scan_mode: "quick" = deps + vulns only (fast), "deep" = full usage + breakage analysis
    """
    deps_to_scan = []

    import time
    t0 = time.time()

    if isinstance(content, str):
        import json
        content = json.loads(content)

    if "packages" in content:
        # package-lock.json v2/v3
        for key, meta in content["packages"].items():
            if key == "" or "node_modules/" not in key:
                continue
            parts = key.split("node_modules/")
            name = parts[-1].rstrip("/")
            depth = key.count("node_modules/")
            version = meta.get("version", "0.0.0")
            # Build origin trace
            origin_parts = ["project"]
            for i, p in enumerate(parts[1:], 1):
                origin_parts.append(p.rstrip("/"))
            deps_to_scan.append({
                "name": name,
                "version": version,
                "depth": depth,
                "origin": origin_parts,
            })
    elif "dependencies" in content or "devDependencies" in content:
        # package.json
        all_deps = {}
        all_deps.update(content.get("dependencies", {}))
        all_deps.update(content.get("devDependencies", {}))
        project_name = content.get("name", "project")
        for name, version in all_deps.items():
            deps_to_scan.append({
                "name": name,
                "version": _clean_version(version),
                "depth": 1,
                "origin": [project_name, name],
            })
    else:
        raise ValueError("Unrecognized format - expected package.json or package-lock.json")

    if not deps_to_scan:
        raise ValueError("No dependencies found in file")

    # Deduplicate by name+version (keep first occurrence)
    seen = set()
    unique_deps = []
    for d in deps_to_scan:
        key = f"{d['name']}@{d['version']}"
        if key not in seen:
            seen.add(key)
            unique_deps.append(d)
    deps_to_scan = unique_deps

    # Determine Project Type
    unique_names = [d["name"] for d in deps_to_scan]
    project_type = "Node.js (General)"
    if "react" in unique_names or "next" in unique_names or "vue" in unique_names or "svelte" in unique_names:
        project_type = "Frontend (React/Vue/etc)"
    if "express" in unique_names or "koa" in unique_names or "nestjs" in unique_names or "fastify" in unique_names:
        if project_type.startswith("Frontend"):
            project_type = "Fullstack (Node + Frontend)"
        else:
            project_type = "Backend (Express/Node)"

    for d in deps_to_scan:
        d["project_type"] = project_type
        if usage_map is not None:
            pkg_usage = usage_map.get(d["name"])
            if pkg_usage and isinstance(pkg_usage, dict):
                d["usage_count"] = pkg_usage.get("count", 0)
                d["usage_files"] = pkg_usage.get("files", [])
                d["used_apis"] = pkg_usage.get("apis", [])
            else:
                d["usage_count"] = 0
                d["usage_files"] = []
                d["used_apis"] = []
        else:
            d["usage_count"] = -1
            d["usage_files"] = []
            d["used_apis"] = []

    t1 = time.time()
    print(f"[DepShield Timing] Parse/Dedupe: {t1-t0:.2f}s ({len(deps_to_scan)} unique deps)")

    # Pre-fetch OSV vulnerabilities in batches
    fetch_osv_batch(deps_to_scan)
    t2 = time.time()
    print(f"[DepShield Timing] OSV Batch Lookup: {t2-t1:.2f}s")

    # Pre-fetch NPM metadata in parallel
    unique_names = list(set(d["name"] for d in deps_to_scan))
    if scan_mode == "deep":
        # Deep: fetch metadata for ALL deps
        prefetch_npm_metadata(unique_names)
    else:
        # Quick: only fetch metadata for deps with known vulnerabilities
        risky_names = [d["name"] for d in deps_to_scan
                       if OSV_CACHE.get(f"{d['name']}@{d['version']}", [])]
        # Also fetch for direct deps (depth 1) so we can show outdated info
        direct_names = [d["name"] for d in deps_to_scan if d.get("depth", 1) == 1]
        prefetch_names = list(set(risky_names + direct_names))
        prefetch_npm_metadata(prefetch_names)
    t3 = time.time()
    print(f"[DepShield Timing] NPM Metadata Prefetch: {t3-t2:.2f}s ({len(NPM_CACHE)} cached)")

    # Parallel analysis
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = {executor.submit(_analyze_single, d): d for d in deps_to_scan}
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                dep = futures[future]
                results.append({
                    "name": dep["name"],
                    "version": dep["version"],
                    "latest": dep["version"],
                    "sev": "SAFE",
                    "score": 0,
                    "cves": [],
                    "vulns": 0,
                    "desc": f"Analysis failed: {str(e)}",
                    "updated": "",
                    "maint": "Active",
                    "origin": dep.get("origin", [dep["name"]]),
                    "fix": "",
                    "fixv": dep["version"],
                    "alts": [],
                    "effort": "Easy",
                    "sz": 8,
                    "col": "var(--teal)",
                    "breakage_risk": "LOW",
                    "breakage_reason": ["Analysis failed"],
                    "usage_count": -1,
                    "usage_files": [],
                    "used_apis": [],
                    "impact_level": "LOW",
                    "impact_reason": "Analysis failed",
                    "confidence": "LOW",
                    "reco": "Error during analysis — retry scan.",
                })
    t4 = time.time()
    print(f"[DepShield Timing] Per-Dep Analysis: {t4-t3:.2f}s")

    # Reduce payload size for huge trees
    if len(results) > 500:
        for r in results:
            if r["sev"] == "SAFE" and len(r.get("origin", [])) > 2:
                # Strip unnecessary big fields for safe transitive deps
                r["desc"] = ""
                r["alts"] = []
                r["reco"] = ""

    # Sort: critical first, then by score descending
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "SAFE": 4}
    results.sort(key=lambda d: (sev_order.get(d["sev"], 5), -d["score"]))

    # Assign sequential IDs
    for i, r in enumerate(results):
        r["id"] = i + 1

    t5 = time.time()
    print(f"[DepShield Timing] Sort/Finalize: {t5-t4:.4f}s")
    print(f"[DepShield Timing] --- Analyzer Total: {t5-t0:.2f}s (mode={scan_mode}) ---")
    print(results)
    return results
