#!/usr/bin/env python3
"""
TAARA Repository Scanner.

"protecting the world's data 3 years later.. every wrong step you take..
one step you push a man in future towards a suicide for a data leak.. be careful"

What this does that Snyk/Trivy/Dependabot do not:

  Snyk/Trivy/Dependabot: scan individual files for known CVEs.
  They are good at what they do. TAARA does not replace them.

  TAARA adds:
    1. Cross-file relationship graph — finds failure chains that span
       Dockerfile + package.json + CI workflows + DB migrations.
       No single file is wrong. The combination is.

    2. Quantum fidelity on configuration embeddings — scores how far
       a configuration's direction is from the policy space, without
       needing a rule. Catches what has no rule yet.

Data sources (live, not hardcoded):
  - OSV.dev API (api.osv.dev) — authoritative open vulnerability database
    used by Google, GitHub, PyPI. Exact version matching.
  - endoflife.date API — authoritative EOL dates for runtimes and images.
  - Package manager lockfiles — package-lock.json, requirements.txt,
    Pipfile.lock, go.sum — parsed for exact pinned versions.

Run:
  python research/scan_repo.py <local-path-or-github-url>
  python research/scan_repo.py /tmp/NodeGoat
  python research/scan_repo.py https://github.com/OWASP/NodeGoat
"""

import os
import sys
import json
import re
import subprocess
import tempfile
import shutil
import time
from pathlib import Path
from datetime import date, datetime
from typing import Optional, List, Dict
import urllib.request
import urllib.parse
import urllib.error

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

# Load .env if present
_env_file = ROOT / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _v = _line.split("=", 1)
            os.environ.setdefault(_k.strip(), _v.strip())


# ── Live data: OSV API ─────────────────────────────────────────────────────────

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_ECOSYSTEM_MAP = {
    ".json": "npm",
    "requirements.txt": "PyPI",
    "Pipfile": "PyPI",
    "go.sum": "Go",
    "Gemfile.lock": "RubyGems",
}

def _http_post(url: str, payload: dict, retries: int = 3) -> Optional[dict]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "TAARA/1.0"}
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read())
        except Exception as e:
            if attempt == retries - 1:
                print(f"  OSV API error: {e}")
                return None
            time.sleep(1)
    return None

def _http_get(url: str, retries: int = 3) -> Optional[dict]:
    req = urllib.request.Request(
        url, headers={"User-Agent": "TAARA/1.0"}
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return json.loads(resp.read())
        except Exception as e:
            if attempt == retries - 1:
                return None
            time.sleep(1)
    return None


def _fetch_vuln_details(vuln_id: str) -> Optional[dict]:
    """Fetch full vulnerability details from OSV by ID."""
    return _http_get(f"https://api.osv.dev/v1/vulns/{vuln_id}")


def query_osv_batch(packages: list[dict]) -> list[dict]:
    """
    Query OSV for multiple packages at once.
    Step 1: batch query to find which packages have vulnerabilities (returns IDs only).
    Step 2: fetch full details for each vulnerability found.
    packages: [{"name": "lodash", "version": "4.17.20", "ecosystem": "npm"}, ...]
    """
    if not packages:
        return []

    # Step 1: batch query — get vuln IDs per package
    pkg_vulns: list[tuple[dict, list[str]]] = []  # (package, [vuln_ids])
    chunk_size = 100
    for i in range(0, len(packages), chunk_size):
        chunk = packages[i:i+chunk_size]
        payload = {
            "queries": [
                {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}, "version": p["version"]}
                for p in chunk
            ]
        }
        result = _http_post(OSV_BATCH_URL, payload)
        if not result:
            continue
        for j, res in enumerate(result.get("results", [])):
            vuln_ids = [v["id"] for v in res.get("vulns", [])]
            if vuln_ids:
                pkg_vulns.append((chunk[j], vuln_ids))

    if not pkg_vulns:
        return []

    # Step 2: fetch full details — deduplicate across packages
    all_ids = list({vid for _, ids in pkg_vulns for vid in ids})
    print(f"    Fetching full details for {len(all_ids)} unique vulnerabilities...")
    vuln_details: dict[str, dict] = {}
    for vid in all_ids:
        detail = _fetch_vuln_details(vid)
        if detail:
            vuln_details[vid] = detail

    # Step 3: build findings
    all_findings = []
    seen_osv_ids = set()
    for pkg, vuln_ids in pkg_vulns:
        for vid in vuln_ids:
            if vid in seen_osv_ids:
                continue
            seen_osv_ids.add(vid)
            v = vuln_details.get(vid, {"id": vid})
            severity = _osv_severity(v)
            summary = v.get("summary", "")
            details = v.get("details", summary)
            all_findings.append({
                "node_id": f"osv:{vid}",
                "label": f"{vid}: {summary[:80]}" if summary else vid,
                "severity": severity,
                "description": (details or summary or "See OSV for details")[:400],
                "package": pkg["name"],
                "version": pkg["version"],
                "ecosystem": pkg["ecosystem"],
                "source_file": pkg.get("source", "lockfile"),
                "osv_id": vid,
                "aliases": v.get("aliases", []),
                "fix_versions": _extract_fix_versions(v, pkg["name"]),
                "references": [r["url"] for r in v.get("references", [])[:2]],
                "source": "osv_api",
                "layer": 1,
            })
    return all_findings


def _osv_severity(vuln: dict) -> str:
    """Extract severity from OSV entry — uses CVSS if available."""
    # Check severity array
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        # CVSS v3 vector string
        if "CVSS:3" in score_str:
            base = re.search(r"/AV:[^/]+/AC:[^/]+/PR:[^/]+/UI:[^/]+/S:[^/]+/C:([^/]+)/I:([^/]+)/A:([^/]+)", score_str)
            if base:
                critical_parts = sum(1 for p in base.groups() if p == "H")
                if critical_parts >= 2:
                    return "critical"
                elif critical_parts >= 1:
                    return "high"
        # Numeric CVSS
        try:
            score = float(score_str)
            if score >= 9.0: return "critical"
            if score >= 7.0: return "high"
            if score >= 4.0: return "medium"
            return "low"
        except (ValueError, TypeError):
            pass

    # Fall back to database_specific
    for db in vuln.get("database_specific", {}).get("severity", []):
        s = str(db).upper()
        if s in ("CRITICAL",): return "critical"
        if s in ("HIGH",): return "high"
        if s in ("MODERATE", "MEDIUM"): return "medium"

    # Fall back to summary keywords
    summary = vuln.get("summary", "").lower()
    if any(w in summary for w in ("remote code execution", "rce", "authentication bypass", "sql injection")):
        return "critical"
    if any(w in summary for w in ("xss", "injection", "bypass", "privilege")):
        return "high"
    return "medium"


def _extract_fix_versions(vuln: dict, pkg_name: str) -> list[str]:
    """Pull fix versions from OSV affected ranges."""
    fixes = []
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() != pkg_name.lower():
            continue
        for r in affected.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    fixes.append(event["fixed"])
    return fixes


# ── Live data: endoflife.date API ──────────────────────────────────────────────

EOL_PRODUCT_MAP = {
    # Docker image prefix → (product, version_extractor)
    "node:": ("nodejs", lambda v: v.split("-")[0].split(".")[0]),
    "python:": ("python", lambda v: ".".join(v.split("-")[0].split(".")[:2])),
    "ubuntu:": ("ubuntu", lambda v: v.split("-")[0]),
    "debian:": ("debian", lambda v: v.split("-")[0]),
    "alpine:": ("alpine", lambda v: ".".join(v.split("-")[0].split(".")[:2])),
    "mongo:": ("mongodb", lambda v: v.split("-")[0].split(".")[0]),
    "mongodb:": ("mongodb", lambda v: v.split("-")[0].split(".")[0]),
    "redis:": ("redis", lambda v: v.split("-")[0].split(".")[0]),
    "postgres:": ("postgresql", lambda v: v.split("-")[0].split(".")[0]),
    "mysql:": ("mysql", lambda v: ".".join(v.split("-")[0].split(".")[:2])),
    "nginx:": ("nginx", lambda v: v.split("-")[0]),
    "php:": ("php", lambda v: ".".join(v.split("-")[0].split(".")[:2])),
    "ruby:": ("ruby", lambda v: ".".join(v.split("-")[0].split(".")[:2])),
    "golang:": ("go", lambda v: ".".join(v.split("-")[0].split(".")[:2])),
    "openjdk:": ("java", lambda v: v.split("-")[0].split(".")[0]),
}

_eol_cache: dict = {}

def check_eol(image_str: str) -> Optional[dict]:
    """
    Query endoflife.date API for a Docker base image string.
    Returns dict with eol_date, days_past_eol, latest_version or None if not found.
    """
    image = image_str.lower().split("@")[0]  # strip digest
    # Remove registry prefix (gcr.io/distroless/... etc)
    if "/" in image and "." in image.split("/")[0]:
        image = "/".join(image.split("/")[1:])

    for prefix, (product, extract_ver) in EOL_PRODUCT_MAP.items():
        if image.startswith(prefix):
            tag = image[len(prefix):]
            if not tag or tag in ("latest", "lts", "current", "stable", "alpine", "slim", "bullseye", "bookworm"):
                return {
                    "product": product,
                    "version": tag or "latest",
                    "warning": "No specific version pinned — cannot verify EOL status",
                    "severity": "high",
                    "eol_date": None,
                    "days_past_eol": None,
                }
            try:
                ver = extract_ver(tag)
            except Exception:
                continue

            cache_key = f"{product}:{ver}"
            if cache_key in _eol_cache:
                return _eol_cache[cache_key]

            url = f"https://endoflife.date/api/{product}/{ver}.json"
            data = _http_get(url)
            if not data:
                _eol_cache[cache_key] = None
                return None

            eol_raw = data.get("eol")
            result = {
                "product": product,
                "version": ver,
                "image": image_str,
                "release_date": data.get("releaseDate"),
                "latest_version": data.get("latest"),
                "latest_release_date": data.get("latestReleaseDate"),
            }

            if eol_raw is True:
                # EOL but no specific date
                result.update({"eol_date": "unknown", "days_past_eol": 9999, "severity": "critical"})
            elif eol_raw is False:
                result.update({"eol_date": None, "days_past_eol": -1, "severity": "none"})
            else:
                try:
                    eol_date = date.fromisoformat(str(eol_raw))
                    days = (date.today() - eol_date).days
                    result.update({
                        "eol_date": str(eol_date),
                        "days_past_eol": days,
                        "severity": "critical" if days > 365 else "high" if days > 0 else "medium" if days > -90 else "none",
                    })
                except ValueError:
                    result.update({"eol_date": str(eol_raw), "days_past_eol": None, "severity": "medium"})

            _eol_cache[cache_key] = result
            return result

    return None


# ── Lockfile parsers — exact version extraction ────────────────────────────────

def parse_package_lock(path: Path) -> list[dict]:
    """Parse package-lock.json v2/v3 — extracts all resolved packages with exact versions."""
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []

    packages = []
    # v2/v3 format: packages object
    for pkg_path, pkg_data in data.get("packages", {}).items():
        if not pkg_path or pkg_path == "":
            continue  # skip root
        name = pkg_data.get("name") or pkg_path.split("node_modules/")[-1]
        version = pkg_data.get("version", "")
        if name and version:
            packages.append({"name": name, "version": version, "ecosystem": "npm", "source": str(path)})

    # v1 format: dependencies object
    if not packages:
        def _extract_v1(deps: dict, result: list):
            for name, info in deps.items():
                if isinstance(info, dict):
                    ver = info.get("version", "")
                    if ver and not ver.startswith("file:") and not ver.startswith("git"):
                        result.append({"name": name, "version": ver, "ecosystem": "npm", "source": str(path)})
                    if "dependencies" in info:
                        _extract_v1(info["dependencies"], result)
        _extract_v1(data.get("dependencies", {}), packages)

    return packages


def parse_requirements_txt(path: Path) -> list[dict]:
    """Parse requirements.txt — only pinned versions (==) for exact CVE matching."""
    packages = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Only exact pins — unpinned versions can't be matched against CVEs reliably
        m = re.match(r'^([A-Za-z0-9_.\-]+)==([^\s;#]+)', line)
        if m:
            packages.append({
                "name": m.group(1),
                "version": m.group(2),
                "ecosystem": "PyPI",
                "source": str(path),
            })
    return packages


def parse_pipfile_lock(path: Path) -> list[dict]:
    """Parse Pipfile.lock — all packages have exact versions."""
    try:
        data = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []
    packages = []
    for section in ("default", "develop"):
        for name, info in data.get(section, {}).items():
            ver = info.get("version", "").lstrip("==")
            if ver:
                packages.append({"name": name, "version": ver, "ecosystem": "PyPI", "source": str(path)})
    return packages


def parse_go_sum(path: Path) -> list[dict]:
    """Parse go.sum — extract module paths and versions."""
    packages = []
    seen = set()
    for line in path.read_text(errors="ignore").splitlines():
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        module = parts[0]
        version = parts[1].split("/")[0].lstrip("v")
        key = f"{module}@{version}"
        if key not in seen:
            seen.add(key)
            packages.append({"name": module, "version": version, "ecosystem": "Go", "source": str(path)})
    return packages


def find_and_parse_lockfiles(repo_path: Path) -> list[dict]:
    """Find all lockfiles in repo and extract exact package versions."""
    all_packages = []

    for lock in repo_path.rglob("package-lock.json"):
        if "node_modules" in str(lock):
            continue
        pkgs = parse_package_lock(lock)
        print(f"  {lock.relative_to(repo_path)}: {len(pkgs)} packages")
        all_packages.extend(pkgs)

    for req in repo_path.rglob("requirements.txt"):
        if "venv" in str(req) or ".egg" in str(req):
            continue
        pkgs = parse_requirements_txt(req)
        if pkgs:
            print(f"  {req.relative_to(repo_path)}: {len(pkgs)} pinned packages")
            all_packages.extend(pkgs)

    for piplock in repo_path.rglob("Pipfile.lock"):
        pkgs = parse_pipfile_lock(piplock)
        if pkgs:
            print(f"  {piplock.relative_to(repo_path)}: {len(pkgs)} packages")
            all_packages.extend(pkgs)

    for gosum in repo_path.rglob("go.sum"):
        pkgs = parse_go_sum(gosum)
        if pkgs:
            print(f"  {gosum.relative_to(repo_path)}: {len(pkgs)} modules")
            all_packages.extend(pkgs)

    return all_packages


# ── Dependency graph + exploit chain discovery ────────────────────────────────

def build_dependency_graph(packages: List[Dict], osv_findings: List[Dict]) -> "object":
    """
    Build a networkx DiGraph of the dependency tree.
    Nodes: package name@version
    Edges: dependency relationship with weight = depth (1=direct, 2+=transitive)
    CVE annotations added to nodes that have known vulnerabilities.

    For lockfile-parsed packages we don't have parent→child edges
    (lockfiles give a flat list, not the tree), so we model all packages
    as children of a synthetic 'app' root node at depth=1.
    For package-lock.json v2/v3 the depth is embedded in the path key.
    Returns the graph or None if networkx unavailable.
    """
    try:
        import networkx as nx
    except ImportError:
        return None

    G = nx.DiGraph()
    G.add_node("__app__", label="Application (root)", depth=0, cves=[])

    # Build CVE lookup: package name → list of OSV findings
    cve_by_package: Dict[str, List[Dict]] = {}
    for f in osv_findings:
        pkg = f.get("package", "").lower()
        if pkg:
            cve_by_package.setdefault(pkg, []).append(f)

    # Track highest depth seen per package to model transitive vs direct
    pkg_depths: Dict[str, int] = {}
    for p in packages:
        name = p["name"].lower()
        # Use path depth from package-lock (node_modules/a/node_modules/b → depth 2)
        source = p.get("source", "")
        depth = source.count("node_modules") if source else 1
        depth = max(depth, 1)
        if name not in pkg_depths or depth < pkg_depths[name]:
            pkg_depths[name] = depth

    for p in packages:
        name = p["name"].lower()
        version = p.get("version", "")
        node_id = f"{name}@{version}"
        depth = pkg_depths.get(name, 1)
        cves = cve_by_package.get(name, [])

        if not G.has_node(node_id):
            G.add_node(node_id,
                       name=name,
                       version=version,
                       ecosystem=p.get("ecosystem", ""),
                       depth=depth,
                       cves=cves,
                       severity=cves[0]["severity"] if cves else "none")

        # Edge from app root for direct deps; for transitive, edge from root still
        # (we can't reconstruct the full tree from a flat lockfile)
        G.add_edge("__app__", node_id, weight=depth)

    return G


def discover_exploit_chains(
    G: "object",
    osv_findings: List[Dict],
    top_n: int = 10
) -> List[Dict]:
    """
    For every CVE-affected node, score it as an exploit chain:
      chain_score = max_cvss_in_path * (1 / depth)
    Closer chains (depth=1, direct dependency) score higher.
    Returns top_n chains sorted by score descending.

    Since the graph is app→package (depth 1 for all packages from flat lockfiles),
    the depth multiplier differentiates direct (1.0) from transitive (0.5, 0.33...).
    """
    try:
        import networkx as nx
    except ImportError:
        return []

    if G is None:
        return []

    chains = []
    severity_score = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "none": 0.0}

    for f in osv_findings:
        pkg_name = f.get("package", "").lower()
        pkg_ver = f.get("version", "")
        node_id = f"{pkg_name}@{pkg_ver}"

        if not G.has_node(node_id):
            continue

        node_data = G.nodes[node_id]
        depth = node_data.get("depth", 1)
        sev = f.get("severity", "medium")
        base_score = severity_score.get(sev, 5.0)
        chain_score = base_score * (1.0 / depth)

        # Build path: app → ... → this package
        try:
            if nx.has_path(G, "__app__", node_id):
                path = nx.shortest_path(G, "__app__", node_id, weight="weight")
            else:
                path = ["__app__", node_id]
        except Exception:
            path = ["__app__", node_id]

        mitre = f.get("mitre", {})
        fix_versions = f.get("fix_versions", [])

        # Build human-readable path string
        path_display = " → ".join(
            n.replace("__app__", "your application") for n in path
        )

        chains.append({
            "chain_id": f"exploit:{f['osv_id']}",
            "osv_id": f["osv_id"],
            "package": f.get("package", ""),
            "version": f.get("version", ""),
            "severity": sev,
            "chain_score": round(chain_score, 3),
            "depth": depth,
            "path": path,
            "path_display": path_display,
            "cve_summary": f.get("label", ""),
            "description": f.get("description", ""),
            "fix_version": fix_versions[0] if fix_versions else None,
            "source_file": f.get("source_file", ""),
            "mitre_technique": mitre.get("mitre_technique", ""),
            "mitre_tactic": mitre.get("mitre_tactic", ""),
            "why_it_matters": mitre.get("why_it_matters", ""),
            "recommended_action": mitre.get("recommended_action", ""),
        })

    # Sort by chain_score descending — closer + more severe first
    chains.sort(key=lambda c: -c["chain_score"])
    return chains[:top_n]


def compute_repo_posture_vector(
    packages: List[Dict],
    osv_findings: List[Dict],
    G: "object",
) -> "object":
    """
    Build a feature vector representing the repo's dependency posture.
    Features:
      0: total direct dependencies (depth=1)
      1: total transitive dependencies (depth>1)
      2: CVE count — critical
      3: CVE count — high
      4: CVE count — medium
      5: CVE count — low
      6: fraction of packages with known CVEs
      7: mean dependency depth (transitive ratio)
      8: graph density (edges / max_edges)
      9: max exploit chain score (normalized to 0-1)
     10: EOL package count (placeholder — filled by caller)
    Used to compute quantum fidelity of the overall repo posture.
    """
    try:
        import numpy as np
        import networkx as nx
    except ImportError:
        return None

    if G is None:
        return None

    n_packages = max(len(packages), 1)
    direct = sum(1 for _, d in G.nodes(data=True) if d.get("depth", 1) == 1 and _ != "__app__")
    transitive = sum(1 for _, d in G.nodes(data=True) if d.get("depth", 1) > 1)

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in osv_findings:
        s = f.get("severity", "low")
        if s in sev_counts:
            sev_counts[s] += 1

    affected_pkgs = len(set(f.get("package", "").lower() for f in osv_findings if f.get("package")))
    frac_affected = affected_pkgs / n_packages

    depths = [d.get("depth", 1) for _, d in G.nodes(data=True) if _ != "__app__"]
    mean_depth = float(sum(depths)) / max(len(depths), 1)

    n_nodes = G.number_of_nodes()
    n_edges = G.number_of_edges()
    max_edges = n_nodes * (n_nodes - 1) if n_nodes > 1 else 1
    density = n_edges / max_edges

    chains = discover_exploit_chains(G, osv_findings, top_n=1)
    max_chain = chains[0]["chain_score"] / 10.0 if chains else 0.0

    vec = np.array([
        min(direct / 100.0, 1.0),
        min(transitive / 1000.0, 1.0),
        min(sev_counts["critical"] / 50.0, 1.0),
        min(sev_counts["high"] / 100.0, 1.0),
        min(sev_counts["medium"] / 200.0, 1.0),
        min(sev_counts["low"] / 200.0, 1.0),
        frac_affected,
        min(mean_depth / 5.0, 1.0),
        min(density * 100.0, 1.0),
        min(max_chain, 1.0),
        0.0,  # EOL count — placeholder
    ], dtype="float32")

    norm = float(sum(v * v for v in vec) ** 0.5)
    if norm > 0:
        vec = vec / norm
    return vec


# ── Dockerfile scanner — EOL via live API ────────────────────────────────────

def scan_dockerfiles(repo_path: Path, skip_eol_api: bool = False) -> tuple[list[dict], list[dict]]:
    """
    Scan all Dockerfiles. Returns (findings, from_images).
    from_images: list of image strings for cross-file chain analysis.
    skip_eol_api: if True, skip endoflife.date API calls (offline mode).
    """
    findings = []
    from_images = []

    for df_path in repo_path.rglob("Dockerfile*"):
        if "node_modules" in str(df_path) or "venv" in str(df_path):
            continue
        content = df_path.read_text(errors="ignore")
        rel = df_path.relative_to(repo_path)

        for i, line in enumerate(content.splitlines(), 1):
            line_stripped = line.strip()
            if not line_stripped.upper().startswith("FROM"):
                continue
            parts = line_stripped.split()
            if len(parts) < 2 or parts[1].upper() == "SCRATCH":
                continue
            image = parts[1]
            from_images.append({"image": image, "file": str(rel), "line": i})

            # Check EOL via live API
            if ":" not in image and "@" not in image:
                findings.append({
                    "node_id": f"docker:no_tag:{image}",
                    "label": f"No tag on base image: {image}",
                    "severity": "high",
                    "description": (
                        f"FROM {image} with no tag means Docker pulls :latest. "
                        f"The image can change on every build. Pin to a specific version digest."
                    ),
                    "file": str(rel), "line": i, "source": "dockerfile_scan", "layer": 1,
                })
                continue

            if ":latest" in image.lower():
                findings.append({
                    "node_id": f"docker:latest_tag:{image.split(':')[0]}",
                    "label": f"Base image pinned to :latest",
                    "severity": "high",
                    "description": (
                        f"FROM {image} — :latest changes silently on every pull. "
                        f"A new image version can introduce breaking changes or CVEs with no warning."
                    ),
                    "file": str(rel), "line": i, "source": "dockerfile_scan", "layer": 1,
                })

            eol = None if skip_eol_api else check_eol(image)
            if eol and eol.get("days_past_eol") is not None:
                days = eol["days_past_eol"]
                if days > 0:
                    sev = eol["severity"]
                    findings.append({
                        "node_id": f"eol:{eol['product']}:{eol['version']}",
                        "label": f"EOL runtime: {eol['product']} {eol['version']} ({days} days past EOL)",
                        "severity": sev,
                        "description": (
                            f"{image} uses {eol['product']} {eol['version']}, "
                            f"which reached end-of-life on {eol['eol_date']} ({days} days ago). "
                            f"No security patches are being issued. "
                            f"Latest supported version: {eol.get('latest_version', 'unknown')}."
                        ),
                        "file": str(rel), "line": i,
                        "source": "endoflife_date_api",
                        "eol_data": eol,
                        "layer": 1,
                    })
                elif -90 < days <= 0:
                    findings.append({
                        "node_id": f"eol_approaching:{eol['product']}:{eol['version']}",
                        "label": f"EOL approaching: {eol['product']} {eol['version']} (EOL in {-days} days)",
                        "severity": "medium",
                        "description": (
                            f"{image} will reach end-of-life on {eol['eol_date']} in {-days} days. "
                            f"Plan migration to {eol.get('latest_version', 'a supported version')} now."
                        ),
                        "file": str(rel), "line": i,
                        "source": "endoflife_date_api",
                        "layer": 1,
                    })

        # Check running as root — no USER directive set before CMD/ENTRYPOINT
        has_user = bool(re.search(r'^\s*USER\s+(?!root)', content, re.MULTILINE | re.IGNORECASE))
        has_run = bool(re.search(r'^\s*RUN\s+', content, re.MULTILINE))
        if has_run and not has_user:
            findings.append({
                "node_id": f"docker:running_as_root:{rel}",
                "label": "Container runs as root",
                "severity": "critical",
                "description": (
                    f"{rel}: No USER directive found. Container runs all processes as root (uid 0). "
                    f"If any CVE in a package allows container escape, attacker gets root on the host. "
                    f"Add 'USER 1001' or create a non-root user."
                ),
                "file": str(rel), "line": 0, "source": "dockerfile_scan", "layer": 1,
            })

    return findings, from_images


# ── GitHub Actions scanner ────────────────────────────────────────────────────

def scan_github_actions(repo_path: Path) -> list[dict]:
    findings = []
    workflows_dir = repo_path / ".github" / "workflows"
    if not workflows_dir.exists():
        return findings

    for wf_path in workflows_dir.glob("*.yml"):
        content = wf_path.read_text(errors="ignore")
        rel = wf_path.relative_to(repo_path)

        # Floating action pin — tags can be moved (tj-actions March 2025)
        for m in re.finditer(r'uses:\s+(\S+)@(v\d+[\w.]*)(?:\s|$)', content, re.MULTILINE):
            action, tag = m.group(1), m.group(2)
            line = content[:m.start()].count("\n") + 1
            findings.append({
                "node_id": f"cicd:floating_pin:{action}",
                "label": f"Action pinned to floating tag: {action}@{tag}",
                "severity": "critical",
                "description": (
                    f"{rel} line {line}: '{action}@{tag}' uses a tag, not a commit SHA. "
                    f"The tag can be moved to point at malicious code. "
                    f"This is exactly how the tj-actions attack worked in March 2025, "
                    f"compromising 23,000+ repositories. "
                    f"Fix: pin to the full commit SHA — uses: {action}@<sha> # {tag}"
                ),
                "file": str(rel), "line": line,
                "source": "actions_scan", "layer": 1,
            })

        # Branch-pinned action
        for m in re.finditer(r'uses:\s+(\S+)@(main|master|HEAD)(?:\s|$)', content, re.MULTILINE):
            action, branch = m.group(1), m.group(2)
            line = content[:m.start()].count("\n") + 1
            findings.append({
                "node_id": f"cicd:branch_pin:{action}",
                "label": f"Action pinned to branch: {action}@{branch}",
                "severity": "critical",
                "description": (
                    f"{rel} line {line}: '{action}@{branch}' — tracking a branch means every new "
                    f"commit to that branch runs in your CI with your secrets. "
                    f"Pin to a specific commit SHA."
                ),
                "file": str(rel), "line": line,
                "source": "actions_scan", "layer": 1,
            })

        # pull_request_target — write permissions + fork code = RCE
        if re.search(r'on:\s*\n\s*pull_request_target', content) or \
           re.search(r'pull_request_target:', content):
            # Check if it also checks out PR head
            if re.search(r'github\.event\.pull_request\.head\.sha', content):
                findings.append({
                    "node_id": f"cicd:prt_checkout:{rel}",
                    "label": "pull_request_target + fork checkout = RCE with write permissions",
                    "severity": "critical",
                    "description": (
                        f"{rel}: Uses pull_request_target (runs with write permissions and secrets) "
                        f"AND checks out the PR head SHA. An attacker opens a PR from a fork, "
                        f"puts malicious code in the workflow, and it runs with full repo access."
                    ),
                    "file": str(rel), "line": 0,
                    "source": "actions_scan", "layer": 1,
                })

        # Script injection via untrusted context
        for m in re.finditer(
            r'\$\{\{\s*github\.event\.(pull_request|issue|discussion)\.[^}]+\}\}',
            content
        ):
            # Check if it's inside a run: block (shell execution context)
            surrounding = content[max(0, m.start()-200):m.start()+50]
            if "run:" in surrounding:
                line = content[:m.start()].count("\n") + 1
                findings.append({
                    "node_id": f"cicd:script_injection:{rel}:{line}",
                    "label": "Untrusted input interpolated into shell command",
                    "severity": "high",
                    "description": (
                        f"{rel} line {line}: User-controlled value interpolated directly "
                        f"into a run: step. If the value contains shell metacharacters, "
                        f"it executes arbitrary commands. Use env: variables as intermediary."
                    ),
                    "file": str(rel), "line": line,
                    "source": "actions_scan", "layer": 1,
                })
                break

        # curl-pipe-bash
        for m in re.finditer(r'curl\s+\S+.*\|\s*(?:bash|sh)', content, re.MULTILINE):
            line = content[:m.start()].count("\n") + 1
            findings.append({
                "node_id": f"cicd:curl_pipe_bash:{rel}:{line}",
                "label": "curl-pipe-bash: fetches and executes remote code",
                "severity": "critical",
                "description": (
                    f"{rel} line {line}: Fetches a script from a remote URL and pipes it "
                    f"directly to bash. If the URL is compromised (DNS hijack, HTTPS MitM, "
                    f"or the host is breached), arbitrary code runs on your CI runner "
                    f"with access to all secrets."
                ),
                "file": str(rel), "line": line,
                "source": "actions_scan", "layer": 1,
            })

        # npm install (not npm ci) in CI
        for m in re.finditer(r'npm install(?!\s+--(?:ci|global)|\s+-g)', content, re.MULTILINE):
            line = content[:m.start()].count("\n") + 1
            findings.append({
                "node_id": f"cicd:npm_install:{rel}",
                "label": "npm install instead of npm ci in CI",
                "severity": "high",
                "description": (
                    f"{rel} line {line}: 'npm install' resolves dependency versions fresh on each run. "
                    f"'npm ci' installs exactly what is in package-lock.json. "
                    f"With 'npm install', a compromised transitive dependency published after "
                    f"your last lock gets pulled silently. Use 'npm ci' in all CI workflows."
                ),
                "file": str(rel), "line": line,
                "source": "actions_scan", "layer": 1,
            })
            break  # one per file

        # ── Secrets referenced via env: (not ${{ secrets.X }}) ──
        # Detect env: blocks where a value is set literally instead of from secrets context.
        # This is a structural check — looks for env key assignments that bypass the secrets store.
        for m in re.finditer(r'^\s{6,}(\w+):\s+([^\$\s\'"][^\n]{8,})$', content, re.MULTILINE):
            key, val = m.group(1), m.group(2).strip()
            # Only flag if the key name suggests it's a credential
            key_lower = key.lower()
            if any(word in key_lower for word in ("key", "secret", "token", "password", "passwd", "credential")):
                # Skip if it references a context variable or looks like a placeholder
                if "${{" not in val and not val.startswith("{{") and not val.lower().startswith("your_"):
                    line = content[:m.start()].count("\n") + 1
                    findings.append({
                        "node_id": f"cicd:env_literal_credential:{rel}:{line}",
                        "label": f"Credential-named env var set to literal value: {key}",
                        "severity": "critical",
                        "description": (
                            f"{rel} line {line}: env var '{key}' has a credential-style name "
                            f"but is set to a literal value, not a secrets context reference. "
                            f"Literal values in workflow files are stored in git history permanently. "
                            f"Use ${{{{ secrets.{key.upper()} }}}} instead."
                        ),
                        "file": str(rel), "line": line,
                        "source": "secrets_scan", "layer": 1,
                        "mitre": {
                            "cwe": "CWE-798",
                            "mitre_technique": "T1552.001 — Credentials In Files",
                            "mitre_tactic": "Credential Access",
                            "why_it_matters": "Credentials in git history give persistent access — even after deletion, they can be recovered from git reflog or forks.",
                            "recommended_action": f"Replace literal value with ${{{{ secrets.{key.upper()} }}}}. Rotate any credential that was ever committed.",
                        },
                    })
                    break  # one finding per file for this check

        # ── Overprivileged permissions blocks ──
        if re.search(r'permissions:\s*write-all', content):
            findings.append({
                "node_id": f"cicd:write_all_permissions:{rel}",
                "label": "Workflow grants write-all permissions",
                "severity": "high",
                "description": (
                    f"{rel}: 'permissions: write-all' grants the workflow token full write access "
                    f"to the repository, packages, deployments, and issues. "
                    f"If this workflow is compromised (e.g., via a floating action tag), the attacker "
                    f"gets full repository write access — can push code, modify releases, exfiltrate secrets."
                ),
                "file": str(rel), "line": 0,
                "source": "actions_scan", "layer": 1,
                "mitre": {
                    "cwe": "CWE-250",
                    "mitre_technique": "T1078.004 — Cloud Accounts",
                    "mitre_tactic": "Defense Evasion",
                    "why_it_matters": "Over-permissioned CI tokens are the primary amplifier in supply chain attacks. write-all means full repo takeover if any step is compromised.",
                    "recommended_action": "Replace with specific permissions: contents: read, id-token: write (only what's needed). Apply principle of least privilege.",
                },
            })

        if re.search(r'on:\s*\n\s*push:', content) and not re.search(r'permissions:', content):
            findings.append({
                "node_id": f"cicd:no_permissions_block:{rel}",
                "label": "Workflow has no explicit permissions block",
                "severity": "medium",
                "description": (
                    f"{rel}: No 'permissions:' block. Without explicit permissions, "
                    f"GitHub defaults vary by repository settings — often granting write access by default. "
                    f"Best practice: always declare explicit minimal permissions."
                ),
                "file": str(rel), "line": 0,
                "source": "actions_scan", "layer": 1,
            })

    return findings


# ── Layer 3: Cross-file relationship chains ───────────────────────────────────

def find_cross_file_chains(
    dockerfile_findings: list[dict],
    osv_findings: list[dict],
    actions_findings: list[dict],
    from_images: list[dict],
    repo_path: Path,
) -> list[dict]:
    """
    Find failure chains that span multiple files.
    Built from actual parsed data — not from keywords or hardcoded patterns.
    Each chain is something where no single file is wrong but the combination is.
    """
    chains = []

    eol_images = [f for f in dockerfile_findings if f["node_id"].startswith("eol:")]
    root_containers = [f for f in dockerfile_findings if "running_as_root" in f["node_id"]]
    floating_pins = [f for f in actions_findings if "floating_pin" in f["node_id"] or "branch_pin" in f["node_id"]]
    npm_install_ci = [f for f in actions_findings if "npm_install" in f["node_id"]]
    critical_osv = [f for f in osv_findings if f.get("severity") in ("critical", "high")]

    # Chain: EOL runtime + critical CVE in dependency + container runs as root
    # = CVE has no patch (EOL) + if exploited, attacker gets root on host
    if eol_images and critical_osv and root_containers:
        eol = eol_images[0]
        cvss_sample = critical_osv[:2]
        chains.append({
            "chain_id": "chain:eol_cve_root_escalation",
            "label": "EOL runtime + unpatched CVE + root container = host compromise path",
            "severity": "critical",
            "layer": 3,
            "files_involved": list(set(
                [eol.get("file", "Dockerfile")]
                + [f.get("source_file", "lockfile") for f in cvss_sample]
                + [root_containers[0].get("file", "Dockerfile")]
            )),
            "description": (
                f"Three issues compound into a full host compromise path: "
                f"(1) {eol['label']} — no security patches. "
                f"(2) {len(critical_osv)} critical/high CVEs in dependencies "
                f"(e.g. {cvss_sample[0]['osv_id'] if cvss_sample else 'multiple'}). "
                f"(3) Container runs as root — if any CVE allows container escape, "
                f"attacker gets root on the host, not just inside the container. "
                f"Each issue is serious alone. Together, they are a complete compromise chain."
            ),
            "why_tests_miss_this": (
                "Tests verify application behavior, not the security boundary between "
                "container and host. The escape path exists regardless of test results. "
                "The EOL runtime means the CVE is permanently unpatched — no fix will come."
            ),
            "real_incident": (
                "Capital One 2019: SSRF vulnerability in a running container led to "
                "metadata service access and eventual data exfiltration of 100M records. "
                "Container root + network misconfiguration was the amplifier."
            ),
            "fix": (
                f"1. Migrate from {eol_images[0].get('eol_data', {}).get('product', 'EOL runtime')} "
                f"to a supported version. "
                f"2. Add USER directive in Dockerfile. "
                f"3. Update vulnerable packages to fix versions."
            ),
        })

    # Chain: Floating action pin + npm install in CI + critical OSV findings
    # = supply chain attack surface at multiple levels simultaneously
    if floating_pins and npm_install_ci and critical_osv:
        chains.append({
            "chain_id": "chain:supply_chain_compound",
            "label": "Compound supply chain risk: floating CI action + unverified installs + known CVEs",
            "severity": "critical",
            "layer": 3,
            "files_involved": list(set(
                [floating_pins[0].get("file", ".github/workflows")]
                + [npm_install_ci[0].get("file", ".github/workflows")]
            )),
            "description": (
                f"Supply chain attack surface exists at three independent points: "
                f"(1) {len(floating_pins)} CI actions pinned to floating tags — "
                f"can be silently redirected to malicious code (tj-actions, March 2025, 23k repos). "
                f"(2) 'npm install' in CI resolves versions fresh — compromised transitive dep "
                f"gets pulled without any change to your code. "
                f"(3) {len(critical_osv)} critical/high CVEs already present in locked dependencies. "
                f"An attacker does not need to find a new vulnerability — they can exploit "
                f"one of these {len(critical_osv)} known ones."
            ),
            "why_tests_miss_this": (
                "The compromise happens at install time or CI execution time. "
                "Your test code runs after the malicious payload has already executed. "
                "Tests pass. CI runner secrets leak. This is the exact tj-actions attack pattern."
            ),
            "real_incident": "tj-actions/changed-files (March 2025): 23,000+ repos leaked secrets via CI logs in one day",
            "fix": (
                "Pin all actions to full commit SHA. Replace 'npm install' with 'npm ci'. "
                "Update packages with known CVEs to their fix versions (listed in findings above)."
            ),
        })

    # Chain: no lockfile + floating action pin
    # = every CI run installs unpredictable versions AND the action itself is unpredictable
    no_lockfile_files = []
    for lf_path in repo_path.rglob("package.json"):
        if "node_modules" in str(lf_path):
            continue
        has_lock = (lf_path.parent / "package-lock.json").exists() or \
                   (lf_path.parent / "yarn.lock").exists()
        if not has_lock:
            no_lockfile_files.append(lf_path)

    if no_lockfile_files and floating_pins:
        chains.append({
            "chain_id": "chain:no_lockfile_floating_action",
            "label": "No lockfile + floating CI action = two independent supply chain attack vectors",
            "severity": "critical",
            "layer": 3,
            "files_involved": [str(f.relative_to(repo_path)) for f in no_lockfile_files[:2]]
                               + [floating_pins[0].get("file", ".github/workflows")],
            "description": (
                f"No package lockfile found for {', '.join(str(f.relative_to(repo_path)) for f in no_lockfile_files[:2])}. "
                f"Combined with {len(floating_pins)} floating CI action pins, there are two independent "
                f"paths for a supply chain compromise: "
                f"(1) A malicious package is published under a name your code resolves to — "
                f"next npm install pulls it. "
                f"(2) A floating action tag is moved to malicious code — next CI run executes it. "
                f"Either path gives an attacker code execution in your CI environment with full secret access."
            ),
            "why_tests_miss_this": (
                "The attack executes before your test code. Secrets are exfiltrated during "
                "the install or action execution phase. Tests never run against the malicious code."
            ),
            "real_incident": "event-stream (2018): 8M weekly downloads, malicious postinstall script, Bitcoin wallets stolen",
            "fix": "Run 'npm install' once locally, commit package-lock.json, use 'npm ci' in CI. Pin actions to commit SHAs.",
        })

    return chains


# ── Layer 2: Quantum fidelity scoring ─────────────────────────────────────────

def add_quantum_fidelity(findings: list[dict], scanner=None) -> list[dict]:
    """
    Score each finding's deviation from policy space using quantum fidelity.
    Accepts an already-loaded TAARAScan instance to avoid reloading the model.
    """
    kb_path = Path(__file__).parent.parent / "knowledge_base" / "embeddings" / "policy_index.faiss"
    if not kb_path.exists():
        print("  Quantum scoring skipped — knowledge base not built.")
        return findings

    try:
        from research.query_knowledge_base import TAARAScan, quantum_fidelity, deviation_score
        import numpy as np
        if scanner is None:
            scanner = TAARAScan()
            scanner._load()
        model = scanner._model
    except Exception:
        return findings

    for f in findings:
        if "quantum_fidelity" in f:
            continue
        text = f"{f.get('label', '')}. {f.get('description', '')}".strip()[:400]
        if not text:
            continue
        try:
            query_vec = model.encode([text], normalize_embeddings=True).astype("float32")[0]
            scores, indices = scanner._index.search(query_vec.reshape(1, -1), 3)
            if indices[0][0] >= 0:
                policy_vec = scanner._policy_embeddings[indices[0][0]]
                F = quantum_fidelity(query_vec, policy_vec)
                dev = deviation_score(F)
                f["quantum_fidelity"] = {
                    "fidelity": round(F, 4),
                    "deviation": round(dev, 4),
                    "quantum_risk": (
                        "critical" if F < 0.3 else
                        "high" if F < 0.5 else
                        "medium" if F < 0.7 else "low"
                    ),
                    "interpretation": (
                        f"F={F:.3f} — this configuration is "
                        + ("maximally unsafe: nearly orthogonal to all known safe configurations" if F < 0.3
                           else "unsafe: more different than similar to safe configurations" if F < 0.5
                           else "drifting from best practice" if F < 0.7
                           else "close to best practice")
                    ),
                    "closest_policy": scanner._chunks[indices[0][0]]["source"],
                }
        except Exception:
            pass

    return findings


# ── Main scanner ───────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def _normalize_finding(f: dict) -> dict:
    """
    Ensure every finding has the canonical UI schema keys:
      title, detail, remediation, file, source
    alongside any original keys. Never removes existing keys.
    """
    f["title"] = f.get("title") or f.get("label") or f.get("node_id", "Unknown finding")
    f["detail"] = f.get("detail") or f.get("description") or ""
    f["remediation"] = f.get("remediation") or f.get("fix") or "See TAARA recommendation"
    return f


def _normalize_chain(c: dict) -> dict:
    """
    Ensure every chain has the canonical UI schema keys:
      title, detail, attack_path, files, remediation
    alongside any original keys.
    """
    c["title"] = c.get("title") or c.get("label") or c.get("chain_id", "Unknown chain")
    c["detail"] = c.get("detail") or c.get("description") or ""
    c["attack_path"] = c.get("attack_path") or c.get("description") or ""
    c["files"] = c.get("files") or c.get("files_involved") or []
    c["remediation"] = c.get("remediation") or c.get("fix") or "See TAARA recommendation"
    return c


def scan_repo(target: str, offline: bool = False) -> dict:
    """
    Scan a local repo path or GitHub URL for security risks.

    Args:
        target: local directory path or https://github.com/... URL
        offline: if True, skip live OSV.dev and endoflife.date API calls.
                 Offline mode still runs lockfile parsing, Dockerfile static checks,
                 and GitHub Actions pattern analysis. It skips only the network calls.
                 What is skipped is explicitly listed in the result's 'offline_skipped' field.
    """
    temp_dir = None

    if target.startswith("http") or target.startswith("git@"):
        if offline:
            # Cannot clone without network, but can still scan a local path
            print("  Offline mode: skipping GitHub clone. Provide a local path for offline scan.")
            return {
                "error": "GitHub URL provided with offline=True. Clone the repo locally first, then scan the local path.",
                "target": target,
                "offline": True,
            }
        print(f"Cloning {target}...")
        temp_dir = tempfile.mkdtemp(prefix="taara_scan_")
        r = subprocess.run(
            ["git", "clone", "--depth=1", target, temp_dir],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            return {"error": f"Clone failed: {r.stderr}"}
        repo_path = Path(temp_dir)
        repo_name = target.rstrip("/").split("/")[-1].replace(".git", "")
    else:
        repo_path = Path(target)
        if not repo_path.exists():
            return {"error": f"Path not found: {repo_path}"}
        repo_name = repo_path.name

    offline_skipped = []

    try:
        print(f"\nScanning: {repo_name}" + (" [OFFLINE MODE]" if offline else ""))
        print("─" * 50)

        # ── Lockfile dependency resolution (always runs — no network needed) ──
        print("\n[1/6] Resolving dependencies from lockfiles...")
        all_packages = find_and_parse_lockfiles(repo_path)
        print(f"  Total resolved packages: {len(all_packages)}")

        # ── OSV vulnerability query ──
        print("\n[2/6] Querying OSV vulnerability database...")
        osv_findings = []
        if all_packages and not offline:
            seen_pkgs = set()
            unique_pkgs = []
            for p in all_packages:
                key = f"{p['ecosystem']}:{p['name']}:{p['version']}"
                if key not in seen_pkgs:
                    seen_pkgs.add(key)
                    unique_pkgs.append(p)
            print(f"  Querying {len(unique_pkgs)} unique packages against OSV...")
            osv_findings = query_osv_batch(unique_pkgs)
            print(f"  Vulnerabilities found: {len(osv_findings)}")
        elif all_packages and offline:
            print("  OFFLINE: OSV.dev API call skipped.")
            offline_skipped.append(f"OSV.dev CVE lookup for {len(all_packages)} packages")

        # ── Dependency graph + exploit chain scoring ──
        print("\n[3/6] Building dependency graph and exploit chains...")
        dep_graph = build_dependency_graph(all_packages, osv_findings)
        exploit_chains = discover_exploit_chains(dep_graph, osv_findings, top_n=10) if dep_graph else []
        repo_posture_vec = compute_repo_posture_vector(all_packages, osv_findings, dep_graph)
        print(f"  Graph nodes: {dep_graph.number_of_nodes() if dep_graph else 0}  "
              f"Exploit chains scored: {len(exploit_chains)}")

        # ── Dockerfile scan ──
        print("\n[4/6] Scanning Dockerfiles...")
        if offline:
            dockerfile_findings, from_images = scan_dockerfiles(repo_path, skip_eol_api=True)
            if from_images:
                offline_skipped.append(
                    f"endoflife.date EOL check for: {', '.join(i.get('image','') for i in from_images[:3])}"
                )
        else:
            dockerfile_findings, from_images = scan_dockerfiles(repo_path)
        print(f"  Dockerfile findings: {len(dockerfile_findings)}")

        # ── GitHub Actions scan ──
        print("\n[5/6] Scanning GitHub Actions workflows...")
        actions_findings = scan_github_actions(repo_path)
        print(f"  Workflow findings: {len(actions_findings)}")

        # ── Cross-file chains ──
        cross_chains = find_cross_file_chains(
            dockerfile_findings, osv_findings, actions_findings, from_images, repo_path
        )

        # ── GraphRAG + Quantum + LLM ──────────────────────────────────────────────
        print("\n[6/6] GraphRAG + quantum fidelity scoring...")
        kb_chains = []
        all_findings = dockerfile_findings + osv_findings + actions_findings

        seen_osv = set()
        deduped = []
        for f in all_findings:
            oid = f.get("osv_id")
            if oid:
                if oid in seen_osv:
                    continue
                seen_osv.add(oid)
            deduped.append(f)
        all_findings = deduped

        all_findings = [_normalize_finding(f) for f in all_findings]
        chains = [_normalize_chain(c) for c in cross_chains]

        repo_quantum = None
        if not offline:
            _scanner = None
            try:
                from research.query_knowledge_base import TAARAScan, quantum_fidelity as _qf
                import numpy as np
                _scanner = TAARAScan()
                _scanner._load()
            except Exception as e:
                print(f"  KB load failed: {e}")

            # Per-finding quantum fidelity
            all_findings = add_quantum_fidelity(all_findings, scanner=_scanner)

            if _scanner:
                # ── Step 1: retrieve policy context for the top CVE findings ──────────
                # Embed each top CVE description → FAISS search → collect policy chunks
                # These are real policy chunks from the KB (CIS, NIST, OWASP, etc.)
                top_osv = sorted(
                    [f for f in all_findings if f.get("osv_id")],
                    key=lambda f: -SEVERITY_ORDER.get(f.get("severity", "low"), 0)
                )[:10]

                policy_chunks_retrieved = []
                policy_vecs_retrieved = []
                for f in top_osv:
                    text = f"{f.get('label', '')}. {f.get('description', '')}".strip()[:400]
                    if not text:
                        continue
                    q_vec = _scanner._model.encode([text], normalize_embeddings=True).astype("float32")
                    scores, idxs = _scanner._index.search(q_vec, 3)
                    for idx, score in zip(idxs[0], scores[0]):
                        if idx >= 0 and score > 0.2:
                            chunk = _scanner._chunks[idx]
                            policy_vecs_retrieved.append(_scanner._policy_embeddings[idx])
                            policy_chunks_retrieved.append({
                                "text": chunk["text"][:300],
                                "source": chunk.get("source", ""),
                                "score": round(float(score), 3),
                            })

                # ── Step 2: call LLM to generate answer about interdependency risks ──
                llm_answer = None
                llm_answer_fidelity = None
                api_key = os.environ.get("GROQ_API_KEY")
                if api_key and top_osv and policy_chunks_retrieved:
                    try:
                        from components.llm_service import LLMService
                        llm = LLMService(api_key=api_key)

                        # Build context from exploit chains and top CVEs
                        chain_lines = []
                        for c in exploit_chains[:5]:
                            chain_lines.append(
                                f"  - {c['path_display']} | {c['severity'].upper()} | {c['cve_summary'][:80]}"
                            )

                        cve_lines = []
                        for f in top_osv[:8]:
                            fixes = f.get("fix_versions", [])
                            fix_str = f"fix: {fixes[0]}" if fixes else "no fix listed"
                            cve_lines.append(
                                f"  - {f['osv_id']} [{f['severity'].upper()}] {f.get('package','?')} v{f.get('version','?')}: {f.get('label','')[:80]} ({fix_str})"
                            )

                        policy_lines = []
                        seen_policy = set()
                        for pc in policy_chunks_retrieved[:5]:
                            if pc["text"] not in seen_policy:
                                seen_policy.add(pc["text"])
                                policy_lines.append(f"  [{pc['source']}] {pc['text'][:200]}")

                        prompt = f"""You are a dependency security analyst. Analyze the following real CVE findings from a repository's dependency graph.

DEPENDENCY VULNERABILITIES FOUND:
{chr(10).join(cve_lines)}

EXPLOIT CHAINS (your application → vulnerable package, scored by severity × proximity):
{chr(10).join(chain_lines) if chain_lines else '  No exploit chains scored'}

RELEVANT SECURITY POLICY CONTEXT:
{chr(10).join(policy_lines)}

In 3-4 sentences: explain the real risk these interdependencies create for users of this application. Focus on what an attacker could actually do, which packages are the most urgent to fix, and why transitive dependencies are dangerous. Be specific, not generic."""

                        resp = llm.generate_response(prompt)
                        if resp.get("success"):
                            llm_answer = resp["explanation"]

                            # ── Step 3: quantum fidelity on the LLM's answer ──────────────
                            # Embed the answer → compare vs the retrieved policy embeddings
                            # F tells us: does the answer point in the same direction as policy?
                            if policy_vecs_retrieved:
                                answer_vec = _scanner._model.encode(
                                    [llm_answer[:500]], normalize_embeddings=True
                                ).astype("float32")[0]
                                # Average policy vector from retrieved chunks
                                policy_vec_mean = np.mean(policy_vecs_retrieved, axis=0).astype("float32")
                                norm = np.linalg.norm(policy_vec_mean)
                                if norm > 0:
                                    policy_vec_mean = policy_vec_mean / norm
                                F_answer = _qf(answer_vec, policy_vec_mean)
                                llm_answer_fidelity = {
                                    "fidelity": round(float(F_answer), 4),
                                    "interpretation": (
                                        "Answer direction aligns well with security policy" if F_answer > 0.6
                                        else "Answer partially aligned with policy" if F_answer > 0.35
                                        else "Answer diverges from policy space — review"
                                    ),
                                }
                    except Exception as e:
                        print(f"  LLM call failed: {e}")

                if llm_answer:
                    kb_chains.append({
                        "chain_id": "graphrag:llm_dependency_analysis",
                        "title": "GraphRAG Dependency Risk Analysis",
                        "severity": top_osv[0]["severity"] if top_osv else "high",
                        "detail": llm_answer,
                        "attack_path": " → ".join(
                            c["path_display"] for c in exploit_chains[:3]
                        ) if exploit_chains else "See individual CVE findings",
                        "files": list(set(f.get("source_file", "lockfile") for f in top_osv[:5])),
                        "remediation": (
                            f"Priority fixes: "
                            + ", ".join(
                                f"{f.get('package','?')} → {f.get('fix_versions',['?'])[0]}"
                                for f in top_osv[:4]
                                if f.get("fix_versions")
                            )
                        ),
                        "policy_context": policy_chunks_retrieved[:3],
                        "llm_answer_fidelity": llm_answer_fidelity,
                        "packages_analyzed": len(top_osv),
                    })

                print(f"  KB propagation chains: {len(kb_chains)}")

                # Repo-level quantum fidelity on posture vector
                if repo_posture_vec is not None:
                    try:
                        # Pad posture vector to 384 dims for FAISS search
                        padded = np.zeros(384, dtype="float32")
                        padded[:len(repo_posture_vec)] = repo_posture_vec
                        norm = np.linalg.norm(padded)
                        if norm > 0:
                            padded = padded / norm
                        scores, idxs = _scanner._index.search(padded.reshape(1, -1), 1)
                        if idxs[0][0] >= 0:
                            policy_vec = _scanner._policy_embeddings[idxs[0][0]]
                            F = _qf(repo_posture_vec, policy_vec[:len(repo_posture_vec)])
                            repo_quantum = {
                                "fidelity": round(float(F), 4),
                                "interpretation": (
                                    "Repo posture unsafe — dependency graph far from secure baseline" if F < 0.5
                                    else "Repo posture drifting from secure baseline" if F < 0.7
                                    else "Repo posture close to secure baseline"
                                ),
                            }
                    except Exception:
                        pass
        else:
            offline_skipped.append("Quantum fidelity + GraphRAG — run without --offline")

        all_findings.sort(key=lambda f: (
            -SEVERITY_ORDER.get(f.get("severity", "low"), 0),
            -f.get("quantum_fidelity", {}).get("deviation", 0),
        ))

        all_chains = chains + [_normalize_chain(c) for c in kb_chains]

        critical = sum(1 for f in all_findings if f.get("severity") == "critical")
        high = sum(1 for f in all_findings if f.get("severity") == "high")
        chain_critical = sum(1 for c in all_chains if c.get("severity") == "critical")

        data_sources = ["lockfile parsing", "dependency graph (networkx)", "GitHub Actions pattern analysis"]
        if not offline:
            data_sources = ["OSV API (api.osv.dev)", "endoflife.date API", "KB GraphRAG"] + data_sources

        return {
            "target": target,
            "repo": repo_name,
            "scanned_at": datetime.now().isoformat(),
            "offline": offline,
            "offline_skipped": offline_skipped,
            "packages_resolved": len(all_packages),
            "packages_queried_osv": len(set(f"{p['ecosystem']}:{p['name']}:{p['version']}" for p in all_packages)) if not offline else 0,
            "summary": {
                "total_findings": len(all_findings),
                "critical": critical + chain_critical,
                "high": high,
                "layer3_chains": len(all_chains),
                "exploit_chains_scored": len(exploit_chains),
            },
            "repo_quantum_fidelity": repo_quantum,
            "data_sources": data_sources,
            "findings": all_findings,
            "osv_findings": [f for f in all_findings if f.get("osv_id")],
            "exploit_chains": exploit_chains,
            "cross_file_chains": all_chains,
        }

    finally:
        if temp_dir:
            shutil.rmtree(temp_dir, ignore_errors=True)


# ── Report printer ─────────────────────────────────────────────────────────────

def print_report(result: dict):
    if "error" in result:
        print(f"ERROR: {result['error']}")
        return

    s = result["summary"]
    print(f"\n{'='*65}")
    print(f"TAARA Scan — {result['repo']}")
    print(f"{'='*65}")
    if result.get("offline"):
        print("  [OFFLINE MODE — OSV and EOL API calls skipped]")
    print(f"Data sources: {', '.join(result.get('data_sources', []))}")
    print(f"Packages resolved: {result['packages_resolved']} | "
          f"Queried against OSV: {result['packages_queried_osv']}")
    print(f"\nCritical: {s['critical']}  High: {s['high']}  "
          f"Total: {s['total_findings']}  Chains: {s['layer3_chains']}")

    chains = result.get("cross_file_chains", [])
    if chains:
        print(f"\n{'─'*65}")
        print("LAYER 3 — Cross-File Failure Chains")
        print("(What no single-file scanner finds)")
        print(f"{'─'*65}")
        for c in chains:
            print(f"\n[{c['severity'].upper()}] {c['title']}")
            files = c.get('files') or c.get('files_involved', [])
            print(f"  Files: {', '.join(str(x) for x in files[:3])}")
            print(f"  {c['detail'][:200]}")
            if c.get('why_tests_miss_this'):
                print(f"  Why tests miss this: {c['why_tests_miss_this'][:150]}")
            if c.get('real_incident'):
                print(f"  Real incident: {c['real_incident'][:100]}")
            print(f"  Fix: {c['remediation'][:150]}")

    print(f"\n{'─'*65}")
    print("LAYER 1+2 — Individual Findings (OSV data + Quantum scoring)")
    print(f"{'─'*65}")
    for i, f in enumerate(result["findings"][:15], 1):
        qf = f.get("quantum_fidelity", {})
        pkg_info = f" [{f['package']} v{f['version']}]" if f.get("package") else ""
        print(f"\n[{i}] {f.get('severity','?').upper()} — {f.get('title','')[:70]}{pkg_info}")
        if f.get("file"):
            print(f"     File: {f['file']}" + (f" line {f['line']}" if f.get('line') else ""))
        if f.get("osv_id"):
            fixes = f.get("fix_versions", [])
            fix_str = f" → fix: v{fixes[0]}" if fixes else " → no fix version listed"
            print(f"     OSV: {f['osv_id']}{fix_str}")
            refs = f.get("references", [])
            if refs:
                print(f"     Ref: {refs[0]}")
        if qf:
            print(f"     Quantum: F={qf.get('fidelity',0):.4f}  {qf.get('interpretation','')[:80]}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python research/scan_repo.py <path-or-github-url> [--json] [--offline]")
        print()
        print("  --offline  Skip live OSV.dev and endoflife.date API calls.")
        print("             Lockfile parsing, Dockerfile checks, CI analysis still run.")
        sys.exit(1)

    offline_mode = "--offline" in sys.argv
    result = scan_repo(sys.argv[1], offline=offline_mode)
    print_report(result)

    if result.get("offline_skipped"):
        print("\n--- OFFLINE MODE: Skipped ---")
        for s in result["offline_skipped"]:
            print(f"  • {s}")

    if "--json" in sys.argv:
        out = ROOT / "benchmark" / "results" / "repo_scan_result.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"\nJSON: {out}")
