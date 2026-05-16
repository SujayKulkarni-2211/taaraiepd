#!/usr/bin/env python3
"""
Build TAARA's policy knowledge base.

What this does:
1. Loads all policy documents from knowledge_base/policies/
2. Chunks them into ~500-token segments with overlap
3. Embeds each chunk using sentence-transformers (all-MiniLM-L6-v2, runs locally, no API)
4. Stores embeddings in a FAISS index for fast vector search
5. Builds a NetworkX knowledge graph linking policy concepts, CVE patterns, and code risks
6. Saves everything to knowledge_base/embeddings/ and knowledge_base/graph/

Run: python research/build_knowledge_base.py
After this runs, the app can query the knowledge base without rebuilding it.
"""

import os
import sys
import json
import pickle
import re
from pathlib import Path

import numpy as np
import networkx as nx
import faiss
from sentence_transformers import SentenceTransformer

ROOT = Path(__file__).parent.parent
POLICIES_DIR = ROOT / "knowledge_base" / "policies"
CVE_FILE = ROOT / "knowledge_base" / "cve" / "nvd_critical_cves.json"
CITATIONS_DIR = ROOT / "knowledge_base" / "citations"
EMBEDDINGS_DIR = ROOT / "knowledge_base" / "embeddings"
GRAPH_DIR = ROOT / "knowledge_base" / "graph"

EMBEDDINGS_DIR.mkdir(parents=True, exist_ok=True)
GRAPH_DIR.mkdir(parents=True, exist_ok=True)

CHUNK_SIZE = 500        # characters per chunk
CHUNK_OVERLAP = 100     # overlap between consecutive chunks


# ── Text chunking ──────────────────────────────────────────────────────────────

def chunk_text(text: str, source: str) -> list[dict]:
    """Split text into overlapping chunks, preserving source metadata."""
    chunks = []
    start = 0
    while start < len(text):
        end = start + CHUNK_SIZE
        chunk = text[start:end].strip()
        if chunk:
            chunks.append({"text": chunk, "source": source, "start": start})
        start += CHUNK_SIZE - CHUNK_OVERLAP
    return chunks


def load_policy_chunks() -> list[dict]:
    chunks = []
    for path in sorted(POLICIES_DIR.glob("*.md")):
        text = path.read_text(errors="ignore")
        if len(text) < 50:
            print(f"  WARN: {path.name} looks empty ({len(text)} bytes), skipping")
            continue
        file_chunks = chunk_text(text, f"policy:{path.stem}")
        chunks.extend(file_chunks)
        print(f"  {path.name}: {len(file_chunks)} chunks")
    return chunks


def load_cve_chunks() -> list[dict]:
    if not CVE_FILE.exists():
        print("  CVE file not found, skipping")
        return []
    with open(CVE_FILE) as f:
        raw = json.load(f)
    # NVD API v2 format: {"vulnerabilities": [{"cve": {...}}, ...]}
    if isinstance(raw, dict) and "vulnerabilities" in raw:
        cve_list = [entry["cve"] for entry in raw["vulnerabilities"]]
    elif isinstance(raw, list):
        cve_list = raw
    else:
        print("  CVE file format unrecognized, skipping")
        return []
    chunks = []
    for cve in cve_list[:5000]:  # first 5k critical CVEs — enough for embedding
        cve_id = cve.get("id", "UNKNOWN")
        desc = cve.get("descriptions", [{}])[0].get("value", "")
        if not desc:
            continue
        text = f"{cve_id}: {desc}"
        chunks.append({"text": text, "source": f"cve:{cve_id}", "start": 0})
    print(f"  CVE database: {len(chunks)} entries embedded")
    return chunks


def load_citation_chunks() -> list[dict]:
    chunks = []
    for path in sorted(CITATIONS_DIR.glob("*.md")):
        text = path.read_text(errors="ignore")
        file_chunks = chunk_text(text, f"citation:{path.stem}")
        chunks.extend(file_chunks)
        print(f"  {path.name}: {len(file_chunks)} chunks")
    return chunks


# ── Embedding and FAISS index ──────────────────────────────────────────────────

def build_faiss_index(chunks: list[dict], model: SentenceTransformer) -> tuple:
    print(f"\nEmbedding {len(chunks)} chunks with sentence-transformers...")
    texts = [c["text"] for c in chunks]
    embeddings = model.encode(texts, batch_size=64, show_progress_bar=True, normalize_embeddings=True)
    embeddings = np.array(embeddings, dtype=np.float32)

    dim = embeddings.shape[1]
    index = faiss.IndexFlatIP(dim)  # inner product = cosine similarity (normalized vectors)
    index.add(embeddings)
    print(f"  FAISS index built: {index.ntotal} vectors, dim={dim}")
    return index, embeddings


# ── Knowledge graph ────────────────────────────────────────────────────────────

def build_knowledge_graph() -> nx.DiGraph:
    """
    Build a structured knowledge graph with three domains:
    - Security policies (CIS, OWASP, SSH, Docker rules)
    - Code/CI-CD risk patterns (vibe coding era failure modes)
    - CVE categories (injection, supply chain, auth, crypto)

    Nodes have: id, domain, label, severity, description
    Edges have: relationship type (violates, causes, mitigates, depends_on, conflicts_with)
    """
    G = nx.DiGraph()

    # ── Domain 1: Security Policy Concepts ──
    policy_nodes = [
        # SSH
        ("ssh:password_auth_enabled",       "ssh",    "Password auth enabled",         "critical", "SSH password auth allows brute force. Disable: PasswordAuthentication no"),
        ("ssh:root_login_enabled",           "ssh",    "Root SSH login permitted",       "critical", "PermitRootLogin yes — direct root access, no audit trail"),
        ("ssh:weak_cipher",                  "ssh",    "Weak SSH cipher",                "high",     "diffie-hellman-group1-sha1 present — Logjam attack vector"),
        ("ssh:no_idle_timeout",              "ssh",    "No SSH idle timeout",            "medium",   "Abandoned sessions usable for lateral movement"),
        ("ssh:no_max_auth_tries",            "ssh",    "Unlimited SSH auth attempts",    "high",     "Enables slow brute force undetected by default fail2ban rules"),
        ("ssh:x11_forwarding",               "ssh",    "X11 forwarding enabled",         "medium",   "Creates local socket exploitable for privilege escalation"),
        ("ssh:agent_forwarding",             "ssh",    "Agent forwarding enabled",       "medium",   "SSH agent hijacking in multi-hop scenarios"),
        # Docker
        ("docker:running_as_root",           "docker", "Container running as root",      "critical", "Root in container = root on host if escape. USER directive missing."),
        ("docker:no_resource_limits",        "docker", "No container resource limits",   "high",     "Single container can starve all others — DoS via resource exhaustion"),
        ("docker:privileged_mode",           "docker", "Container in privileged mode",   "critical", "Full host kernel access — complete container escape"),
        ("docker:mutable_filesystem",        "docker", "Mutable container filesystem",   "medium",   "Attacker can persist changes inside container across restarts"),
        ("docker:secrets_in_env",            "docker", "Secrets passed via ENV vars",    "high",     "docker inspect exposes ENV secrets to any process on host"),
        ("docker:secrets_in_build_arg",      "docker", "Secrets in Dockerfile ARG",      "high",     "Build args visible in image history: docker history <image>"),
        ("docker:unpinned_base_image",       "docker", "Unpinned Docker base image",     "high",     "FROM node:latest — silent image swap introduces CVEs"),
        ("docker:no_image_signing",          "docker", "No image signature verification","medium",   "No guarantee image hasn't been tampered with in registry"),
        ("docker:network_default_bridge",    "docker", "Default bridge network",         "medium",   "All containers on default bridge can communicate without restriction"),
        # GitHub Actions / CI-CD
        ("cicd:floating_action_pin",         "cicd",   "Action pinned to floating tag",  "critical", "uses: action@v2 — tag can be moved to malicious commit (tj-actions attack)"),
        ("cicd:pull_request_target_unsafe",  "cicd",   "Unsafe pull_request_target",     "critical", "pull_request_target + fork checkout = attacker code with write permissions"),
        ("cicd:script_injection",            "cicd",   "Script injection via context",   "high",     "${{ github.event.pull_request.title }} in run: step = shell injection"),
        ("cicd:over_permissioned_token",     "cicd",   "GITHUB_TOKEN over-permissioned", "high",     "No permissions: block — default is broad read-write"),
        ("cicd:secrets_in_logs",             "cicd",   "Secrets visible in CI logs",     "critical", "printenv or debug logging exposes all secrets to log readers"),
        ("cicd:unpinned_npm_install",        "cicd",   "Unpinned npm install in CI",     "high",     "npm install without lockfile = supply chain attack surface"),
        # Vibe coding / AI code risks
        ("vibecode:slopsquatting",           "vibecode","Slopsquatting risk",             "critical", "AI hallucinates package names. Attacker registers the hallucinated name."),
        ("vibecode:secret_sprawl",           "vibecode","Secret sprawl in AI code",       "high",     "AI-generated code hardcodes secrets 2x more than human code"),
        ("vibecode:zombie_infra",            "vibecode","Zombie infrastructure",           "medium",   "Vibe-deployed infra forgotten — no one owns it, no one patches it"),
        ("vibecode:schema_drift",            "vibecode","Silent DB schema drift",          "high",     "AI migration runs clean but corrupts downstream reports 3 months later"),
        ("vibecode:dependency_hallucination","vibecode","Hallucinated dependencies",       "critical", "AI suggests package that doesn't exist — real package name squatted"),
        # Auth / OWASP
        ("auth:no_mfa",                      "auth",   "No MFA on admin accounts",       "high",     "Single factor auth — credential stuffing and phishing bypass"),
        ("auth:weak_session_tokens",         "auth",   "Weak session token entropy",     "high",     "Predictable session IDs enable session fixation attacks"),
        ("auth:no_rate_limiting",            "auth",   "No login rate limiting",          "high",     "Credential stuffing attacks go undetected"),
        ("auth:jwt_none_algorithm",          "auth",   "JWT none algorithm accepted",     "critical", "Unsigned JWT accepted as valid — complete auth bypass"),
        # Infrastructure
        ("infra:public_s3_bucket",           "infra",  "Public S3 bucket",               "critical", "Misconfigured bucket exposes data to anyone on internet"),
        ("infra:unencrypted_storage",        "infra",  "Unencrypted storage at rest",    "high",     "Data readable if disk is physically or logically accessed"),
        ("infra:no_vpc_isolation",           "infra",  "No VPC network isolation",       "high",     "Services reachable from internet that should be internal-only"),
        ("infra:default_credentials",        "infra",  "Default service credentials",    "critical", "Default admin:admin or similar — first thing attackers try"),
        ("infra:missing_audit_logs",         "infra",  "Missing audit logs",             "high",     "Breach undetectable — no forensic trail"),
    ]

    for node_id, domain, label, severity, desc in policy_nodes:
        G.add_node(node_id, domain=domain, label=label, severity=severity, description=desc, node_type="risk")

    # ── Domain 2: Mitigations ──
    mitigation_nodes = [
        ("fix:disable_password_auth",    "fix", "PasswordAuthentication no",           "none", "Set in /etc/ssh/sshd_config"),
        ("fix:pin_action_to_sha",        "fix", "Pin action to commit SHA",             "none", "uses: owner/repo@<full-sha> # tag"),
        ("fix:use_secrets_manager",      "fix", "Use secrets manager (not ENV)",        "none", "AWS Secrets Manager, Vault, or GitHub Secrets — never ENV vars in Dockerfile"),
        ("fix:add_resource_limits",      "fix", "Add Docker resource limits",           "none", "--memory=512m --cpus=0.5 or deploy.resources in compose"),
        ("fix:run_as_nonroot",           "fix", "Run container as non-root USER",       "none", "USER 1001 in Dockerfile, verify with docker run --user"),
        ("fix:pin_base_image_sha",       "fix", "Pin base image to digest",             "none", "FROM node:20@sha256:<digest> — immutable reference"),
        ("fix:env_var_intermediary",     "fix", "Use env: for untrusted input",         "none", "Set env: PR_TITLE: ${{ ... }} then use $PR_TITLE in shell"),
        ("fix:restrict_token_perms",     "fix", "Add permissions: block",              "none", "permissions: contents: read — minimum needed per job"),
        ("fix:enable_fail2ban",          "fix", "Enable fail2ban for SSH",              "none", "Ban IP after 3 failed attempts — blocks slow brute force"),
        ("fix:lockfile_in_ci",           "fix", "Commit package lockfile, use ci",      "none", "npm ci not npm install — uses exact lockfile versions"),
    ]

    for node_id, domain, label, severity, desc in mitigation_nodes:
        G.add_node(node_id, domain=domain, label=label, severity=severity, description=desc, node_type="mitigation")

    # ── Domain 3: Known breach patterns (incident references) ──
    incident_nodes = [
        ("incident:tj_actions_2025",       "incident", "tj-actions supply chain compromise", "critical",
         "March 2025: tj-actions/changed-files compromised, 23,000+ repos leaked secrets via CI logs"),
        ("incident:codecov_2021",          "incident", "Codecov bash uploader backdoor",      "critical",
         "April 2021: Codecov's bash uploader modified to exfiltrate CI environment variables"),
        ("incident:uber_2022",             "incident", "Uber HackerOne MFA fatigue",           "critical",
         "September 2022: Attacker spammed MFA push notifications until employee approved"),
        ("incident:solarwinds_2020",       "incident", "SolarWinds Orion supply chain",       "critical",
         "2020: Build pipeline compromised, malicious code shipped in signed update to 18,000 customers"),
        ("incident:log4shell_2021",        "incident", "Log4Shell remote code execution",      "critical",
         "December 2021: CVE-2021-44228, JNDI lookup in log messages, billions of Java apps affected"),
        ("incident:capital_one_2019",      "incident", "Capital One SSRF + S3 misconfiguration","critical",
         "2019: SSRF on EC2 metadata endpoint + public S3 bucket, 100M records exposed"),
        ("incident:event_stream_2018",     "incident", "event-stream malicious dependency",     "critical",
         "2018: npm package (8M weekly downloads) compromised via maintainer handoff, stole Bitcoin wallets"),
    ]

    for node_id, domain, label, severity, desc in incident_nodes:
        G.add_node(node_id, domain=domain, label=label, severity=severity, description=desc, node_type="incident")

    # ── Edges: relationships between nodes ──
    edges = [
        # Risk → Mitigation (mitigated_by)
        ("ssh:password_auth_enabled",       "fix:disable_password_auth",    "mitigated_by"),
        ("ssh:no_max_auth_tries",           "fix:enable_fail2ban",          "mitigated_by"),
        ("cicd:floating_action_pin",        "fix:pin_action_to_sha",        "mitigated_by"),
        ("docker:secrets_in_env",           "fix:use_secrets_manager",      "mitigated_by"),
        ("docker:secrets_in_build_arg",     "fix:use_secrets_manager",      "mitigated_by"),
        ("docker:no_resource_limits",       "fix:add_resource_limits",      "mitigated_by"),
        ("docker:running_as_root",          "fix:run_as_nonroot",           "mitigated_by"),
        ("docker:unpinned_base_image",      "fix:pin_base_image_sha",       "mitigated_by"),
        ("cicd:script_injection",           "fix:env_var_intermediary",     "mitigated_by"),
        ("cicd:over_permissioned_token",    "fix:restrict_token_perms",     "mitigated_by"),
        ("cicd:unpinned_npm_install",       "fix:lockfile_in_ci",           "mitigated_by"),

        # Risk → Incident (exploited_in)
        ("cicd:floating_action_pin",        "incident:tj_actions_2025",     "exploited_in"),
        ("cicd:secrets_in_logs",            "incident:tj_actions_2025",     "exploited_in"),
        ("cicd:unpinned_npm_install",       "incident:event_stream_2018",   "exploited_in"),
        ("auth:no_mfa",                     "incident:uber_2022",           "exploited_in"),
        ("infra:public_s3_bucket",          "incident:capital_one_2019",    "exploited_in"),

        # Risk → Risk (causes / enables)
        ("docker:running_as_root",          "docker:privileged_mode",        "enables"),
        ("cicd:floating_action_pin",        "cicd:secrets_in_logs",          "causes"),
        ("vibecode:slopsquatting",          "vibecode:dependency_hallucination", "causes"),
        ("infra:missing_audit_logs",        "ssh:password_auth_enabled",     "hides"),
        ("ssh:root_login_enabled",          "infra:missing_audit_logs",      "bypasses"),
        ("vibecode:zombie_infra",           "infra:default_credentials",     "causes"),
        ("vibecode:schema_drift",           "infra:missing_audit_logs",      "masked_by"),

        # Incident → Incident (attack pattern propagation)
        ("incident:solarwinds_2020",        "incident:tj_actions_2025",      "pattern_repeated_in"),
        ("incident:event_stream_2018",      "incident:tj_actions_2025",      "pattern_repeated_in"),
    ]

    for src, dst, rel in edges:
        G.add_edge(src, dst, relationship=rel)

    print(f"\nKnowledge graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    return G


# ── Propagation risk scoring ────────────────────────────────────────────────────

SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2, "none": 0.0}

def compute_propagation_risk(G: nx.DiGraph, node_id: str, depth: int = 3) -> dict:
    """
    Starting from a detected risk node, traverse the graph to find
    what it causes, enables, or leads to. Returns chain with scores.
    """
    if node_id not in G:
        return {}
    chain = {}
    visited = set()
    queue = [(node_id, 0, 1.0)]
    while queue:
        current, current_depth, current_score = queue.pop(0)
        if current in visited or current_depth > depth:
            continue
        visited.add(current)
        node_data = G.nodes[current]
        base_weight = SEVERITY_WEIGHT.get(node_data.get("severity", "low"), 0.2)
        propagated_score = current_score * base_weight
        chain[current] = {
            "label": node_data.get("label", current),
            "severity": node_data.get("severity", "unknown"),
            "description": node_data.get("description", ""),
            "depth": current_depth,
            "propagation_score": round(propagated_score, 3),
        }
        for successor in G.successors(current):
            rel = G.edges[current, successor].get("relationship", "")
            if rel not in ("mitigated_by",):  # don't traverse into mitigations when finding risk chains
                queue.append((successor, current_depth + 1, propagated_score))
    return chain


# ── Main build ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("TAARA Knowledge Base Builder")
    print("=" * 60)

    print("\n[1/4] Loading and chunking documents...")
    all_chunks = []
    all_chunks.extend(load_policy_chunks())
    all_chunks.extend(load_cve_chunks())
    all_chunks.extend(load_citation_chunks())
    print(f"\nTotal chunks: {len(all_chunks)}")

    print("\n[2/4] Loading sentence-transformers model...")
    model = SentenceTransformer("all-MiniLM-L6-v2")

    print("\n[3/4] Building FAISS index...")
    index, embeddings = build_faiss_index(all_chunks, model)

    faiss.write_index(index, str(EMBEDDINGS_DIR / "policy_index.faiss"))
    with open(EMBEDDINGS_DIR / "policy_chunks.pkl", "wb") as f:
        pickle.dump(all_chunks, f)
    np.save(EMBEDDINGS_DIR / "policy_embeddings.npy", embeddings)
    print(f"  Saved to {EMBEDDINGS_DIR}/")

    print("\n[4/4] Building knowledge graph...")
    G = build_knowledge_graph()

    with open(GRAPH_DIR / "taara_knowledge_graph.pkl", "wb") as f:
        pickle.dump(G, f)

    # Also save as JSON for inspection
    graph_data = {
        "nodes": [
            {"id": n, **G.nodes[n]}
            for n in G.nodes
        ],
        "edges": [
            {"source": u, "target": v, **G.edges[u, v]}
            for u, v in G.edges
        ]
    }
    with open(GRAPH_DIR / "taara_knowledge_graph.json", "w") as f:
        json.dump(graph_data, f, indent=2)

    print(f"  Saved to {GRAPH_DIR}/")

    print("\n" + "=" * 60)
    print("Knowledge base build complete.")
    print(f"  FAISS index: {index.ntotal} vectors")
    print(f"  Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    print("\nApp can now query the knowledge base.")
    print("Next: python research/run_benchmark.py")
    print("=" * 60)


if __name__ == "__main__":
    main()
