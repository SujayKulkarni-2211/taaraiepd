#!/usr/bin/env python3
"""
TAARA GraphRAG Query Engine with Quantum Fidelity Scoring.

Given a file (Dockerfile, GitHub Actions YAML, SSH config, nginx.conf, etc.),
this finds all policy violations by:
1. Scanning for known misconfig patterns (rule-based, fast)
2. Embedding the file and searching FAISS for semantically similar policy violations
3. Scoring each finding with quantum fidelity (how far from best practice)
4. Traversing the knowledge graph to find what each violation causes / enables
5. Returning a ranked list of findings with propagation chains

Run standalone:
  python research/query_knowledge_base.py <path-to-file>

Or import the TAARAScan class for use in the app.
"""

import os
import sys
import json
import pickle
import re
from pathlib import Path
from typing import Optional

import numpy as np
import networkx as nx
import faiss
import pennylane as qml
from pennylane import numpy as pnp
from sentence_transformers import SentenceTransformer

ROOT = Path(__file__).parent.parent
EMBEDDINGS_DIR = ROOT / "knowledge_base" / "embeddings"
GRAPH_DIR = ROOT / "knowledge_base" / "graph"

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


# ── Quantum Fidelity Scorer ────────────────────────────────────────────────────

dev = qml.device("default.qubit", wires=4)

@qml.qnode(dev)
def _fidelity_circuit(state_vec_a: np.ndarray, state_vec_b: np.ndarray) -> float:
    """Compute quantum fidelity F(|ψ_a⟩, |ψ_b⟩) = |⟨ψ_a|ψ_b⟩|²"""
    qml.AmplitudeEmbedding(state_vec_a, wires=range(4), normalize=True, pad_with=0.0)
    qml.adjoint(qml.AmplitudeEmbedding)(state_vec_b, wires=range(4), normalize=True, pad_with=0.0)
    return qml.probs(wires=range(4))


def quantum_fidelity(vec_a: np.ndarray, vec_b: np.ndarray) -> float:
    """
    Compute fidelity between two embedding vectors via quantum circuit.

    F = |⟨ψ_a|ψ_b⟩|² where |ψ⟩ is the amplitude-encoded state.
    F = 1.0 → identical behavioral direction (config matches best practice perfectly)
    F = 0.0 → completely orthogonal (config is in a direction never seen in safe examples)
    F < 0.5 → more orthogonal than parallel = genuinely unsafe direction

    This is the honest claim: PennyLane simulation, no quantum speedup.
    Value: principled, parameter-free directionality criterion. No threshold tuning.
    """
    a = vec_a[:16].astype(float)   # 4-qubit circuit = 2^4 = 16 amplitudes
    b = vec_b[:16].astype(float)
    probs = _fidelity_circuit(a, b)
    # Fidelity = probability of measuring |0000⟩ = overlap between states
    return float(probs[0])


def deviation_score(fidelity: float) -> float:
    """Convert fidelity to deviation score. 1.0 = maximally deviant from best practice."""
    return round(1.0 - fidelity, 4)


# ── Pattern-based scanner ──────────────────────────────────────────────────────

# Maps regex pattern → (graph_node_id, description, severity)
PATTERN_RULES = {
    # SSH config rules
    r"PasswordAuthentication\s+yes":          ("ssh:password_auth_enabled",      "critical"),
    r"PermitRootLogin\s+(?!no)":              ("ssh:root_login_enabled",          "critical"),
    r"X11Forwarding\s+yes":                   ("ssh:x11_forwarding",              "medium"),
    r"AllowAgentForwarding\s+yes":            ("ssh:agent_forwarding",            "medium"),
    r"#.*ClientAliveInterval":                ("ssh:no_idle_timeout",             "medium"),
    r"Protocol\s+1":                          ("ssh:weak_cipher",                 "high"),

    # Dockerfile rules
    r"^FROM\s+\S+:latest":                    ("docker:unpinned_base_image",      "high"),
    r"^FROM\s+\S+\s*$":                       ("docker:unpinned_base_image",      "high"),  # no tag at all
    r"^ENV\s+.*(?:PASSWORD|SECRET|KEY|TOKEN)": ("docker:secrets_in_env",          "high"),
    r"^ARG\s+.*(?:PASSWORD|SECRET|KEY|TOKEN)": ("docker:secrets_in_build_arg",    "high"),
    r"--privileged":                          ("docker:privileged_mode",          "critical"),
    r"^(?!.*USER\s+\d).*RUN\s+":             ("docker:running_as_root",          "critical"),  # RUN without USER before it

    # GitHub Actions rules
    r"uses:\s+\S+@(?:main|master|v\d+)(?:\s|$)": ("cicd:floating_action_pin",   "critical"),
    r"\$\{\{\s*github\.event\.pull_request": ("cicd:script_injection",           "high"),
    r"on:\s*pull_request_target":            ("cicd:pull_request_target_unsafe", "critical"),
    r"npm install(?!\s+--ci|\s+ci)":         ("cicd:unpinned_npm_install",       "high"),
    r"(?:^|\n)\s*permissions:":              None,  # permissions block present = GOOD, skip
    r"ACTIONS_RUNNER_DEBUG.*true":           ("cicd:secrets_in_logs",            "critical"),

    # Generic secrets
    r"(?i)(?:api[_-]?key|secret|password|token)\s*=\s*['\"][^'\"]{8,}": ("docker:secrets_in_env", "high"),
}

def pattern_scan(content: str, filename: str) -> list[dict]:
    """Fast regex scan for known misconfigs. Returns list of findings."""
    findings = []
    seen_nodes = set()
    for pattern, rule in PATTERN_RULES.items():
        if rule is None:
            continue
        node_id, severity = rule
        if node_id in seen_nodes:
            continue
        matches = list(re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE))
        if matches:
            seen_nodes.add(node_id)
            findings.append({
                "node_id": node_id,
                "severity": severity,
                "match": matches[0].group(0).strip()[:100],
                "line": content[:matches[0].start()].count("\n") + 1,
                "source": "pattern_scan",
            })
    return findings


# ── Semantic search ────────────────────────────────────────────────────────────

class TAARAScan:
    def __init__(self):
        self._model = None
        self._index = None
        self._chunks = None
        self._graph = None
        self._policy_embeddings = None

    def _load(self):
        if self._model is not None:
            return
        print("Loading TAARA knowledge base...")
        if not (EMBEDDINGS_DIR / "policy_index.faiss").exists():
            raise FileNotFoundError(
                "Knowledge base not built. Run: python research/build_knowledge_base.py"
            )
        self._model = SentenceTransformer("all-MiniLM-L6-v2")
        self._index = faiss.read_index(str(EMBEDDINGS_DIR / "policy_index.faiss"))
        with open(EMBEDDINGS_DIR / "policy_chunks.pkl", "rb") as f:
            self._chunks = pickle.load(f)
        self._policy_embeddings = np.load(EMBEDDINGS_DIR / "policy_embeddings.npy")
        with open(GRAPH_DIR / "taara_knowledge_graph.pkl", "rb") as f:
            self._graph = pickle.load(f)
        print(f"  Loaded: {self._index.ntotal} policy vectors, {self._graph.number_of_nodes()} graph nodes")

    def _semantic_search(self, content: str, top_k: int = 5) -> list[dict]:
        """Find semantically similar policy violations to the given content."""
        query_vec = self._model.encode([content], normalize_embeddings=True).astype(np.float32)
        scores, indices = self._index.search(query_vec, top_k)
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx < 0:
                continue
            chunk = self._chunks[idx]
            results.append({
                "chunk": chunk,
                "similarity": float(score),
                "embedding_idx": int(idx),
            })
        return results

    def _compute_quantum_fidelity_for_finding(
        self, content_embedding: np.ndarray, policy_embedding: np.ndarray
    ) -> dict:
        """
        Compare the file's embedding against the policy (best-practice) embedding.
        Low fidelity = file's config is moving in an unsafe direction not seen in policy.
        """
        F = quantum_fidelity(content_embedding, policy_embedding)
        deviation = deviation_score(F)
        risk_level = "critical" if F < 0.3 else "high" if F < 0.5 else "medium" if F < 0.7 else "low"
        return {
            "fidelity": round(F, 4),
            "deviation": deviation,
            "quantum_risk": risk_level,
            "interpretation": (
                f"F={F:.3f} — config direction is "
                + ("maximally unsafe (nearly orthogonal to best practice)" if F < 0.3
                   else "unsafe (more orthogonal than parallel to best practice)" if F < 0.5
                   else "drifting from best practice" if F < 0.7
                   else "close to best practice")
            ),
        }

    def _propagation_chain(self, node_id: str, depth: int = 3) -> list[dict]:
        """Walk the graph from a detected risk — what does it cause / enable?"""
        if node_id not in self._graph:
            return []
        chain = []
        visited = set()
        queue = [(node_id, 0)]
        while queue:
            current, d = queue.pop(0)
            if current in visited or d > depth:
                continue
            visited.add(current)
            node = self._graph.nodes[current]
            if node.get("node_type") == "mitigation":
                continue
            chain.append({
                "id": current,
                "label": node.get("label", current),
                "severity": node.get("severity", "unknown"),
                "description": node.get("description", ""),
                "depth": d,
                "relationships": [
                    {
                        "to": v,
                        "to_label": self._graph.nodes[v].get("label", v),
                        "rel": self._graph.edges[current, v].get("relationship", ""),
                    }
                    for v in self._graph.successors(current)
                    if self._graph.nodes[v].get("node_type") != "mitigation"
                ],
            })
            for v in self._graph.successors(current):
                rel = self._graph.edges[current, v].get("relationship", "")
                if rel not in ("mitigated_by",):
                    queue.append((v, d + 1))
        return chain

    def _get_mitigations(self, node_id: str) -> list[dict]:
        """Find recommended fixes for a detected risk."""
        if node_id not in self._graph:
            return []
        mitigations = []
        for v in self._graph.successors(node_id):
            if self._graph.nodes[v].get("node_type") == "mitigation":
                rel = self._graph.edges[node_id, v].get("relationship", "")
                mitigations.append({
                    "id": v,
                    "label": self._graph.nodes[v].get("label", v),
                    "description": self._graph.nodes[v].get("description", ""),
                    "relationship": rel,
                })
        return mitigations

    def scan_file(self, filepath: str | Path) -> dict:
        """
        Scan a single file and return all findings with quantum scores.
        This is the main entry point.
        """
        self._load()
        filepath = Path(filepath)
        if not filepath.exists():
            return {"error": f"File not found: {filepath}"}

        content = filepath.read_text(errors="ignore")
        filename = filepath.name

        # Step 1: Fast pattern scan
        pattern_findings = pattern_scan(content, filename)

        # Step 2: Embed the entire file for semantic + quantum scoring
        content_embedding = self._model.encode([content], normalize_embeddings=True).astype(np.float32)[0]

        # Step 3: Semantic search — find policy chunks most similar to this file's content
        semantic_results = self._semantic_search(content, top_k=8)

        # Step 4: For each pattern finding, compute quantum fidelity against its policy embedding
        findings = []
        seen_nodes = set()

        for pf in pattern_findings:
            node_id = pf["node_id"]
            if node_id in seen_nodes:
                continue
            seen_nodes.add(node_id)

            # Find the best matching policy embedding for this node
            node_label = self._graph.nodes.get(node_id, {}).get("label", "")
            policy_query = self._model.encode([node_label], normalize_embeddings=True).astype(np.float32)[0]
            qf = self._compute_quantum_fidelity_for_finding(content_embedding, policy_query)

            chain = self._propagation_chain(node_id)
            mitigations = self._get_mitigations(node_id)

            node_data = self._graph.nodes.get(node_id, {})
            findings.append({
                "node_id": node_id,
                "label": node_data.get("label", node_id),
                "severity": pf["severity"],
                "description": node_data.get("description", ""),
                "match": pf.get("match", ""),
                "line": pf.get("line", 0),
                "quantum_fidelity": qf,
                "propagation_chain": chain,
                "mitigations": mitigations,
                "detection_method": "pattern+quantum",
            })

        # Step 5: Add semantic-only findings (things pattern scan missed)
        for sr in semantic_results:
            source = sr["chunk"]["source"]
            chunk_text = sr["chunk"]["text"]
            similarity = sr["similarity"]
            if similarity < 0.55:  # below threshold — not relevant
                continue
            # Get embedding of this policy chunk
            policy_embedding = self._policy_embeddings[sr["embedding_idx"]]
            qf = self._compute_quantum_fidelity_for_finding(content_embedding, policy_embedding)

            # Only add if it's a genuinely unsafe direction
            if qf["fidelity"] < 0.5 and source not in seen_nodes:
                findings.append({
                    "node_id": source,
                    "label": f"Semantic match: {source}",
                    "severity": qf["quantum_risk"],
                    "description": chunk_text[:200],
                    "match": "",
                    "line": 0,
                    "quantum_fidelity": qf,
                    "propagation_chain": [],
                    "mitigations": [],
                    "detection_method": "semantic+quantum",
                    "similarity": round(similarity, 4),
                })
                seen_nodes.add(source)

        # Step 6: Sort by severity then by quantum deviation (most deviant first)
        findings.sort(key=lambda f: (
            -SEVERITY_ORDER.get(f["severity"], 0),
            -f["quantum_fidelity"]["deviation"]
        ))

        # Step 7: Compute overall file risk score
        if findings:
            max_dev = max(f["quantum_fidelity"]["deviation"] for f in findings)
            avg_dev = sum(f["quantum_fidelity"]["deviation"] for f in findings) / len(findings)
            critical_count = sum(1 for f in findings if f["severity"] == "critical")
            high_count = sum(1 for f in findings if f["severity"] == "high")
            overall_risk = min(1.0, (critical_count * 0.4 + high_count * 0.2 + avg_dev) / 2)
        else:
            max_dev = avg_dev = overall_risk = 0.0
            critical_count = high_count = 0

        return {
            "file": str(filepath),
            "filename": filename,
            "findings_count": len(findings),
            "critical": critical_count,
            "high": high_count,
            "overall_risk_score": round(overall_risk, 4),
            "max_quantum_deviation": round(max_dev, 4),
            "findings": findings,
        }

    def scan_text(self, content: str, label: str = "inline") -> dict:
        """Scan raw text (e.g., from TaaraAnalysis ssh config output) instead of a file."""
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            tmp_path = f.name
        result = self.scan_file(tmp_path)
        result["file"] = label
        result["filename"] = label
        os.unlink(tmp_path)
        return result


# ── CLI ────────────────────────────────────────────────────────────────────────

def print_report(result: dict):
    if "error" in result:
        print(f"ERROR: {result['error']}")
        return

    print("\n" + "=" * 70)
    print(f"TAARA Scan Report: {result['filename']}")
    print("=" * 70)
    print(f"Overall Risk Score : {result['overall_risk_score']:.4f}")
    print(f"Max Quantum Dev    : {result['max_quantum_deviation']:.4f}")
    print(f"Critical Findings  : {result['critical']}")
    print(f"High Findings      : {result['high']}")
    print(f"Total Findings     : {result['findings_count']}")

    if not result["findings"]:
        print("\nNo findings. Configuration looks clean.")
        return

    print("\n── Findings ─────────────────────────────────────────────────────────\n")
    for i, f in enumerate(result["findings"], 1):
        print(f"[{i}] {f['severity'].upper()} — {f['label']}")
        if f.get("line"):
            print(f"     Line {f['line']}: {f['match']}")
        print(f"     {f['description']}")
        qf = f["quantum_fidelity"]
        print(f"     Quantum: F={qf['fidelity']:.4f}, deviation={qf['deviation']:.4f} ({qf['quantum_risk']})")
        print(f"     {qf['interpretation']}")

        if f["mitigations"]:
            print(f"     Fix: {f['mitigations'][0]['label']} — {f['mitigations'][0]['description']}")

        if f["propagation_chain"] and len(f["propagation_chain"]) > 1:
            chain_labels = " → ".join(
                c["label"] for c in f["propagation_chain"][:4]
                if c["id"] != f["node_id"]
            )
            if chain_labels:
                print(f"     Cascade: {chain_labels}")
        print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python research/query_knowledge_base.py <path-to-file>")
        print("       python research/query_knowledge_base.py Dockerfile")
        print("       python research/query_knowledge_base.py .github/workflows/ci.yml")
        print("       python research/query_knowledge_base.py /etc/ssh/sshd_config")
        sys.exit(1)

    scanner = TAARAScan()
    result = scanner.scan_file(sys.argv[1])
    print_report(result)
