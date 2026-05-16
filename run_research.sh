#!/bin/bash
# TAARA Research Pipeline
# Builds the knowledge base and runs benchmarks.
# Run this once before running the app (or after adding new policy documents).
# After this completes, the app will use the built artifacts.

set -e

cd "$(dirname "$0")"
source venv/bin/activate

echo "========================================"
echo " TAARA Research Pipeline"
echo "========================================"
echo ""

case "${1:-all}" in

  kb)
    echo "[1/1] Building knowledge base (embeddings + graph)..."
    python research/build_knowledge_base.py
    ;;

  bench)
    echo "[1/1] Running benchmark on LogHub SSH dataset..."
    python research/run_benchmark.py
    ;;

  scan)
    if [ -z "$2" ]; then
      echo "Usage: ./run_research.sh scan <path-to-file-or-repo> [--offline]"
      echo "Example: ./run_research.sh scan Dockerfile"
      echo "         ./run_research.sh scan /path/to/repo"
      echo "         ./run_research.sh scan /path/to/repo --offline"
      echo "         ./run_research.sh scan https://github.com/org/repo"
      echo ""
      echo "--offline: skips live OSV.dev + endoflife.date API calls."
      echo "           Lockfile parsing, Dockerfile static checks, and CI"
      echo "           workflow analysis still run. No internet required."
      exit 1
    fi
    OFFLINE_FLAG=""
    if [[ "$3" == "--offline" ]]; then
      OFFLINE_FLAG="--offline"
      echo "Offline mode: OSV and EOL API calls skipped"
    fi
    # Detect if it's a repo (directory or URL) or a single file
    if [ -d "$2" ] || [[ "$2" == http* ]]; then
      echo "Repo scan: $2"
      python research/scan_repo.py "$2" --json $OFFLINE_FLAG
    else
      echo "File scan: $2"
      python research/query_knowledge_base.py "$2"
    fi
    ;;

  all|*)
    echo "[1/2] Building knowledge base..."
    python research/build_knowledge_base.py

    echo ""
    echo "[2/2] Running SSH benchmark..."
    python research/run_benchmark.py

    echo ""
    echo "Done. Artifacts written to:"
    echo "  knowledge_base/embeddings/  — FAISS index + chunk metadata"
    echo "  knowledge_base/graph/       — knowledge graph (pkl + json)"
    echo "  benchmark/results/          — benchmark_results.json"
    ;;
esac
