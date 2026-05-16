#!/bin/bash
# TAARA Command Center — App entry point
# Run this to launch the Streamlit dashboard.
# Prerequisite: run ./run_research.sh once to build knowledge base and models.

set -e
cd "$(dirname "$0")"

echo "========================================"
echo " TAARA q.0 — Command Center"
echo "========================================"
echo ""

source venv/bin/activate

# Verify knowledge base exists
if [ ! -f "knowledge_base/embeddings/policy_index.faiss" ]; then
  echo "Knowledge base not built yet. Run first:"
  echo "  ./run_research.sh"
  echo ""
fi

echo "Starting TAARA Command Center..."
echo "Open: http://localhost:8501"
echo ""
streamlit run main.py
