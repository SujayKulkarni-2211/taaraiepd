#!/bin/bash

echo "========================================"
echo "   TAARA - DevSecOps Control Plane"
echo "========================================"
echo ""
echo "Starting Taara application..."
echo ""

# Activate virtual environment
source venv/bin/activate

# Run Streamlit
streamlit run main.py
