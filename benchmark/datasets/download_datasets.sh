#!/usr/bin/env bash
# ============================================================
# TAARA Benchmark Dataset Downloader
# ============================================================
# Downloads the public SSH and Linux syslog datasets from the
# Loghub collection (logpai/loghub, Zenodo DOI 10.5281/zenodo.8196385).
#
# These files are NOT stored in the git repo because:
#   SSH.log  — 71 MB
#   Linux.log — 2.3 MB
# Git LFS or direct download is the right approach for raw logs.
#
# Usage:
#   chmod +x benchmark/datasets/download_datasets.sh
#   ./benchmark/datasets/download_datasets.sh
#
# After running this script, the benchmark pipeline will work:
#   python benchmark/scripts/run_benchmark.py
# ============================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "TAARA Benchmark Dataset Downloader"
echo "==================================="

# ── Helper: download with progress if missing ─────────────────
download_if_missing() {
    local url="$1"
    local dest="$2"
    local desc="$3"
    if [[ -f "$dest" ]]; then
        echo "  [OK] $dest already present ($(du -sh "$dest" | cut -f1))"
        return
    fi
    echo "  Downloading $desc..."
    if command -v curl &>/dev/null; then
        curl -fL --progress-bar -o "$dest" "$url"
    elif command -v wget &>/dev/null; then
        wget -q --show-progress -O "$dest" "$url"
    else
        echo "  ERROR: neither curl nor wget found. Install one and retry."
        exit 1
    fi
    echo "  [OK] $dest ($(du -sh "$dest" | cut -f1))"
}

# ── SSH Brute-Force Log (Loghub — SSH) ────────────────────────
# Source: https://github.com/logpai/loghub (SSH dataset)
# Zenodo: https://zenodo.org/record/8196385
# Direct download via Zenodo file export
SSH_URL="https://zenodo.org/record/8196385/files/SSH.tar.gz?download=1"
download_if_missing "$SSH_URL" "SSH.tar.gz" "SSH.tar.gz from Zenodo (Loghub)"

if [[ -f "SSH.tar.gz" && ! -f "SSH.log" ]]; then
    echo "  Extracting SSH.tar.gz..."
    tar -xzf SSH.tar.gz --strip-components=1 --wildcards "*.log" 2>/dev/null \
        || tar -xzf SSH.tar.gz 2>/dev/null
    # Find and move the log if extracted to a subdir
    find . -maxdepth 2 -name "SSH.log" ! -path "./SSH.log" -exec mv {} ./SSH.log \; 2>/dev/null || true
    echo "  [OK] SSH.log extracted"
fi

# ── Linux Syslog (Loghub — Linux) ─────────────────────────────
LINUX_URL="https://zenodo.org/record/8196385/files/Linux.tar.gz?download=1"
download_if_missing "$LINUX_URL" "Linux.tar.gz" "Linux.tar.gz from Zenodo (Loghub)"

if [[ -f "Linux.tar.gz" && ! -f "Linux.log" ]]; then
    echo "  Extracting Linux.tar.gz..."
    tar -xzf Linux.tar.gz --strip-components=1 --wildcards "*.log" 2>/dev/null \
        || tar -xzf Linux.tar.gz 2>/dev/null
    find . -maxdepth 2 -name "Linux.log" ! -path "./Linux.log" -exec mv {} ./Linux.log \; 2>/dev/null || true
    echo "  [OK] Linux.log extracted"
fi

echo ""
echo "Done. Datasets available:"
for f in SSH.log Linux.log; do
    if [[ -f "$f" ]]; then
        echo "  $f — $(du -sh "$f" | cut -f1) — $(wc -l < "$f") lines"
    else
        echo "  $f — NOT found (check URL or extract manually from .tar.gz)"
    fi
done

echo ""
echo "Run the benchmark:"
echo "  source venv/bin/activate && python benchmark/scripts/run_benchmark.py"
