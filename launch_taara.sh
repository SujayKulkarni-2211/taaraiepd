#!/usr/bin/env bash
# TAARA — single launch script.
# Kills any stale process on port 8765, then starts Electron which owns the Python server.

cd "$(dirname "$0")"

# Kill anything on port 8765 from a previous session — be thorough
PIDS=$(lsof -ti:8765 2>/dev/null)
if [ -n "$PIDS" ]; then
  echo "[TAARA] Killing stale processes on port 8765: $PIDS"
  kill -TERM $PIDS 2>/dev/null
  sleep 1.2
  # Force kill if still running
  PIDS=$(lsof -ti:8765 2>/dev/null)
  if [ -n "$PIDS" ]; then
    kill -KILL $PIDS 2>/dev/null
    sleep 0.5
  fi
fi

# Electron must not run as plain Node
unset ELECTRON_RUN_AS_NODE

export DISPLAY="${DISPLAY:-:0}"

exec ./desktop/node_modules/electron/dist/electron ./desktop "$@"
