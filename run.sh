#!/usr/bin/env bash
# WebShield AI Runner Script for Termux
# Usage: ./run.sh [args]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ $# -eq 0 ]; then
    python3 main.py
else
    python3 main.py "$@"
fi
