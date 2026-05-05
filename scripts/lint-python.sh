#!/usr/bin/env bash
# lint-python.sh — Lint Python scripts using ruff
# Usage: bash scripts/lint-python.sh

set -euo pipefail

if ! command -v ruff &>/dev/null; then
  echo "ruff is not installed. Install with: pip install ruff  or  uv tool install ruff"
  exit 1
fi

ruff check scripts/
