#!/usr/bin/env bash
# lint-markdown.sh — Lint all markdown files using markdownlint-cli2
# Usage: bash scripts/lint-markdown.sh

set -euo pipefail

if ! command -v markdownlint-cli2 &>/dev/null; then
  echo "markdownlint-cli2 is not installed. Install with: npm install -g markdownlint-cli2"
  exit 1
fi

markdownlint-cli2 "**/*.md" "#node_modules" "#.venv"
