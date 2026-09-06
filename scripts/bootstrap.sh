#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if command -v uv >/dev/null 2>&1; then
  uv sync
  uv run variaxiom demo --reset
  uv run python -m unittest discover -s tests -v
else
  python3 -m venv .venv
  . .venv/bin/activate
  python -m pip install --upgrade pip
  python -m pip install -e .
  variaxiom demo --reset
  python -m unittest discover -s tests -v
fi
