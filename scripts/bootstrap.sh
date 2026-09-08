#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

git config core.hooksPath .githooks

if ! command -v uv >/dev/null 2>&1; then
  echo "uv 0.12.5 is required; install it from https://docs.astral.sh/uv/getting-started/installation/" >&2
  exit 1
fi

uv sync --locked --extra dev
uv run --locked --extra dev variaxiom demo --reset
uv run --locked --extra dev python -m unittest discover -s tests -v
