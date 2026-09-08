#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
if command -v uv >/dev/null 2>&1; then
  PYTHON=(uv run --locked --extra dev python)
elif [[ -x "$ROOT/.venv/bin/python" ]]; then
  PYTHON=("$ROOT/.venv/bin/python")
elif [[ -x "$ROOT/.venv/Scripts/python.exe" ]]; then
  PYTHON=("$ROOT/.venv/Scripts/python.exe")
else
  printf 'No project environment found. Run scripts/bootstrap.sh first.\n' >&2
  exit 2
fi
"${PYTHON[@]}" -m compileall -q src tests
"${PYTHON[@]}" scripts/verify_repo.py
"${PYTHON[@]}" scripts/regenerate_conformance_fixtures.py --check
"${PYTHON[@]}" scripts/regenerate_m2_fixtures.py --check
"${PYTHON[@]}" scripts/verify_m2_fixtures.py
"${PYTHON[@]}" -m ruff check src tests scripts
"${PYTHON[@]}" -m ruff format --check src tests scripts
"${PYTHON[@]}" -m pyright
"${PYTHON[@]}" scripts/regenerate_demo_docs.py --check
"${PYTHON[@]}" -m unittest discover -s tests -v
"${PYTHON[@]}" -m variaxiom.cli --home .variaxiom demo --reset >/dev/null
"${PYTHON[@]}" -m variaxiom.cli --home .variaxiom verify
printf '\nVariaxiom verification complete.\n'
