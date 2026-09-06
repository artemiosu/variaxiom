#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"
python3 -m compileall -q src tests
python3 scripts/verify_repo.py
PYTHONPATH=src python3 scripts/regenerate_demo_docs.py
python3 -m unittest discover -s tests -v
python3 -m variaxiom.cli --home .variaxiom demo --reset >/dev/null
python3 -m variaxiom.cli --home .variaxiom verify
printf '\nVariaxiom verification complete.\n'
