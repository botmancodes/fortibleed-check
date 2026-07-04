#!/usr/bin/env bash
# make_venv.sh — create a local virtual environment for fortibleed-check.
#
# Strictly optional: the scripts are stdlib-only and run fine with any
# system Python 3.9+. The venv just gives you an isolated, reproducible
# interpreter (and a place for dev tools if you add any).
#
# Usage:
#   ./make_venv.sh
#   source .venv/bin/activate

set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

if ! "$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)'; then
    echo "ERROR: Python 3.9+ required (found: $("$PYTHON" --version 2>&1))" >&2
    exit 1
fi

"$PYTHON" -m venv .venv
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt

echo "Done. Activate with:  source .venv/bin/activate"
echo "Then run:             python3 fortibleed_check_offline.py --help"
