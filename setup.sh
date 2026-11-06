#!/usr/bin/env bash
# Lamplight Pay 3.0 — set up the test environment and run the suite.
#
# Usage: ./setup.sh
#   Creates .venv (if missing), installs the pinned dependencies from
#   requirements.txt, downloads solc 0.8.24, then runs the full test
#   suite. Needs network the first time (PyPI + solc download).
#   The full suite takes ~13 minutes; use
#   `.venv/bin/python -m pytest tests/test_v3_whitelist.py -q`
#   for a fast smoke check instead.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -c "import solcx; solcx.install_solc('0.8.24')"
.venv/bin/python -m pytest tests/ -q
