#!/usr/bin/env bash
set -euo pipefail
cd /workspace/Threat-Intelligence-Graph
if [[ ! -x /workspace/tig-venv/bin/python ]]; then
  python3 -m venv /workspace/tig-venv
fi
export PIP_CACHE_DIR=/workspace/.cache/pip
/workspace/tig-venv/bin/python -m pip install --require-virtualenv -r requirements.txt
/workspace/tig-venv/bin/python -m pip check
/workspace/tig-venv/bin/python scripts/fetch_attack.py
if [[ ! -f local/demo.sqlite3 ]]; then
  /workspace/tig-venv/bin/python scripts/demo.py
fi
