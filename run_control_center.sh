#!/usr/bin/env bash
# launch the simplified control center using the project's virtualenv
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"

if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  echo "[ERROR] Virtualenv missing at ${VENV_DIR}." >&2
  echo "        Run 'python3 -m venv .venv && .venv/bin/pip install -r requirements.txt' first." >&2
  exit 1
fi

exec "${VENV_DIR}/bin/python" -m automation.ui.control_center "$@"
