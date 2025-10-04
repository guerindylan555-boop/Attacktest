#!/usr/bin/env bash
# launch the simplified control center using the project's virtualenv
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${SCRIPT_DIR}/.venv"

# Ensure virtualenv exists
if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
  echo "[setup] Creating virtual environment at ${VENV_DIR}"
  python3 -m venv "${VENV_DIR}"
fi

# Always ensure required packages are installed before launch
if [[ -f "${SCRIPT_DIR}/requirements.txt" ]]; then
  echo "[setup] Installing/updating Python dependencies"
  "${VENV_DIR}/bin/pip" install -r "${SCRIPT_DIR}/requirements.txt"
else
  echo "[warn] requirements.txt not found at ${SCRIPT_DIR}; skipping install" >&2
fi

# Provide sensible defaults for automation environment variables if user hasn't set them.
export MAYNDRIVE_APP_PACKAGE="${MAYNDRIVE_APP_PACKAGE:-fr.mayndrive.app}"
export MAYNDRIVE_APP_ACTIVITY="${MAYNDRIVE_APP_ACTIVITY:-city.knot.mayndrive.ui.MainActivity}"

# Default structured log sink so GUI/CLI writes JSONL when none provided.
export AUTOMATION_LOG_FILE="${AUTOMATION_LOG_FILE:-${SCRIPT_DIR}/automation/logs/control_center.jsonl}"

# Optionally expose metrics server unless user explicitly disables it.
export AUTOMATION_METRICS_PORT="${AUTOMATION_METRICS_PORT:-8008}"

exec "${VENV_DIR}/bin/python" -m automation.ui.control_center "$@"
