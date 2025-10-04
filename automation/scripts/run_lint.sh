#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

printf '==> Running compileall checks\n'
python3 -m compileall automation/session automation/replay automation/ui_catalog automation/logs automation/scripts >/dev/null

if command -v mypy >/dev/null 2>&1; then
  printf '==> Running mypy type checks\n'
  mypy automation/session automation/replay automation/ui_catalog || exit 1
else
  printf '==> Skipping mypy (not installed)\n'
fi

printf 'Lint checks completed successfully\n'
