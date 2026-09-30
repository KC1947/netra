#!/usr/bin/env bash
# Install the engine, server and full test suite into the local Python 3.12 venv.
# Python 3.12, Pango, TShark and Node.js are system prerequisites; see README.md.
# Dependency installation may use the internet. Capture analysis stays offline.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

for executable in python3.12 tshark node; do
  if ! command -v "$executable" >/dev/null 2>&1; then
    echo "Missing prerequisite: $executable. See README.md before retrying." >&2
    exit 1
  fi
done

if [[ ! -x .venv/bin/python ]]; then
  python3.12 -m venv .venv
fi
.venv/bin/python -c 'import sys; assert sys.version_info[:2] == (3, 12), "Use a Python 3.12 virtual environment"'
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip check
# Importing WeasyPrint also checks that its native libraries (including Pango)
# are available. The full suite exercises PDF rendering and schema validation.
.venv/bin/python -c 'from weasyprint import HTML; from fastapi.testclient import TestClient; from cyclonedx.validation.json import JsonStrictValidator'

echo "Setup complete. Run .venv/bin/python -m server.app and open http://127.0.0.1:8000/."
