#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
PYTHON_BIN="$(command -v python3 || command -v python || true)"

if [ -z "$PYTHON_BIN" ]; then
    echo "❌ Error: Python 3 is required to run the test suite." >&2
    exit 1
fi

exec "$PYTHON_BIN" "$SCRIPT_DIR/test.py" "$@"
