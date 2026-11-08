#!/usr/bin/env bash
# Run the account-panel example entirely on this machine:
#   - the application with its own account panel
#   - Gate One, using the embedded dev identity provider (loopback only)
#
#   ./run.sh          start both, then Ctrl-C to stop
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
source ../lib.sh

GATE_ONE="$(require_bin gate-one)"
need_python

APP_DIR="config"
[ -d "$APP_DIR" ] || { echo "error: $APP_DIR is missing" >&2; exit 1; }

python3 -m http.server 8080 --bind 127.0.0.1 --directory "$APP_DIR" &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

echo "application: http://127.0.0.1:8080 (serving $APP_DIR)"
"$GATE_ONE" -check -config config/routes.json
"$GATE_ONE" -config config/routes.json
