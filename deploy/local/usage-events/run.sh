#!/usr/bin/env bash
# Run the usage-events example entirely on this machine:
#   - the demo application
#   - the reference audit plugin (cmd/plugin-audit-echo, from the source tree)
#   - Gate One with the embedded dev identity provider (loopback only)
#
#   ./run.sh          start all three, then Ctrl-C to stop
#
# Needs Go and the Gate One source repository for the reference plugin.
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
source ../lib.sh

GATE_ONE="$(require_bin gate-one)"
need_python

if ! command -v go >/dev/null 2>&1; then
	echo "error: go is required to run the reference plugin (cmd/plugin-audit-echo)" >&2
	exit 1
fi
if [ ! -d "$REPO_ROOT/cmd/plugin-audit-echo" ]; then
	echo "error: cmd/plugin-audit-echo is missing; this demo needs the Gate One source tree" >&2
	exit 1
fi

export GATE_ONE_SUBJECT_SECRET=local-subject-secret
export GATE_ONE_PLUGIN_SECRET=local-plugin-secret

python3 -m http.server 8080 --bind 127.0.0.1 --directory ../_app &
SERVER_PID=$!
(
	cd "$REPO_ROOT"
	exec go run ./cmd/plugin-audit-echo -addr :9100 -name com.cladone.audit
) &
PLUGIN_PID=$!
cleanup() {
	kill "$SERVER_PID" "$PLUGIN_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "application: http://127.0.0.1:8080"
echo "plugin:      http://127.0.0.1:9100 (events are logged below)"
sleep 1
"$GATE_ONE" -check -config config/routes.json
"$GATE_ONE" -config config/routes.json
