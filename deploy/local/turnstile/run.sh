#!/usr/bin/env bash
# Turnstile demo on *.localhost, no domain and no account.
#
#   ./run.sh gate    # the whole page is gated (paths: ["/*"])
#   ./run.sh api     # only the action is gated (paths: ["/api/*"])
#
# Cloudflare's always-passing test keys are used: the widget loads
# from challenges.cloudflare.com (internet required) and Siteverify
# accepts the token with the test secret.
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
source ../lib.sh

MODE="${1:-gate}"
case "$MODE" in
	gate | api) ;;
	*)
		echo "usage: ./run.sh [gate|api]" >&2
		exit 2
		;;
esac

GATE_ONE="$(require_bin gate-one)"
need_python

CONFIG="config/routes.${MODE}.json"
[ -f "$CONFIG" ] || { echo "missing $CONFIG" >&2; exit 1; }

# Cloudflare's public test secret (always passes). Override to use a
# real widget.
export TURNSTILE_SECRET="${TURNSTILE_SECRET:-1x0000000000000000000000000000000AA}"
export TURNSTILE_DEMO_MODE="$MODE"

python3 app/server.py 8081 &
SERVER_PID=$!
cleanup() { kill "$SERVER_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

echo "backend:     http://127.0.0.1:8081 (serving app/)"
echo "mode:        $MODE"
echo "open:        http://app.demo.localhost:3000/"
echo
"$GATE_ONE" -check -config "$CONFIG"
"$GATE_ONE" -config "$CONFIG"
