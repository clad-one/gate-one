#!/usr/bin/env bash
# Metering audit demo — user side only.
#
#   Gate One ──metric──► hold ──settle──► outbox (no receiver: pending)
#                                             │
#                                             └──► gate-one meter verify|export|check
#
#   ./run.sh      start the gateway, then Ctrl-C to stop
#   ./verify.sh   send requests and audit the retained records
#
# There is deliberately no receiver here: every record stays in the local
# outbox, which is what the offline audit reads. Delivery and invoicing
# are the managed service's job, not this demo's.
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
source ../lib.sh

GATE_ONE="$(require_bin gate-one)"
need_python

GW_PORT="${GW_PORT:-18180}"
APP_PORT="${APP_PORT:-18182}"
WORK="${WORK_DIR:-$PWD/.run}"
rm -rf "$WORK"
mkdir -p "$WORK"

key_field() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"; }

"$GATE_ONE" keygen -out "$WORK/sink.key" -keyId sink-demo >/dev/null
"$GATE_ONE" keygen -out "$WORK/issuer.key" -keyId issuer-demo >/dev/null
SINK_SEED="$(key_field "$WORK/sink.key" seed)"
SINK_PUB="$(key_field "$WORK/sink.key" publicKey)"
ISSUER_PUB="$(key_field "$WORK/issuer.key" publicKey)"

EXPIRES="$(python3 -c 'import datetime as d;print((d.datetime.now(d.timezone.utc)+d.timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))')"
"$GATE_ONE" allowance -key "$WORK/issuer.key" -tenant default -metric '*' \
	-amount-micro 50000000 -expires "$EXPIRES" -out "$WORK/allowance.json" 2>/dev/null

python3 -m http.server "$APP_PORT" --bind 127.0.0.1 --directory ../_app \
	>"$WORK/app.log" 2>&1 &
APP_PID=$!

export DEMO_SUBJECT_SECRET=local-subject-secret
export DEMO_PLUGIN_SECRET=local-plugin-secret
export DEMO_SINK_KEY="$SINK_SEED"

cat >"$WORK/routes.json" <<JSON
{
  "authProvider": {
    "type": "dev",
    "loginBaseUrl": "http://login.dev.localhost:3000",
    "cookieDomain": "dev.localhost"
  },
  "usage": {
    "dir": "$WORK/usage-wal",
    "nodeId": "gw-audit",
    "subjectSecretEnv": "DEMO_SUBJECT_SECRET",
    "pluginSecretEnv": "DEMO_PLUGIN_SECRET",
    "budgetBytes": 1048576,
    "types": {"billing": {"shareBytes": 1048576, "fsync": "none"}},
    "profile": "online",
    "allowanceFile": "$WORK/allowance.json",
    "allowancePublicKey": "$ISSUER_PUB",
    "sink": {
      "url": "http://127.0.0.1:1",
      "signingKeyEnv": "DEMO_SINK_KEY",
      "batchWaitMs": 200,
      "exportDir": "$WORK/export"
    },
    "metrics": {
      "api.request": {
        "unit": "request", "scale": 0, "maxDimensions": 1,
        "dimensions": {"route": {"type": "string", "maxLength": 64}}
      }
    },
    "tariffs": {
      "api.request.v1": {
        "metric": "api.request", "version": "api.request.v1",
        "currency": "EUR", "effectiveFrom": "2026-01-01T00:00:00Z",
        "charges": [{"model": "unit", "amountMicro": 10000}]
      }
    }
  },
  "routes": [{
    "host": "app.localhost", "path": "/*",
    "backend": "http://127.0.0.1:$APP_PORT",
    "metric": "api.request"
  }]
}
JSON

cat >"$WORK/env" <<ENV
GW_PORT=$GW_PORT
WORK=$WORK
SINK_PUB=$SINK_PUB
DEMO_SUBJECT_SECRET=$DEMO_SUBJECT_SECRET
DEMO_PLUGIN_SECRET=$DEMO_PLUGIN_SECRET
DEMO_SINK_KEY=$DEMO_SINK_KEY
ENV

GW_PID=""
cleanup() {
	[ -n "$GW_PID" ] && kill "$GW_PID" 2>/dev/null || true
	kill "$APP_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

sleep 1
"$GATE_ONE" -check -config "$WORK/routes.json" >/dev/null
echo "gateway: http://127.0.0.1:$GW_PORT  (Host: app.localhost)"
echo "state:   $WORK   (verify.sh reads $WORK/env)"
echo
"$GATE_ONE" -config "$WORK/routes.json" -addr "127.0.0.1:$GW_PORT" &
GW_PID=$!
wait "$GW_PID"
