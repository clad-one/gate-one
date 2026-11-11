#!/usr/bin/env bash
# Send a few requests through the running demo, then audit the retained
# records and prove that a tampered snapshot is rejected.
#
#   ./verify.sh            (run.sh must be running in another terminal)
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

WORK="${WORK_DIR:-$PWD/.run}"
if [ ! -f "$WORK/env" ]; then
	echo "error: $WORK/env not found; start ./run.sh first" >&2
	exit 1
fi
# shellcheck disable=SC1090
set -a
source "$WORK/env"
set +a
GATE_ONE="${GATE_ONE_BIN:-$PWD/../../../bin/gate-one}"
export GATE_ONE_BIN="$GATE_ONE"

echo "== 5 requests (1 cent each, no receiver)"
for i in $(seq 1 5); do
	curl -s -o /dev/null -H "Host: app.localhost" \
		"http://127.0.0.1:$GW_PORT/?audit=$i"
done
sleep 1

echo
echo "== replay each retained record against its tariff"
"$GATE_ONE" meter verify -config "$WORK/routes.json"

echo
echo "== signed snapshot, verified offline"
"$GATE_ONE" meter export -config "$WORK/routes.json" \
	-out "$WORK/audit.json"
"$GATE_ONE" meter check -file "$WORK/audit.json" -publicKey "$SINK_PUB"

echo
echo "== tamper detection"
python3 - "$WORK/audit.json" "$WORK/tampered.json" <<'PY'
import base64
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
raw = base64.urlsafe_b64decode(doc["records"][0]["data"] + "==")
rec = json.loads(raw)
rec["amountMicro"] = rec["amountMicro"] + 1
doc["records"][0]["data"] = base64.urlsafe_b64encode(
    json.dumps(rec, separators=(",", ":")).encode()).decode().rstrip("=")
json.dump(doc, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY
if "$GATE_ONE" meter check -file "$WORK/tampered.json" \
	-publicKey "$SINK_PUB" >/dev/null 2>&1; then
	echo "FAIL: the tampered snapshot was accepted" >&2
	exit 1
fi
echo "tampered snapshot rejected, as expected"

echo
echo "== outbox (nothing is committed without a receipt)"
"$GATE_ONE" billing pending -config "$WORK/routes.json"
