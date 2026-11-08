#!/usr/bin/env bash
# Render the deployment configuration from templates/ and .env.
#
#   ./render.sh          render config/ and prepare data/
#
# Safe to re-run after changing .env (for example a new DOMAIN).
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if [ ! -f .env ]; then
	echo "render: .env is missing; run 'make init'" >&2
	exit 1
fi

set -a
# shellcheck disable=SC1091
. ./.env
set +a

: "${DOMAIN:?render: DOMAIN is required in .env}"
: "${BIN_DIR:=./bin}"

mkdir -p config data

render() {
	local src="$1" dst="$2"
	sed "s|__DOMAIN__|${DOMAIN}|g" "$src" >"$dst"
}

render templates/broker.json.tmpl config/broker.json
render templates/broker.demo.json.tmpl config/broker.demo.json
render templates/routes.json.tmpl config/routes.json
render templates/routes.ha.json.tmpl config/routes.ha.json
cp templates/idp.json config/idp.json

if [ ! -f config/broker.key ]; then
	if [ ! -x "${BIN_DIR}/cladone-auth" ]; then
		echo "render: ${BIN_DIR}/cladone-auth is missing; put the binaries in ${BIN_DIR}" >&2
		exit 1
	fi
	"${BIN_DIR}/cladone-auth" keygen -out config/broker.key
fi
chmod 600 config/broker.key

if [ ! -f data/acme.json ]; then
	touch data/acme.json
fi
chmod 600 data/acme.json

echo "rendered config/ for ${DOMAIN}"
