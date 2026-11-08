#!/usr/bin/env bash
# First-run setup: create .env, generate the empty secrets, render config/.
#
#   ./init.sh
#
# Idempotent: existing secrets and configuration are kept.
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if [ ! -f .env ]; then
	cp .env.example .env
	echo "created .env from .env.example"
fi

if ! grep -Eq '^DOMAIN=.+' .env; then
	echo "Set DOMAIN (and ACME_EMAIL) in .env, then run 'make init' again." >&2
	exit 1
fi

secret() {
	openssl rand -base64 32 | tr -d '\n'
}

set_if_empty() {
	local name="$1" value
	if ! grep -Eq "^${name}=.+" .env; then
		value="$(secret)"
		if grep -Eq "^${name}=" .env; then
			sed -i "s|^${name}=.*|${name}=${value}|" .env
		else
			printf '%s=%s\n' "$name" "$value" >>.env
		fi
		echo "generated ${name}"
	fi
}

set_if_empty GATE_ONE_OIDC_CLIENT_SECRET
set_if_empty GATE_ONE_SESSION_KEY

./render.sh
