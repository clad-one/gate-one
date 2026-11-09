#!/usr/bin/env bash
# Validate the three ingress examples in this directory with the real
# implementations, in containers. Skips (exit 0) when Docker is absent.
#
#   ./examples/reverse-proxy/validate.sh
#
# No port is bound and no network is used: nginx and Caddy only parse
# their configuration; Traefik is started briefly on high ports to catch
# static/dynamic configuration errors.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if ! command -v docker >/dev/null 2>&1; then
	echo "validate-ingress: docker is required (skipped)"
	exit 0
fi
if ! command -v openssl >/dev/null 2>&1; then
	echo "validate-ingress: openssl is required (skipped)"
	exit 0
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/gate-one-ingress.XXXXXX")"
cleanup() { rm -rf "$tmp"; }
trap cleanup EXIT

# Throwaway certificate so `nginx -t` can load the TLS block.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-subj "/CN=app.example.com" \
	-keyout "$tmp/privkey.pem" -out "$tmp/fullchain.pem" >/dev/null 2>&1

echo "== nginx: syntax and TLS load"
docker run --rm -v "$PWD/nginx.conf:/etc/nginx/nginx.conf:ro" \
	-v "$tmp:/etc/nginx/certs:ro" nginx:alpine nginx -t 2>&1 | tail -2

echo "== caddy: configuration"
docker run --rm -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" \
	caddy:2 caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | tail -2

echo "== traefik: static + dynamic configuration"
mkdir -p "$tmp/data"
# Traefik has no config dry-run: it exits on an invalid static file and logs
# "field not found"/"error while parsing rule" for a bad dynamic file. So we
# start it briefly with no network, then assert the file provider loaded and
# no configuration error was reported. ACME and the /readyz probe fail here
# by design (no internet, no gateway) and are ignored.
traefik_log="$tmp/traefik.log"
timeout 15 docker run --rm --network none 	-v "$PWD/traefik.yml:/etc/traefik/traefik.yml:ro" 	-v "$PWD/traefik-dynamic.yml:/etc/traefik/traefik-dynamic.yml:ro" 	-v "$tmp/data:/data" 	traefik:v3.1 --configfile=/etc/traefik/traefik.yml \
	--log.level=DEBUG >"$traefik_log" 2>&1 || true

if grep -qiE "field not found|configuration error|error while parsing rule|invalid configuration" "$traefik_log"; then
	echo "traefik: INVALID configuration"
	grep -iE "field not found|configuration error|error while parsing rule|invalid configuration" "$traefik_log" | head -3
	exit 1
fi
if ! grep -q "Starting provider \*file.Provider" "$traefik_log"; then
	echo "traefik: the file provider did not start"
	exit 1
fi
echo "traefik: static and dynamic configurations accepted"

echo "validate-ingress: all three configurations are valid"
