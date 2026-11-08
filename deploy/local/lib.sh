#!/usr/bin/env bash
# Shared helpers for the local demos under deploy/local/.
#
# The demos never build Gate One. Binary lookup order:
#   1. $BIN_DIR (default: ./bin next to the demo)
#   2. a sibling source checkout built with ./build.sh (../bin)
#   3. the PATH
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
DEMO_BIN_DIR="${BIN_DIR:-$PWD/bin}"

find_bin() {
	local name="$1" candidate
	for candidate in "$DEMO_BIN_DIR/$name" "$REPO_ROOT/bin/$name"; do
		if [ -x "$candidate" ]; then
			printf '%s\n' "$candidate"
			return 0
		fi
	done
	if command -v "$name" >/dev/null 2>&1; then
		command -v "$name"
		return 0
	fi
	return 1
}

require_bin() {
	local name="$1" path
	if ! path="$(find_bin "$name")"; then
		cat >&2 <<EOF
error: '$name' was not found.

Put the binaries in one of:
  - $DEMO_BIN_DIR  (recommended: export BIN_DIR=/path/to/bin)
  - $REPO_ROOT/bin (this source checkout, after ./build.sh)
  - any directory in your PATH

Release assets: https://github.com/clad-one/gate-one/releases
  gate-one_<version>_<os>_<arch>.tar.gz          -> gate-one
  cladone-auth_<version>_<os>_<arch>.tar.gz      -> cladone-auth
  gate-one-demo-idp_<version>_<os>_<arch>.tar.gz -> demo-idp (test IdP, never production)

Verify the checksums before running anything.
EOF
		exit 1
	fi
	printf '%s\n' "$path"
}

# prepare_bins <tool>... — export BIN_DIR and require every tool there,
# because the compose files mount them from a single directory.
prepare_bins() {
	local first tool
	first="$(require_bin "$1")"
	BIN_DIR="$(cd -- "$(dirname -- "$first")" && pwd)"
	export BIN_DIR
	for tool in "$@"; do
		require_bin "$tool" >/dev/null
		if [ ! -x "$BIN_DIR/$tool" ]; then
			echo "error: $tool must sit next to $1 in $BIN_DIR" >&2
			exit 1
		fi
	done
}

compose_cmd() {
	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
		return 0
	fi
	echo "error: docker compose v2 is required by this demo" >&2
	exit 1
}

# wait_http <url>... — wait up to 60s for every URL to answer.
wait_http() {
	local url ok
	printf 'waiting for the stack'
	for _ in $(seq 1 60); do
		ok="yes"
		for url in "$@"; do
			if ! curl -fsS "$url" >/dev/null 2>&1; then
				ok=""
				break
			fi
		done
		if [ -n "$ok" ]; then
			printf '\n'
			return 0
		fi
		printf '.'
		sleep 1
	done
	printf '\n'
	echo "the stack did not become ready; run './run.sh logs'." >&2
	return 1
}

need_python() {
	command -v python3 >/dev/null 2>&1 || {
		echo "error: python3 is required by this demo" >&2
		exit 1
	}
}
