#!/usr/bin/env bash
# Cladone Gate One — local run (reads ./testdata/api-routes.json)
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
go run ./cmd/gate-one -config testdata/api-routes.json
