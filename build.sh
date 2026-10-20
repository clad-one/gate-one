#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

# go mod tidy
# code formating: go fmt ./... gofmt -w internal/proxy/auth.go
go build -o ./bin/gate-one ./cmd/gate-one
