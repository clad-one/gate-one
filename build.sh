#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

# go mod tidy
# code formating: go fmt ./... gofmt -w internal/proxy/auth.go

version="${VERSION:-$(cat VERSION 2>/dev/null || echo dev)}"
commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

go build \
	-trimpath \
	-ldflags "-X main.version=${version} -X main.commit=${commit} -X main.date=${date}" \
	-o ./bin/gate-one ./cmd/gate-one
