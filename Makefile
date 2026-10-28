build: ## Compile le binaire dans bin/gate-one
	./build.sh

test: ## go vet + tests unitaires
	go vet ./...
	go test ./...

test-auth: ## Tests d'acceptation auth (AC-AUTH-*) + broker + conformité
	go test ./cmd/gate-one/... ./internal/authn/... ./internal/broker/... ./internal/core/... ./internal/proxy/... ./pkg/identityadapter/... ./pkg/pluginmanifest/... -run 'TestAC_AUTH_' -count=1
	go test ./internal/broker/... ./pkg/identityadapter/... ./pkg/pluginmanifest/... -count=1

test-auth-race: ## Tests auth sous le race detector
	go test -race ./cmd/gate-one/... ./internal/authn/... ./internal/broker/... ./internal/proxy/... ./pkg/identityadapter/... ./pkg/pluginmanifest/... -run 'TestAC_AUTH_' -count=1

build-auth: ## Compile le broker OIDC dans bin/cladone-auth
	go build -o ./bin/cladone-auth ./cmd/cladone-auth

smoke: build ## Smoke test bout-en-bout (backend + auth-bridge factices)
	./smoke.sh

run: ## Lance le binaire avec la config de référence
	./run.sh

check: build ## Valide la config de référence sans démarrer
	./bin/gate-one -config testdata/api-routes.json -check

release: ## Prépare les artefacts locaux dans dist/ (aucun push, aucun tag)
	./release.sh

.PHONY: build test test-auth test-auth-race build-auth smoke run check release
