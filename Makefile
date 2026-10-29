build: ## Compile le binaire dans bin/gate-one
	./build.sh

test: ## go vet + tests unitaires
	go vet ./...
	go test ./...

test-auth: ## Tests d'acceptation auth (AC-AUTH-*) + broker + conformité
	go test ./cmd/gate-one/... ./internal/authn/... ./internal/broker/... ./internal/core/... ./internal/proxy/... ./pkg/identityadapter/... ./pkg/pluginmanifest/... -run 'TestAC_AUTH_' -count=1
	go test ./internal/broker/... ./internal/testutil/... ./pkg/identityadapter/... ./pkg/pluginmanifest/... -count=1

test-auth-race: ## Tests auth sous le race detector
	go test -race ./cmd/gate-one/... ./internal/authn/... ./internal/broker/... ./internal/proxy/... ./pkg/identityadapter/... ./pkg/pluginmanifest/... -run 'TestAC_AUTH_' -count=1
	go test -race ./internal/testutil/... -count=1

test-e2e: ## E2E in-process (faux Google, 2 brokers, 2 Gate One, Redis)
	go test -tags=e2e -count=1 ./test/e2e/...

e2e-up: ## Démarre la stack E2E locale (fake Google + broker + Redis + 2 Gate One)
	docker compose -f testdata/auth/compose/compose.yaml up -d --build

e2e-down: ## Arrête et supprime la stack E2E locale
	docker compose -f testdata/auth/compose/compose.yaml down -v

build-auth: ## Compile le broker OIDC dans bin/cladone-auth
	go build -o ./bin/cladone-auth ./cmd/cladone-auth

build-fake-google: ## Compile le faux Google dans bin/fake-google
	go build -o ./bin/fake-google ./cmd/fake-google

smoke: build ## Smoke test bout-en-bout (backend + auth-bridge factices)
	./smoke.sh

run: ## Lance le binaire avec la config de référence
	./run.sh

check: build ## Valide la config de référence sans démarrer
	./bin/gate-one -config testdata/api-routes.json -check

release: ## Prépare les artefacts locaux dans dist/ (aucun push, aucun tag)
	./release.sh

.PHONY: build test test-auth test-auth-race test-e2e e2e-up e2e-down build-auth build-fake-google smoke run check release
