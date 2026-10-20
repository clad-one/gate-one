build: ## Compile le binaire dans bin/gate-one
	./build.sh

test: ## go vet + tests unitaires
	go vet ./...
	go test ./...

smoke: build ## Smoke test bout-en-bout (backend + auth-bridge factices)
	./smoke.sh

run: ## Lance le binaire avec la config de référence
	./run.sh

check: build ## Valide la config de référence sans démarrer
	./bin/gate-one -config testdata/api-routes.json -check

.PHONY: build test smoke run check
