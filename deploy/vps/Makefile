# Gate One on a VPS — Traefik + Gate One + cladone-auth (+ Google).
#
#   make init     create .env, generate secrets, render config/
#   make up       start the production stack
#   make demo     start the stack plus the demo IdP (no Google needed)
#   make ha       two Gate One replicas + Redis
#   make down     stop everything
#   make logs     follow the logs
#   make reload   re-read the Gate One configuration (SIGHUP)
#   make check    validate the rendered configuration
#   make destroy  stop and delete the volumes and generated config

SHELL := /bin/bash
COMPOSE := docker compose --env-file .env -f compose.yml

.PHONY: init up demo ha down logs reload check destroy

init:
	@./init.sh

up: check
	@set -a; . ./.env; set +a; \
		if [ -z "$$GOOGLE_CLIENT_ID" ] || [ -z "$$GOOGLE_CLIENT_SECRET" ]; then \
			echo "GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are empty in .env."; \
			echo "Set them first, or run 'make demo' to smoke-test the stack"; \
			echo "with the demo IdP (the IAM refuses to start without an upstream)."; \
			exit 1; \
		fi
	$(COMPOSE) up -d --remove-orphans

demo: check
	IAM_CONFIG=/config/embedded-iam.demo.json $(COMPOSE) --profile demo up -d --remove-orphans

ha: check
	@set -a; . ./.env; set +a; \
		if [ -z "$$GOOGLE_CLIENT_ID" ] || [ -z "$$GOOGLE_CLIENT_SECRET" ]; then \
			echo "GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are empty in .env."; \
			echo "Set them first, or run 'make demo' to smoke-test the stack"; \
			echo "with the demo IdP (the IAM refuses to start without an upstream)."; \
			exit 1; \
		fi
	$(COMPOSE) --profile ha up -d --remove-orphans

down:
	$(COMPOSE) --profile demo --profile ha down --remove-orphans

logs:
	$(COMPOSE) --profile demo --profile ha logs -f traefik gate-one cladone-auth

reload:
	$(COMPOSE) kill -s HUP gate-one

check:
	@./render.sh >/dev/null
	@set -a; . ./.env; set +a; \
		"$${BIN_DIR:-./bin}/gate-one" -check -config config/routes.json

destroy:
	$(COMPOSE) --profile demo --profile ha down -v --remove-orphans
	rm -rf config data
