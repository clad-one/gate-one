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
	$(COMPOSE) up -d --remove-orphans

demo: check
	$(COMPOSE) --profile demo up -d --remove-orphans

ha: check
	$(COMPOSE) --profile ha up -d --remove-orphans

down:
	$(COMPOSE) --profile demo --profile ha down --remove-orphans

logs:
	$(COMPOSE) --profile demo --profile ha logs -f traefik gate-one broker

reload:
	$(COMPOSE) kill -s HUP gate-one

check:
	@./render.sh >/dev/null
	@set -a; . ./.env; set +a; \
		"$${BIN_DIR:-./bin}/gate-one" -check -config config/routes.json

destroy:
	$(COMPOSE) --profile demo --profile ha down -v --remove-orphans
	rm -rf config data
