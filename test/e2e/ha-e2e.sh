#!/usr/bin/env bash
# E2E HA : session active + bascule Sentinel + révocation.
#
#   make test-ha
#
# Le test Go tourne DANS le réseau Docker `cladone-auth-ha` de la pile
# Redis HA de cladone-it-infra (les sentinels n'ont pas de port publié).
# Le script attend que le test ait établi une session, arrête le maître
# courant, puis laisse le test vérifier que la session survit et que la
# révocation est visible.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INFRA_DIR="${INFRA_DIR:-$ROOT/../cladone-it-infra}"
if [ ! -f "$INFRA_DIR/compose/redis-ha.yml" ]; then
  echo "ha-e2e: cladone-it-infra introuvable; set INFRA_DIR=/path/to/cladone-it-infra" >&2
  exit 1
fi

COMPOSE=(docker compose -f "$INFRA_DIR/compose/redis-ha.yml")
MASTER_NAME="${MASTER_NAME:-authmaster}"
PREFIX="${E2E_HA_PREFIX:-cladone:auth:v1:e2e:}"
READY_DIR="$(mktemp -d /tmp/ha-e2e-XXXXXX)"
TEST_BIN="$(mktemp /tmp/ha-e2e-XXXXXX.test)"
CONTAINER=gate-one-ha-e2e

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  # Un drill interrompu ne doit pas laisser le maître arrêté.
  "${COMPOSE[@]}" up -d --wait --wait-timeout 180 >/dev/null 2>&1 || true
  rm -rf "$READY_DIR" "$TEST_BIN"
}
trap cleanup EXIT

envval() {
  grep -E "^$1=" "$INFRA_DIR/compose/.env" | tail -1 | cut -d= -f2-
}

APP="$(envval REDIS_HA_APP_PASSWORD)"
SENT="$(envval REDIS_HA_SENTINEL_PASSWORD)"
if [ -z "$APP" ] || [ -z "$SENT" ]; then
  echo "REDIS_HA_APP_PASSWORD / REDIS_HA_SENTINEL_PASSWORD absents de $INFRA_DIR/compose/.env" >&2
  exit 1
fi

echo "== 1. pile HA"
"$INFRA_DIR/compose/redis-ha/gen-certs.sh" >/dev/null
"${COMPOSE[@]}" up -d --wait --wait-timeout 180 >/dev/null

echo "== 2. compilation du test (tags e2e e2e_ha)"
(
  cd "$ROOT"
  CGO_ENABLED=0 go test -c -tags "e2e e2e_ha" -o "$TEST_BIN" ./test/e2e
)

echo "== 3. exécution (le maître sera arrêté après le login)"
docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run --rm --name "$CONTAINER" \
  --network cladone-auth-ha \
  -e E2E_HA_SENTINELS="redis-sentinel-1:26379,redis-sentinel-2:26379,redis-sentinel-3:26379" \
  -e E2E_HA_MASTER="$MASTER_NAME" \
  -e E2E_HA_SENTINEL_PASSWORD="$SENT" \
  -e E2E_HA_APP_PASSWORD="$APP" \
  -e E2E_HA_CA=/tls/ca.crt \
  -e E2E_HA_SERVER_NAME=redis.cladone.internal \
  -e E2E_HA_PREFIX="$PREFIX" \
  -e E2E_HA_READY_FILE=/shared/ready \
  -v "$TEST_BIN":/test:ro \
  -v "$INFRA_DIR/compose/redis-ha/certs":/tls:ro \
  -v "$READY_DIR":/shared \
  alpine:3 /test -test.v -test.timeout 5m \
  -test.run 'TestE2E_HA_' &
TEST_PID=$!

# Attendre le signal READY (session établie) ou la fin du test.
for _ in $(seq 1 240); do
  [ -f "$READY_DIR/ready" ] && break
  kill -0 "$TEST_PID" 2>/dev/null || break
  sleep 0.5
done
if [ ! -f "$READY_DIR/ready" ]; then
  echo "le test n'a pas signalé READY (échec avant la bascule)" >&2
  wait "$TEST_PID" || true
  exit 1
fi

master_ip="$("${COMPOSE[@]}" exec -T redis-sentinel-1 \
  redis-cli --tls --cacert /tls/ca.crt -p 26379 \
  -a "$SENT" --no-auth-warning \
  sentinel get-master-addr-by-name "$MASTER_NAME" | head -1)"
master_svc=""
for c in redis-master redis-replica-1 redis-replica-2; do
  ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    "cladone-redis-ha-$c-1" 2>/dev/null || true)"
  [ "$ip" = "$master_ip" ] && master_svc="$c"
done
if [ -z "$master_svc" ]; then
  echo "maître Sentinel introuvable ($master_ip)" >&2
  wait "$TEST_PID" || true
  exit 1
fi

echo "== 4. bascule : arrêt de $master_svc ($master_ip)"
"${COMPOSE[@]}" stop "$master_svc" >/dev/null

set +e
wait "$TEST_PID"
rc=$?
set -e
echo "== test exit=$rc"
exit "$rc"
