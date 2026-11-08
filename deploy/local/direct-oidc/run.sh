#!/usr/bin/env bash
# Start (or stop) the direct OIDC demo.
#
#   ./run.sh          start, wait for readiness, print the URLs
#   ./run.sh down     stop and remove the containers
#   ./run.sh logs     follow the container logs
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
source ../lib.sh

compose() { docker compose -f compose.yml "$@"; }

case "${1:-up}" in
down)  compose down -v; exit 0 ;;
logs)  compose logs -f gate-one demo-idp; exit 0 ;;
up)    ;;
*)     echo "usage: $0 [up|down|logs]" >&2; exit 2 ;;
esac

prepare_bins gate-one demo-idp
compose_cmd
compose up -d
wait_http http://127.0.0.1:8080/healthz

cat <<'EOF'
Open:      http://app.demo.localhost:8080
Sign in:   alice@demo.test or bob@demo.test (the demo IdP auto-consents).

Gate One is the OIDC relying party: it talks to the issuer directly,
with no IAM in between. The backend shows the identity headers, and the
user badge shows the roles the issuer put in the token.

Replace the issuer in config/routes.json with a real one (Keycloak,
Entra ID, Google) to use this shape in production.

Stop:      ./run.sh down
EOF
