#!/usr/bin/env bash
# Start (or stop) the multi-application SSO demo.
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
logs)  compose logs -f gate-one demo-idp app reports; exit 0 ;;
up)    ;;
*)     echo "usage: $0 [up|down|logs]" >&2; exit 2 ;;
esac

prepare_bins gate-one demo-idp
compose_cmd
compose up -d
wait_http http://127.0.0.1:8080/healthz

cat <<'EOF'
Open:      http://app.demo.localhost:8080
then:      http://reports.demo.localhost:8080

Sign in on either host. The second application does not ask again: the
same provider verified both routes and the session cookie is shared on
demo.localhost. The backend title tells you which application answered.

Two things enable SSO, both visible in config/routes.json:
  * the same authProvider for both routes;
  * a cookieDomain covering both hosts.

Stop:      ./run.sh down
EOF
