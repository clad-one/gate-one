#!/usr/bin/env bash
# Start (or stop) the two-tenant Redis demo.
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
logs)  compose logs -f gate-one-1 gate-one-2 iam-mycompany iam-contoso; exit 0 ;;
up)    ;;
*)     echo "usage: $0 [up|down|logs]" >&2; exit 2 ;;
esac

prepare_bins gate-one cladone-auth demo-idp
compose_cmd
compose up -d
wait_http http://127.0.0.1:8080/healthz http://127.0.0.1:8090/healthz

cat <<'EOF'
Tenant mycompany (alice@mycompany.test, role admin):
  http://app.mycompany.localhost:8080      Gate One instance 1
  http://app.mycompany.localhost:8090      Gate One instance 2 — same session
  http://api.mycompany.localhost:8080      401 JSON without a session
  http://public.mycompany.localhost:8080   no authentication

Tenant contoso (bob@contoso.test, role user):
  http://app.contoso.localhost:8080        separate IAM and issuer

Sign in on instance 1, then open instance 2: the session is accepted
without a new login (shared Redis + shared session key). Sign out from
the badge and both instances refuse the session again.

The demo IdPs auto-consent: there is no password prompt.

Stop:  ./run.sh down
EOF
