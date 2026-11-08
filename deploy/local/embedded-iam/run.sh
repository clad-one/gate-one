#!/usr/bin/env bash
# Start (or stop) the local embedded IAM demo.
#
#   ./run.sh                 start, wait for readiness, print the URL
#   ./run.sh down            stop and remove the containers
#   ./run.sh logs            follow the Gate One and IAM logs
#   ./run.sh user <args...>  run the IAM admin CLI inside the stack
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
source ../lib.sh

compose() { docker compose -f compose.yml "$@"; }

case "${1:-up}" in
down) compose down -v; exit 0 ;;
logs) compose logs -f gate-one cladone-auth demo-idp; exit 0 ;;
user)
	shift
	compose exec cladone-auth /bin/cladone-auth user "$@" -config /config/embedded-iam.json
	exit $?
	;;
up) ;;
*)
	echo "usage: $0 [up|down|logs|user <args>]" >&2
	exit 2
	;;
esac

prepare_bins gate-one cladone-auth demo-idp
compose_cmd
compose up -d
wait_http http://127.0.0.1:8080/healthz

cat <<'EOF'
Open:      http://app.demo.localhost:8080
Sign in:   alice@demo.test (mapped to role admin) or bob@demo.test (role user)
           The demo IdP auto-consents: there is no password prompt.

The backend shows the identity headers Gate One sends (X-User-Id,
X-Email, X-Roles, ...). Rights come from two places:

  * the claim mapping in config/embedded-iam.json (groups=admins -> role admin);
  * per-user grants, editable live after the first sign-in:

      ./run.sh user list -tenant demo
      ./run.sh user set  -tenant demo \
          -issuer http://idp.demo.localhost:9000 -sub idp-alice \
          -roles admin,editor

    Sign out and back in to see the new roles.

(.localhost resolves to loopback; run the browser on this machine.)

Stop:      ./run.sh down
EOF
