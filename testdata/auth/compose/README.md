# Local auth E2E stack — fake Google + broker + Gate One

Full chain without Keycloak:

```text
browser → Gate One (2 instances) → broker cladone-auth → fake Google
```

Everything runs in Docker, with real hostnames under `*.localhost`
(loopback per RFC 6761), real cookies and Redis-backed revocation.

## Services

| Service | Host / port | Role |
|---|---|---|
| `redis` | internal `redis:6379` | broker store + shared revocation |
| `fake-google-acme` | `http://idp.acme.localhost:9000` | fake Google, user alice |
| `fake-google-contoso` | `http://idp.contoso.localhost:9001` | fake Google, user bob |
| `broker-acme` | `http://auth.acme.localhost:8081` | broker tenant acme |
| `broker-contoso` | `http://auth.contoso.localhost:8082` | broker tenant contoso |
| `backend` | internal `backend:8080` | shows `X-User-*` headers |
| `gate-one-1` | `http://app.acme.localhost:8080` etc. | Gate One instance 1 |
| `gate-one-2` | `http://app2.acme.localhost:8090` | Gate One instance 2 (shared Redis/key) |

## Run

```bash
cd ~/proj/2026/gate-one-src
docker compose -f testdata/auth/compose/compose.yaml up -d --build
docker compose -f testdata/auth/compose/compose.yaml ps
```

The first build compiles `gate-one`, `cladone-auth` and `fake-google`
from the repository (multi-stage Dockerfile).

## Try it

- `http://app.acme.localhost:8080/` → fake Google auto-consents as
  `alice@acme.test`, backend shows `X-User-Id`, `X-Username`,
  `X-Email`, `X-Roles`.
- `http://app2.acme.localhost:8090/` → second Gate One instance, same
  session (cookie domain `acme.localhost`, shared Redis + session key).
- `http://app.contoso.localhost:8080/` → login as `bob@contoso.test`.
- `http://public.acme.localhost:8080/` → no auth.
- `http://api.acme.localhost:8080/` → 401 JSON without a session.
- `http://auth.acme.localhost:8081/health` → broker health.
- `http://idp.acme.localhost:9000/healthz` → fake Google health.

The fake Google is auto-consent: there is no password prompt.

## Failure injection

```bash
# fake Google discovery down
curl -X POST 'http://idp.acme.localhost:9000/__control/fail?discovery=1'
curl -X POST 'http://idp.acme.localhost:9000/__control/fail?discovery=0'

# JWKS down, token endpoint down
curl -X POST 'http://idp.acme.localhost:9000/__control/fail?jwks=1'
curl -X POST 'http://idp.acme.localhost:9000/__control/fail?token=1'

# key rotation (old key kept in JWKS)
curl -X POST 'http://idp.acme.localhost:9000/__control/rotate'

# state
curl 'http://idp.acme.localhost:9000/__control/state'
```

Broker down per tenant:

```bash
docker compose -f testdata/auth/compose/compose.yaml stop broker-acme
# acme routes -> 502; contoso keeps working
```

Redis down:

```bash
docker compose -f testdata/auth/compose/compose.yaml stop redis
# authenticated routes -> 502; public routes still 200
```

## Stop

```bash
docker compose -f testdata/auth/compose/compose.yaml down -v
```

## Notes

- This stack is HTTP only; the production canary uses HTTPS. Cookies
  here are `Secure=false` because the login base URL is `http://`.
- The keys in `../keys/` are **TEST ONLY**.
- The local secrets (`local-acme-secret`, `local-contoso-secret`,
  `local-session-key`) are not secrets; they only exist in this stack.
- `*.localhost` resolves to loopback on the Docker host. Run the
  browser on the same machine as Docker (or forward the ports).
