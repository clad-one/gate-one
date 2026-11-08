# Two tenants, two instances, one Redis

The scaling and multi-tenant demo. Everything is local, on `*.localhost`.

```text
browser ──► Gate One instance 1 ─┐
        └─► Gate One instance 2 ─┴─► Redis (sessions, revocation,
                                       IAM user directories)
                                     ├─► IAM mycompany ─► demo IdP A
                                     └─► IAM contoso   ─► demo IdP B
```

Two tenants are used deliberately: it is the smallest setup where shared
state does real work (two issuers, two cookie domains, one revocation
keyspace).

## Why Redis is required here

A single Gate One instance keeps sessions in a local bbolt file. With two
instances, a logout recorded on one would be invisible to the other. Redis
makes the session/revocation state shared, and the IAMs use the same
Redis for their user directories so the admin CLI writes are visible to
the running processes.

## Prerequisites

- `gate-one`, `cladone-auth`, `demo-idp` in one directory (`BIN_DIR`);
- Docker with Compose v2.

See [the embedded IAM demo](../embedded-iam/README.md#prerequisites) for
the binary download list.

## Run

```bash
cd gate-one-src/deploy/local/redis
BIN_DIR=~/gate-one-bin ./run.sh
```

| URL | Shows |
|---|---|
| <http://app.mycompany.localhost:8080> | tenant mycompany, instance 1 |
| <http://app.mycompany.localhost:8090> | instance 2, same session, no new login |
| <http://app.contoso.localhost:8080> | tenant contoso, separate issuer |
| <http://public.mycompany.localhost:8080> | a public route, no authentication |
| <http://api.mycompany.localhost:8080> | `401` JSON without a session |

## What it demonstrates

**Per-route provider binding.** `authProviders` declares two `oidc`
issuers, and each route selects one with `auth.provider`. The provider
binding is compiled at load time; a request cannot choose another one.

**Shared session state.** The two instances run the same config with the
same `sessionKeyEnv`, both storing sessions in Redis. Sign in on `:8080`,
open `:8090`: no second login. Sign out on either, and both refuse the
session.

**Tenant isolation.** The two IAMs have separate issuers, separate
cookie domains (`mycompany.localhost`, `contoso.localhost`) and separate
user directories. A contoso session is useless on a mycompany route.

**Failure modes.** Stop Redis and authenticated routes answer
`502 authentication_unavailable` while public routes keep working:

```bash
docker compose -f compose.yml stop redis
docker compose -f compose.yml start redis
```

Stop one IAM and only its tenant fails.

## Files

| File | Contents |
|---|---|
| `compose.yml` | Redis, two demo IdPs, two IAMs, two Gate One instances, backend |
| `config/routes.json` | `authProviders` for both tenants + the routes |
| `config/mycompany.json`, `config/contoso.json` | the two IAMs |
| `config/idp-*.json` | demo IdP users |
| `config/*.key` | demo signing keys — **never use in production** |
| `backend/server.py` | identity headers page |

## Production

The same shape with Traefik, TLS and real Google is
[`deploy/vps/`](../../vps/), including a two-replica `ha` profile.
