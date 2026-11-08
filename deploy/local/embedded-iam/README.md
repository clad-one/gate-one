# Local embedded IAM demo

Runs the real chain on one machine, with no external service and no
domain:

```text
browser → Gate One → cladone-auth (embedded IAM) → demo IdP
```

| Service | URL | Role |
|---|---|---|
| Gate One | <http://app.demo.localhost:8080> | gateway, route policy, user badge |
| login host | <http://login.demo.localhost:8080> | Hosted login surface |
| `cladone-auth` | <http://auth.demo.localhost:8081/t/demo> | OIDC issuer/IAM |
| demo IdP | <http://idp.demo.localhost:9000> | fake Google, auto-consent |
| backend | internal `backend:8080` | shows the `X-User-*` headers |
| Redis | internal `redis:6379` | broker directory + Gate One session store |

The demo IdP stands in for Google. It runs the same OIDC flow
(discovery, JWKS, authorization code), so the claim mapping and the
grants behave exactly as they do against a real provider.

Redis is part of the demo because the broker stores its user directory
there: that is what makes `cladone-auth user set` visible to the running
process without a restart.

## Prerequisites

1. The three binaries, in one directory:

   ```bash
   export BIN_DIR=~/gate-one-bin
   # release assets (verify the checksums first):
   #   gate-one_<v>_<os>_<arch>.tar.gz       -> gate-one
   #   cladone-auth_<v>_<os>_<arch>.tar.gz   -> cladone-auth
   #   gate-one-demo-idp_<v>_<os>_<arch>.tar.gz -> demo-idp
   ```

   `./run.sh` also accepts a source build: `cd gate-one-src && ./build.sh`
   produces `bin/gate-one`; `go build -o bin/cladone-auth ./cmd/cladone-auth`
   and `go build -o bin/demo-idp ./cmd/fake-google` complete the set.

2. Docker with Compose v2 (Redis, backend and networking).

## Run

```bash
cd gate-one-src/deploy/local/embedded-iam
BIN_DIR=~/gate-one-bin ./run.sh
```

Open <http://app.demo.localhost:8080> and sign in as `alice@demo.test`.
There is no password: the demo IdP consents automatically.

The backend page lists `X-User-Id`, `X-Username`, `X-Email`, `X-Roles`,
`X-Scopes` and `X-Claims`.

## What it demonstrates

**Federated login.** Gate One trusts only the broker
(`authProvider.issuer` → `…/t/demo`). It never sees the demo IdP.

**Claim mapping.** `config/broker.json` maps the upstream `groups`
claim to IAM roles:

```json
"mappings": [{ "claim": "groups", "values": ["admins"], "roles": ["admin"] }]
```

`alice` arrives with `groups=["admins"]`, so the token carries
`roles=["user","admin"]` (`user` is the tenant default). `bob` only gets
`user`.

**Per-user grants.** Sign in once so the broker creates the federated
user, then edit the grants while it runs:

```bash
./run.sh user list -tenant demo
./run.sh user set  -tenant demo \
    -issuer http://idp.demo.localhost:9000 -sub idp-alice \
    -roles admin,editor
```

A federated user is looked up by issuer and subject (both shown by
`user list`) or by `-id`; `-email` targets local accounts.

Sign out and back in, and the backend shows the new roles. Grants are
stored on the user and apply to local accounts too.

**Single sign-out.** The user badge's sign-out ends the Gate One session
and the broker session; the revocation is shared through Redis.

## Files

| File | Contents |
|---|---|
| `compose.yml` | the five containers |
| `config/routes.json` | Gate One: one OIDC provider, one route |
| `config/broker.json` | tenant, upstream, mapping, key file, Redis |
| `config/idp.json` | demo IdP users (`alice`, `bob`) |
| `config/demo.key` | demo Ed25519 signing key — **never use in production** |
| `backend/server.py` | the identity-header page |

## Going to production

The same stack with real Google, TLS and a public domain is
[`deploy/vps/`](../../vps/) — see its README. The broker configuration
only changes its `upstreams` block (`https://accounts.google.com`) and
its `redirectUris`.
