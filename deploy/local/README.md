# Local demos

Everything here runs on one machine, on `*.localhost`, over plain HTTP.
No domain, no DNS entry, no external identity provider.

`.localhost` resolves to loopback on modern systems, so
`app.demo.localhost:8080` reaches your own machine without `/etc/hosts`.

## No Docker (embedded dev provider)

| Demo | Shows | Needs |
|---|---|---|
| `getting-started` | Gate One in front of a static site | `gate-one` |
| `account-panel` | an application rendering its own account panel | `gate-one` |
| `injectable-ux` | injection, UI gating, nonce CSP | `gate-one` |
| `turnstile` | Cloudflare Turnstile gate: whole page and action-only | `gate-one`, internet |
| `usage-events` | signed plugin, WAL, events | `gate-one`, Go |
| `metering-audit` | pricing, allowance, outbox, signed offline audit | `gate-one`, Python 3 |

These use the loopback-only `dev` provider: `alice`/`alice` (user) and
`bob`/`bob` (admin). `run.sh` starts a static server and Gate One, and
prints the URL. The `turnstile` demo has no identity provider: the
gate is the only protection (Cloudflare test keys).

## Docker Compose (real OIDC chain)

| Demo | Shows | Needs |
|---|---|---|
| `direct-oidc` | Gate One talking to one issuer, no IAM | `gate-one`, `demo-idp` |
| `sso-multi-apps` | two applications, one provider, one cookie domain | `gate-one`, `demo-idp` |
| `embedded-iam` | IAM, claim mapping, live grants | the three binaries, Docker |
| `redis` | two tenants, two instances, shared Redis | the three binaries, Docker |

Each `run.sh` starts the stack, waits for readiness and prints the URLs.
`./run.sh down` stops it; `./run.sh logs` follows the logs.

## Binaries

`run.sh` looks for the binaries in `$BIN_DIR`, then `../bin` (a source
build), then the `PATH`. See [the deploy README](../README.md) for the
release assets. Redis and the demo backends come from the compose files;
nothing is built.

## The demo IdP

`demo-idp` (alias of `cmd/fake-google`) imitates Google: discovery,
JWKS, authorization code, auto-consent, selectable user. It makes the
OIDC demos real without an external account. It is not a production IdP
and must never be reachable from a public network.
