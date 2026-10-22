# Cladone Gate One — sources

Config-driven reverse proxy written in Go: SSO delegation to
auth-bridge, role guards, PWA wrapping, upstream proxying and
userscript injection.

This repository holds the **sources** of Gate One. Two sibling
repositories complete the picture:

| Repository | Contents |
|---|---|
| `gate-one-src` (this one) | Go sources, unit tests, smoke tests, developer docs |
| `gate-one` (public) | user documentation, demo, Dockerfile / compose examples |
| `cladone-it-infra` | deployment stack: `compose/gate-one/` (prebuilt binary + live `api-routes.json`), Ansible, Keycloak |

The live production configuration lives in
`cladone-it-infra/compose/gate-one/api-routes.json`.
`testdata/` holds the live config and its JSON schemas (`api-routes` and
`inject-bundle`; the config copy feeds `TestLoadRealConfigStrict`, the
strict grammar check). Refresh them from the infra repo when the live
config changes:

```bash
cd ../cladone-it-infra && make sync-config
```

## Build

```bash
./build.sh                 # -> bin/gate-one
./run.sh                   # go run, reads testdata/api-routes.json
./bin/gate-one -config testdata/api-routes.json -check
```

## Tests

```bash
go vet ./...
go test ./...
./smoke.sh                 # end-to-end: fake backend + auth-bridge + gateway
```

`test/ui` contains the jsdom harness for the injected guard script
(`npm install && npm test`).

## Delegated upstream credentials

A route may call its backend with a **per-user token** supplied by the
internal `token-broker` instead of a shared service credential. The
gateway authenticates the caller as usual, asks the broker for that
user's token, and injects it into the backend request. Provider client
secrets never enter Gate One.

```json
{
  "tokenBroker": {
    "url": "http://token-broker:4000",
    "secretEnv": "TOKEN_BROKER_SHARED_SECRET"
  },
  "routes": [{
    "host": "api.example.com",
    "path": "/*",
    "backend": "https://api.github.com",
    "auth": {},
    "upstream": {
      "host": true,
      "delegated": { "provider": "github" }
    }
  }]
}
```

- `auth` is mandatory: the broker needs the authenticated user id.
- `upstream.delegated.provider` is a broker-owned name. Gate One checks
  it against `GET /providers` when it starts (and on every SIGHUP); an
  unknown or disabled provider refuses startup.
- The default injection is `Authorization: Bearer <token>`. `header`
  and `prefix` override it; an explicit empty `prefix` sends the raw
  token. `Host`, `Cookie`, `X-User-*`, `X-Forwarded-*` and `X-Gate-One-*`
  header names are reserved.
- A missing connection never reaches the backend: API routes get
  `401 delegated_credentials_required` (or `409
  reauthorization_required`) with a `connect_url`; frontend routes are
  redirected there. A broker outage is a `502`.
- The same policy applies to REST calls produced by an MCP route's
  `tools/call`, using the authenticated MCP caller's token.

The shared secret is read from the environment at load and is never
serialized or logged. `tokenBroker.url` defaults to the Docker service
name `http://token-broker:4000` (or `TOKEN_BROKER_URL`); the broker has
no Traefik route and is reachable only from the internal network.

## Releasing to the infrastructure repository

From `cladone-it-infra`:

```bash
make gate-one              # builds this repo and copies bin/gate-one
                           # into compose/gate-one/bin/
```

`make deploy` (in `cladone-it-infra`) performs that build first. The
infra Dockerfile only packages the prebuilt binary — it never needs a
Go toolchain on the server.

## Layout

```
cmd/gate-one/       entrypoint (flags, SIGHUP hot reload, shutdown)
internal/core/      config grammar + route loading/validation
internal/proxy/     reverse proxy, auth, guards, rewriting, limits
internal/pwa/       PWA wrap (manifest, service worker, Workbox)
internal/mcp/       MCP endpoint
test/ui/            guard-script harness (jsdom)
sw-sim/             service-worker simulator
testdata/           reference production config
```

## License

Source-available, BSL-custom — see `LICENSE`.
