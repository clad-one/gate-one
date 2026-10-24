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

## Authentication policy

The two condition families are kept strictly apart. `auth.when` holds
**technical** conditions (`method`/`query`/`header`/`body`) that decide
*whether* authentication is required; `auth.identity` holds **identity**
conditions (`roles`/`scopes`/`claims`/`user`) checked *after* a
successful authentication (failure = `403`). Mixing them is refused at
load.

```json
{
  "host": "vers.example.com",
  "path": "/api/process",
  "backend": "http://versifier:9292",
  "auth": {
    "when": [
      { "method": "POST", "body": { "coupes": true } },
      { "method": "DELETE" }
    ],
    "identity": {
      "roles": ["offline_access"],
      "scopes": ["profile"],
      "claims": { "email": "*" }
    }
  }
}
```

- `auth` absent → the route is **public**.
- `auth: {}` (or `identity` only) → authentication is **always** required.
- `when` accepts one object (AND of its conditions) or an array (OR of
  ANDs): authentication is required as soon as **one** element matches.
  A request matching no element stays public.
- `identity` is a single AND clause, evaluated **only** on requests that
  were actually authenticated (no token = no identity check).
- `frontend` routes redirect to the login on `401`; API routes get a
  JSON `401`.

An identity failure (`403`) is a **rights refusal**, not an auth problem,
so a login is never offered (it would loop):

- a **browser navigation** gets a readable built-in HTML page (not the
  raw JSON body);
- a **`fetch()`/XHR** keeps the JSON `403` unchanged, so the app handles
  the refusal itself.

Both are marked with `X-Gate-One-Forbidden`; a `403` coming **from the
backend** never is (the header is stripped from proxied responses).
Optional UX (`authGuard.forbidden`):

```json
{
  "authGuard": {
    "forbidden": {
      "banner": true,
      "pageUrl": "https://app.example.com/access-denied",
      "message": "You do not have access to this service."
    }
  }
}
```

- `banner` — the injected guard shows a dismissable hint on a gateway
  identity `403` seen by `fetch()`, inviting the front authors to **hide
  the feature** (`uiGate` / `data-gtw-*`) instead of letting the user hit
  a dead end. Shown at most once per page load.
- `pageUrl` — navigations refused on identity are redirected there (`302`)
  instead of the built-in page.
- `message` — overrides the built-in page's text.

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

## External MCP proxy

`mcp.upstream` exposes an **external** MCP server (Streamable HTTP)
through the same Gate One authentication. Instead of deriving tools
from an OpenAPI document, Gate One proxies the MCP exchange and filters
tool names:

```json
{
  "host": "github-mcp.example.com",
  "path": "/mcp",
  "backend": "https://api.githubcopilot.com/mcp/",
  "auth": {},
  "mcp": {
    "enabled": true,
    "path": "/mcp",
    "upstream": {
      "tools": { "exclude": ["delete_*", "merge_*"] }
    }
  },
  "upstream": {
    "delegated": { "provider": "github" }
  }
}
```

- `mcp.upstream.url` defaults to the route backend and must be the full
  upstream endpoint (the incoming `/mcp` path is not appended).
- `tools.include` is an allow-list and `tools.exclude` a deny-list;
  patterns use `path.Match` syntax (`*`, `?`, `[...]`). Exclude wins.
  Filtering is applied to `tools/list` **and** enforced on `tools/call`:
  a hidden tool is answered locally and never reaches the upstream.
- `mcp.upstream` and `mcp.operations` are mutually exclusive.
- `upstream.delegated` injects the caller's broker token. Without it,
  `upstream.headers` can carry a static service credential (resolved
  with `${VAR}` at load). The Gate One bearer, cookies and identity
  headers are never forwarded upstream.
- The upstream's `Mcp-Session-Id` is relayed, and Gate One binds each
  session to the authenticated user. Upstream 401/403 answers become a
  `502 upstream_mcp_authentication_failed` instead of a Gate One 401.
- Supported upstream transport: MCP Streamable HTTP (POST/GET SSE and
  session DELETE). Tool filtering is applied to JSON and SSE
  `tools/list` responses.

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
