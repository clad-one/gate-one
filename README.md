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

## Quickstart (two commands, no external service)

```bash
./build.sh

# 1. Public site (zero authentication dependency)
./bin/gate-one init --static --host app.localhost \
  --backend http://127.0.0.1:8080
./bin/gate-one -config api-routes.json
# → http://app.localhost:3000

# 2. SSO-shaped app with the embedded dev IdP (loopback only)
./bin/gate-one init --host app.demo.localhost \
  --backend http://127.0.0.1:8080
./bin/gate-one -config api-routes.json
# → http://app.demo.localhost:3000  login: alice/alice, bob/bob

# 3. Production OIDC (your IdP; no auth-bridge required)
./bin/gate-one init --oidc --host app.example.com \
  --backend http://127.0.0.1:8080 \
  --issuer https://auth.example.com/realms/acme \
  --client-id gate-one
```

`init` writes the smallest working `api-routes.json`; `-check` validates
it without starting; `doctor` also probes the provider:

```bash
./bin/gate-one -config api-routes.json -check
./bin/gate-one doctor -config api-routes.json
```

## Authentication providers

`authProvider` selects how requests are authenticated. It is the seam
that keeps auth-bridge **optional**, including for OIDC:

| type | What it is | External dependency |
|---|---|---|
| `dev` | Embedded development IdP (dedicated `login.<domain>` host, real form, signed session cookie) | none (loopback only) |
| `http` | Any service implementing the Gate One auth contract (`/auth`, `/auth/mcp`, `/login`, `/logout`, `/auth/popup-done`). auth-bridge is the reference implementation; a non-conforming service needs an adapter. | that service |
| `oidc` | Native OIDC Relying Party: discovery, code + PKCE, JWKS, session, logout, MCP resource server | an OIDC IdP (Keycloak, Entra, Google, Authentik, Okta, Auth0…) |

Absent `authProvider` = the legacy `oidc` + auth-bridge translation, so
existing configs keep working. A purely public route needs no auth block
at all.

Authelia and Authentik are **not** drop-in `http` providers: Authentik
exposes an OIDC provider (`type: "oidc"`); Authelia is a forward-auth
portal and needs an adapter implementing the Gate One contract
(`/auth`, `/auth/mcp`, `/auth/popup-done`). `verifyUrl` and the header
mapping only cover the verification call.

```json
{
  "authProvider": {
    "type": "http",
    "baseUrl": "http://auth-bridge:3000",
    "loginUrl": "https://login.example.com/login",
    "issuer": "https://auth.example.com/realms/example"
  }
}
```

`baseUrl` defaults to `http://auth-bridge:3000`; the legacy block
`"oidc": {loginUrl, issuer}` and this explicit `type: "http"` block are
**behaviorally identical**. Migrating the shape is therefore safe (no
session change, no auth-bridge change) and is the recommended first
step before considering native OIDC. Examples:
`examples/http.api-routes.json` (auth-bridge) and
`examples/oidc.api-routes.json` (native, future migration).

Native OIDC (no auth-bridge; the IdP must register
`https://login.example.com/auth/callback`):

```json
{
  "authProvider": {
    "type": "oidc",
    "issuer": "https://auth.example.com/realms/example",
    "clientId": "gate-one",
    "clientSecretEnv": "OIDC_CLIENT_SECRET",
    "loginBaseUrl": "https://login.example.com",
    "cookieDomain": "example.com"
  }
}
```

`gate-one init --oidc --issuer ... --client-id ...` writes this block and
prints the redirect URI to register. auth-bridge stays fully supported
for OIDC too: use `type: "http"` when you want the bridge in front of
Keycloak.

An unreachable provider is a **502**, never a login redirect: the
gateway no longer hides an outage behind a sign-in loop.

Full guide: `doc/auth-providers.adoc`.

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
(`npm install && npm test`). `npm run preview` serves the controls
fixture at http://127.0.0.1:8787/ with the guard injected, each case
labelled with the tested `data-gtw-*` attribute/value, and a demo login
flow (useful to see the gating in a real browser). Force-auth and the
demo logout refresh the session in place, without reloading the page.

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

## Declarative UI gating

Frontend markup can declare auth-aware UI with `data-gtw-auth`,
`data-gtw-auth-off`, `data-gtw-auth-hidden`, `data-gtw-roles`,
`data-gtw-scopes`, `data-gtw-claims` and `data-gtw-logout`. The guard
gates **activation**, never deactivation. Value controls (`select`,
`range`, date/time/color) are gated on `change`, with
`data-gtw-auth-off` (or the default value) as the OFF value. Text-entry
clicks are focus, not action: put the attribute on the submit button.

Full contract and behavioural test matrix: `doc/ui-gating.adoc`.

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

## Preparing a release (local only)

```bash
./release.sh                 # version from ./VERSION
VERSION=1.0.0 ./release.sh   # override
```

Builds static binaries for linux/darwin/arm64+amd64 and windows/amd64
into `dist/`, with a tarball per platform (binary + schemas + examples +
README/LICENSE), `SHA256SUMS` and `RELEASE_NOTES.md`. The script never
pushes, tags or uploads anything — this repository intentionally has no
remote.

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
cmd/gate-one/       entrypoint (flags, init/doctor, SIGHUP reload, shutdown)
cmd/gate-one-license/ vendor-side licence keygen/sign
internal/authn/     provider SPI: dev IdP, http adapter, native OIDC
internal/core/      config grammar + route loading/validation
internal/proxy/     reverse proxy, auth, guards, rewriting, limits
internal/pwa/       PWA wrap (manifest, service worker, Workbox)
internal/mcp/       MCP endpoint
test/ui/            guard-script harness (jsdom)
sw-sim/             service-worker simulator
testdata/           reference production config
examples/           minimal static/dev/http/OIDC configs
release.sh          local release artifacts (never pushes)
```

## License

**Source-available** (not open source), BSL-custom — see `LICENSE`.

- personal use, evaluation, testing and internal development: **free**;
- **commercial production use requires a paid licence**;
- no competing service / paid SaaS hosting without written permission.

The gateway stays **fully functional** without a licence: it only shows an
"eval / personal" notice in the user badge (no kill switch, no phone-home).

Optional `license` block in `api-routes.json`:

```json
{
  "license": {
    "token": "v1.<base64url(claims)>.<base64url(signature)>",
    "tokenFile": "/run/secrets/gate-one-license",
    "publicKey": "<base64 Ed25519 public key>",
    "publicKeys": {
      "2026-10": "<base64 old public key>",
      "2027-10": "<base64 new public key>"
    },
    "url": "https://example.com/pricing"
  }
}
```

The token is an **Ed25519-signed** payload (`kid`, `org`, `email`, `plan`,
`exp`, `domains`, `features`) verified **offline** with a public key; only
public keys ship (the private signing key never does). Absent, invalid or
expired = evaluation mode.

**Token sources** (precedence):

1. `GATE_ONE_LICENSE_TOKEN` environment variable;
2. `license.tokenFile` (path to a file — e.g. a mounted secret);
3. `license.token` (inline).

The file and env var are re-read on every config reload (**SIGHUP**), so a
renewal does **not** require editing `api-routes.json`: replace the token file
(or the env var) and send `SIGHUP`.

**Renewal** (same key): mint a new token with the existing private key, update
the file/env/config, then `SIGHUP`.

**Key rotation** (zero-downtime: several keys valid at once):

1. `gate-one-license keygen` → new keypair + suggested `kid`;
2. add the new public key under `license.publicKeys["<kid>"]` on the gateways
   (normal deployment) — the old key stays valid;
3. mint new tokens with `sign -kid <kid>`;
4. keep the old key until the old tokens expire;
5. remove the old entry.

A token carries its `kid` inside the **signed** payload; an unknown `kid` is
rejected (no silent fallback to another key). The legacy `license.publicKey`
(tokens without `kid`) still works.

Mint tokens (vendor side; keep the private key offline):

```bash
go run ./cmd/gate-one-license keygen
go run ./cmd/gate-one-license sign -key priv.b64 -org "ACME" \
  -email ops@acme.fr -plan pro -days 365 -domains acme.fr -features sso,mcp
```
