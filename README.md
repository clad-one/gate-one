# Cladone G.O. Gate One — sources

Config-driven reverse proxy written in Go: SSO delegation to
auth-bridge, role guards, PWA wrapping, upstream proxying and
userscript injection.

This repository holds the **sources** of Gate One (public:
<https://github.com/clad-one/gate-one>). Sibling repositories complete
the picture:

| Repository | Visibility | Contents |
|---|---|---|
| `gate-one` (this one) | public | Go sources, unit tests, smoke tests, developer docs, signed releases |
| `gate-one-doc` | public | documentation site, examples, published JSON Schemas |
| `gate-one-vendor` | private | licence issuance tooling and vendor operations |
| `cladone-it-infra` | private | deployment stack: `compose/gate-one/` (prebuilt binary + live `api-routes.json`), Ansible, Keycloak |

The gateway verifies licences offline with an Ed25519 **public** key; the
signing key and the token-minting tooling are **not** part of this
repository. See the *License* section below.

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
  --issuer https://auth.example.com/realms/mycompany \
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
| `jwt` | Stateless JWKS bearer verifier for API/MCP routes; no login page, no cookie session | a JWT issuer with JWKS |

`authProviders` declares named providers, and each route selects one
with `auth.provider` (empty = `defaultAuthProvider`). This is how a
second tenant gets its own issuer, key, audience, cookie and store:

```json
{
  "authProviders": [
    {
      "id": "mycompany",
      "type": "oidc",
      "issuer": "https://auth.example.com/t/mycompany",
      "clientId": "cladone-go",
      "clientSecretEnv": "MYCOMPANY_OIDC_SECRET",
      "loginBaseUrl": "https://login.mycompany.example.com",
      "cookieDomain": "mycompany.example.com",
      "cookieName": "cladone_mycompany_session",
      "roleClaims": ["roles"],
      "mcpAudience": "https://mcp.mycompany.example.com",
      "sessionStore": {"type": "bolt", "path": "./state/mycompany.db"}
    },
    {
      "id": "mycompany-api",
      "type": "jwt",
      "issuer": "https://auth.example.com/t/mycompany",
      "jwksUrl": "https://auth.example.com/t/mycompany/jwks.json",
      "audience": "https://api.mycompany.example.com",
      "algorithms": ["EdDSA"]
    }
  ],
  "defaultAuthProvider": "mycompany",
  "routes": [
    {"host": "app.mycompany.example.com", "path": "/*", "frontend": true,
     "backend": "http://app:8080", "auth": {"provider": "mycompany"}},
    {"host": "api.mycompany.example.com", "path": "/*",
     "backend": "http://api:8080", "auth": {"provider": "mycompany-api"}}
  ]
}
```

The singular `authProvider` remains accepted as a legacy alias
(normalized to `id: "default"`). It is mutually exclusive with
`authProviders`. In the multi-tenant `authProviders` form, only `oidc`
and `jwt` are accepted: `http` (auth-bridge) and `dev` are legacy
single-provider modes.

For multi-instance or immediate revocation, use the shared Redis store:

```json
"authProviders": [{
  "id": "mycompany", "type": "oidc", "...": "...",
  "sessionKeyEnv": "MYCOMPANY_SESSION_KEY",
  "sessionStore": {
    "type": "redis",
    "url": "redis://redis:6379/0",
    "passwordEnv": "REDIS_PASSWORD",
    "prefix": "cladone:auth:v1:"
  }
}]
```

`sessionKeyEnv` is required for OIDC+Redis so every instance signs the
same cookie. The revocation check runs on every authenticated request:
a revoked `sid`/`sub` is rejected on the next request, on every instance.
If Redis is unavailable, authenticated routes fail closed with `502`
(public routes continue).

The IAM shares one browser `sid` across all apps of the same tenant
(host-only IAM cookie, `Path=/t/{tenant}`). A logout from any app
revokes the session `sid` **and the user `sub`** in Redis: every existing
session/device is rejected on its next request, and IAM refresh
tokens/codes issued before the logout are refused. The `sub` revocation
carries a timestamp, so a new login after the logout is allowed (no user
lockout).

A provider that cannot be built (discovery down at startup) is
**degraded per tenant**: its routes answer `502
authentication_unavailable`, the other tenants continue, and existing
local sessions remain valid. An invalid token stays `401`; a JWKS or
IAM outage becomes `502`.

For a second tenant, the recommended companion is the small OIDC IAM:
`doc/auth-iam.adoc` and `cmd/cladone-auth`. It federates Google,
applies roles/tenant/audience policy, and re-emits Ed25519 JWTs. Gate One
trusts only that issuer.

Absent `authProvider` = the legacy `oidc` + auth-bridge translation, so
existing configs keep working. A purely public route needs no auth block
at all.

Authelia and Authentik are **not** drop-in `http-bridge` providers: Authentik
exposes an OIDC provider (`type: "oidc"`); Authelia is a forward-auth
portal and needs an adapter implementing the Gate One contract
(`/auth`, `/auth/mcp`, `/auth/popup-done`). `verifyUrl` and the header
mapping only cover the verification call.

```json
{
  "authProvider": {
    "type": "http-bridge",
    "baseUrl": "http://auth-bridge:3000",
    "loginUrl": "https://login.example.com/login",
    "issuer": "https://auth.example.com/realms/example"
  }
}
```

`baseUrl` defaults to `http://auth-bridge:3000`; the legacy block
`"oidc": {loginUrl, issuer}` and this explicit `type: "http-bridge"` block are
**behaviorally identical**. Migrating the shape is therefore safe (no
session change, no auth-bridge change) and is the recommended first
step before considering native OIDC. Examples:
`examples/http.api-routes.json` (auth-bridge) and
`examples/oidc.api-routes.json` (native OIDC).

Native OIDC (no auth-bridge; the IdP must register
`https://login.example.com/auth/callback` and, for immediate
revocation, `https://login.example.com/backchannel-logout`):

```json
{
  "authProvider": {
    "type": "oidc",
    "issuer": "https://auth.example.com/realms/example",
    "clientId": "gate-one",
    "clientSecretEnv": "OIDC_CLIENT_SECRET",
    "loginBaseUrl": "https://login.example.com",
    "cookieDomain": "example.com",
    "sessionStore": {"type": "bolt", "path": "./gate-one-state.db"},
    "sessionTtlSeconds": 3600,
    "backchannelLogout": true
  }
}
```

The bbolt file persists back-channel logout revocations across
restarts; the revocation is checked before the gateway identity cache.
bbolt is single-writer (one Gate One instance); for HA and immediate
revocation use `sessionStore.type: "redis"` (see above).

The login host root (`https://login.example.com/`) is the generic
landing point for out-of-band links (email verification, account
actions). It is **IdP-blind**: the application to return to must be
carried by the link, never guessed.

- `returnTo` (custom/OIDC) or `continueUrl` (Firebase) present and on
  an allowed host (a configured route host, the login host, or a
  subdomain of the cookie domain) → `302` to that application, the
  rest of the query preserved (`mode`, `oobCode`, `lang`…);
- an action payload (`mode`, `oobCode`, `key`, `code`, `state`, `token`…)
  without a return target → readable `400` page naming the missing
  adapter configuration (no silent fallback);
- a bare visit → `302` to `defaultAppUrl` (operational fallback).

```json
{
  "defaultAppUrl": "https://app.example.com/",
  "authProvider": { "...": "..." }
}
```

`defaultAppUrl` is a safety net, not a per-application router: it is
used only when the link carries no return target (or an invalid one).

`gate-one init --oidc --issuer ... --client-id ...` writes this block and
prints the URIs to register. auth-bridge stays fully supported
for OIDC too: use `type: "http-bridge"` when you want the bridge in front of
Keycloak.

An unreachable provider is a **502**, never a login redirect: the
gateway no longer hides an outage behind a sign-in loop.

Full guide: `doc/auth-providers.adoc`.
Strict CSP (nonce styles, custom injections, proxified sites):
<https://clad-one.github.io/gate-one-doc/v0.4.5-docs.9/docs/strict-csp/>.

## Bot protection (Cloudflare Turnstile)

A top-level `turnstile` block adds the Turnstile widget to matching form
pages and verifies every matching POST with Siteverify **before the
backend**. It works on pages Gate One already proxies; the application
does not change. `siteKey` is public, the secret is read from
`secretEnv` (missing = startup refused). `hosts`/`paths`/`forms` select
the pages and forms, so one block covers several hosts without
duplication.

It protects only traffic that passes through this Gate One instance: a
second ingress, an internal caller or a published port bypasses it.
Network isolation (only Gate One can reach the application) remains the
operator's responsibility.

```json
"turnstile": {
  "siteKey": "0x4AAAAAAA...",
  "secretEnv": "TURNSTILE_SECRET",
  "paths": ["/contact/*"],
  "action": "contact",
  "forms": ["form#contact"]
}
```

Full guide: `doc/turnstile.adoc`.

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
make test-auth             # AC-AUTH-* acceptance tests (authn, IAM, proxy, conformance)
make test-auth-race        # same, under -race
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
so a login is never offered **automatically** (it would loop on the same
account):

- a **browser navigation** gets a readable built-in HTML page (not the
  raw JSON body). When the route's provider hosts an interactive login,
  the page names the refused account and offers **Sign out and use
  another account**: it clears the RP session, revokes it, and returns
  to the refused URL so a different account can sign in. Without that
  action a new tab would reuse the same session and stay blocked;
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

Full contract and behavioural test matrix:
<https://clad-one.github.io/gate-one-doc/v0.4.5-docs.9/docs/ui-gating/>.

## Delegated upstream credentials

A route may call its backend with a **per-user token** supplied by the
internal `token-broker` instead of a shared service credential. The
gateway authenticates the caller as usual, asks the IAM for that
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
      "tokenBroker": { "provider": "github" }
    }
  }]
}
```

- `auth` is mandatory: the IAM needs the authenticated user id.
- `upstream.delegated.provider` is an IAM-owned name. Gate One checks
  it against `GET /providers` when it starts (and on every SIGHUP); an
  unknown or disabled provider refuses startup.
- The default injection is `Authorization: Bearer <token>`. `header`
  and `prefix` override it; an explicit empty `prefix` sends the raw
  token. `Host`, `Cookie`, `X-User-*`, `X-Forwarded-*` and `X-Gate-One-*`
  header names are reserved.
- A missing connection never reaches the backend: API routes get
  `401 delegated_credentials_required` (or `409
  reauthorization_required`) with a `connect_url`; frontend routes are
  redirected there. A IAM outage is a `502`.
- The same policy applies to REST calls produced by an MCP route's
  `tools/call`, using the authenticated MCP caller's token.

The shared secret is read from the environment at load and is never
serialized or logged. `tokenBroker.url` defaults to the Docker service
name `http://token-broker:4000` (or `TOKEN_BROKER_URL`); the IAM has
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
    "tokenBroker": { "provider": "github" }
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
- `upstream.delegated` injects the caller's IAM token. Without it,
  `upstream.headers` can carry a static service credential (resolved
  with `${VAR}` at load). The Gate One bearer, cookies and identity
  headers are never forwarded upstream.
- The upstream's `Mcp-Session-Id` is relayed, and Gate One binds each
  session to the authenticated user. Upstream 401/403 answers become a
  `502 upstream_mcp_authentication_failed` instead of a Gate One 401.
- Supported upstream transport: MCP Streamable HTTP (POST/GET SSE and
  session DELETE). Tool filtering is applied to JSON and SSE
  `tools/list` responses.

## Preparing a release

The release pipeline lives in this repository. It builds signed
artifacts for linux/darwin/arm64+amd64 and windows/amd64, attaches the
published schemas, examples and docs, generates an SPDX SBOM per target
and signs `SHA256SUMS` with cosign.

```bash
./release.sh --dry-run

COSIGN_KEY=~/.config/gate-one/release/cosign.key \
COSIGN_PASSWORD="$(cat ~/.config/gate-one/release/cosign.password)" \
COSIGN_PUB=release/cosign.pub \
./release.sh
```

The source tag must be `vX.Y.Z`. When the product repository is present
(`GATE_ONE_PRODUCT`, default `../gate-one-product`), its tag must be
`vX.Y.Z` or `vX.Y.Z-docs.N` for a documentation-only release; the
product site archive is included. Without the product repository, the
release still builds the binaries with the source schemas/examples but
omits the site archive and the product-only schemas.

Artifacts land in `dist/`: `gate-one_<version>_<os>_<arch>.tar.gz` and
`cladone-auth_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows), the
site archive, SBOMs, `RELEASE_MANIFEST.json`, `SHA256SUMS`,
`SHA256SUMS.bundle` and `cosign.pub`. The script never pushes, tags or
uploads anything.

The site archive is built with the GitHub Pages base URL for the same
release (`https://clad-one.github.io/gate-one-doc/v<label>/`, the folder
the documentation workflow publishes). Override it with `SITE_BASE_URL`
when publishing elsewhere.

The verification key is committed as `release/cosign.pub`; the private
key stays outside the repository.

### Publishing

The public source repository is
<https://github.com/clad-one/gate-one>. It carries the source tags and
the release assets:

```bash
git push origin main
git push origin vX.Y.Z

gh release create vX.Y.Z dist/* \
  --title "Gate One vX.Y.Z" \
  --notes-file dist/RELEASE_NOTES.md
```

The documentation source is a separate repository,
<https://github.com/clad-one/gate-one-doc>. Release archives contain the
documentation site, and the docs repository publishes the same static
site under a versioned GitHub Pages folder:
<https://clad-one.github.io/gate-one-doc/>.

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
cmd/cladone-auth/   small multi-tenant OIDC IAM (Google federation, JWKS, policy)
internal/authn/     provider SPI: dev IdP, http adapter, native OIDC, JWT/JWKS, bbolt store
internal/iam/       OIDC issuer: tenants, Google adapter, policy, Ed25519 tokens
internal/core/      config grammar + route loading/validation
internal/proxy/     reverse proxy, auth, guards, rewriting, limits
internal/pwa/       PWA wrap (manifest, service worker, Workbox)
internal/mcp/       MCP endpoint
pkg/authstate/     shared Redis key schema (revocation, issuer/tenant)
pkg/pluginmanifest/ signed plugin manifest/artifact/dependency verification
pkg/identityadapter/ IAM-side IdentityAdapter contract + conformance suite
pkg/identityadapter/httpbinding/ portable HTTP/JSON binding
test/ui/            guard-script harness (jsdom)
sw-sim/             service-worker simulator
testdata/           reference production config; testdata/auth/ IAM example
deploy/             runnable deployments: local/ (*.localhost demos) and vps/ (Traefik + TLS)
doc/                developer docs: embedded IAM, auth providers, test plan, plugins (see doc/README.md)
release.sh          signed release artifacts (never pushes)
release/            public verification key for the release signature
```

## License

**Source-available** (not open source), BSL-custom — see `LICENSE`
(English authoritative; French translation: `LICENSE.fr.md`).

- personal use, evaluation, testing and internal development: **free**;
- **commercial production use requires a paid licence**;
- no competing service / paid SaaS hosting without written permission;
- **extension plugins** (non-auth, non-IAM) may use their own licence,
  including closed source/commercial — see `PLUGIN-LICENSING.md`.

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

1. generate a new keypair with the vendor tooling and note its `kid`;
2. add the new public key under `license.publicKeys["<kid>"]` on the gateways
   (normal deployment) — the old key stays valid;
3. mint new tokens with the new `kid`;
4. keep the old key until the old tokens expire;
5. remove the old entry.

A token carries its `kid` inside the **signed** payload; an unknown `kid` is
rejected (no silent fallback to another key). The legacy `license.publicKey`
(tokens without `kid`) still works.

Only the **verifier** ships in this repository. Licence issuance
(key generation, token minting, key custody) is handled by the private
vendor tooling in `gate-one-vendor` and the private signing key never
ships. To obtain a licence, contact Cladone-IT.
