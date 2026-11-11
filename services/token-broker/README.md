# token-broker

A small, provider-agnostic OAuth 2.0 token broker for **delegated
credentials**. Gate One keeps using its own identity (Keycloak /
auth-bridge); this service obtains and stores the *user's* token for an
upstream service (GitHub, etc.) so the gateway can call that service on
the user's behalf.

Disconnect is a **pause**: the credential stays stored and Connect
resumes it. **Erase** deletes the local credential and never calls the
provider (the user may use the same credential elsewhere). See the
`/connections` page and the operator API below.

It is deliberately **not** a reverse proxy and **not** an identity
provider.

```
browser ──► Gate One (login host) ──► token-broker ──► provider consent screen
                                  │
                                  └── encrypted tokens (SQLite)

Gate One ──► token-broker /token/{provider} ──► access token
Gate One ──► upstream API with that token
```

## Trust boundary

- The broker is on the Docker `internal` network **only**: no Traefik
  label, no published port.
- It only accepts calls carrying `X-Broker-Secret`.
- User-scoped calls also carry `X-User-Id` (set by Gate One after
  authentication). Only Gate One (and this broker) holds the shared
  secret; auth-bridge must not receive it.
- Provider client secrets and the encryption key live in the broker's
  environment, never in Gate One's configuration.
- The provider registry (endpoints, client id, scopes) lives here too;
  Gate One only references a provider **name**.
- Destructive browser actions require a signed CSRF token (bound to the
  user) and a same-origin `Origin`/`Sec-Fetch-Site`.
- The operator API uses a **separate** admin secret; Gate One does not
  hold it. It can list/pause/resume/delete but never writes a credential.

## Endpoints

| Method | Path | Caller | Purpose |
|---|---|---|---|
| `GET` | `/health` | internal | liveness/readiness, no auth |
| `GET` | `/providers` | internal | enabled provider names + connection status |
| `GET` | `/connections` | browser via Gate One | HTML/JSON list, states and actions |
| `POST` | `/connections/{provider}/disconnect` | browser | pause the delegation (no delete, no provider call) |
| `POST` | `/connections/{provider}/connect` | browser | resume a paused delegation (OAuth fallback) |
| `POST` | `/connections/{provider}/erase` | browser | delete the local credential (no provider call) |
| `POST` | `/connections/erase-all` | browser | delete every credential of the user |
| `GET` | `/connect/{provider}` | browser | start authorization code flow |
| `GET` | `/oauth/{provider}/callback` | provider → Gate One → here | exchange code, store tokens |
| `GET` | `/token/{provider}` | Gate One | fresh access token or an explicit error |
| `DELETE` | `/token/{provider}` | Gate One | internal local deletion (works for a disabled provider) |
| `GET` | `/security` | operator/Gate One | redacted security posture (shared secret) |
| `GET/POST/DELETE` | `/admin/...` | operator | list/pause/resume/delete (separate admin secret, no credential write) |

`/token/{provider}` responses:

- `200` — `{access_token, token_type, expires_at, scopes, provider}`
- `404` — `not_connected`, with a `connect_url`
- `403` — `delegation_disabled` (the user paused the delegation; the
  credential is kept), with a `connect_url`
- `409` — `reauthorization_required` (refresh token rejected; the local
  row is deleted), with a `connect_url`
- `502` — `upstream_unavailable` (provider/network failure; the row is
  kept so a later retry can work)

## Provider registry

`providers.json` is an allow-list. A provider is data, not code:

```json
{
  "providers": {
    "github": {
      "enabled": false,
      "display_name": "GitHub",
      "type": "oauth2",
      "authorization_endpoint": "https://github.com/login/oauth/authorize",
      "token_endpoint": "https://github.com/login/oauth/access_token",
      "client_id": "REPLACE_WITH_GITHUB_APP_CLIENT_ID",
      "client_secret_env": "GITHUB_CLIENT_SECRET",
      "scopes": [],
      "pkce": false,
      "refresh": true,
      "token_auth_method": "client_secret_post"
    }
  }
}
```

Fields:

| Field | Meaning |
|---|---|
| `enabled` | disabled providers are neither advertised nor required to have a secret |
| `type` | currently `oauth2` |
| `authorization_endpoint`, `token_endpoint` | must be HTTPS (HTTP only for loopback/mock) |
| `client_id` | provider client id |
| `client_secret_env` | env var holding the secret (never inline) |
| `scopes` | requested scopes; `[]` for GitHub App permissions |
| `pkce` | send S256 PKCE (default `true`) |
| `refresh` | allow refresh-token grant (default `true`) |
| `token_auth_method` | `client_secret_post` (default), `client_secret_basic`, `none` |
| `authorization_params` | extra string params; protocol params cannot be overridden |

Adding Google/Slack/another OAuth 2.0 service is a registry entry, not a
code change. Only genuinely non-standard providers need an adapter.

## Configuration

All configuration is environment-based:

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `TOKEN_BROKER_SHARED_SECRET` | yes | — | internal `X-Broker-Secret` |
| `TOKEN_BROKER_ENCRYPTION_KEY` | yes | — | AES-256-GCM key, 32 bytes base64 (`openssl rand -base64 32`) |
| `TOKEN_BROKER_PUBLIC_BASE_URL` | no | `https://login.cladone.com` | public login origin (served by Gate One); used for callback/connect URLs |
| `TOKEN_BROKER_RETURN_TO_HOSTS` | no | public host | comma list; `.cladone.com` allows the apex + subdomains |
| `TOKEN_BROKER_DB_PATH` | no | `/data/token-broker.db` | SQLite file |
| `TOKEN_BROKER_PROVIDERS_FILE` | no | `/app/providers.json` | provider registry |
| `TOKEN_BROKER_STATE_TTL_SECONDS` | no | `600` | authorization state lifetime |
| `TOKEN_BROKER_REFRESH_SKEW_SECONDS` | no | `60` | refresh this long before expiry |
| `TOKEN_BROKER_HTTP_TIMEOUT_SECONDS` | no | `15` | provider HTTP timeout |
| `TOKEN_BROKER_ADMIN_SECRET` | no | — | operator API (`X-Broker-Admin-Secret`); absent = disabled (404) |
| `TOKEN_BROKER_RETENTION_DAYS` | no | `0` | purge **paused** connections after N days; 0 = keep forever |

## Storage

SQLite is intentional: one broker replica, low write volume (one row
per user × provider), no new database server, smallest blast radius.

- AES-256-GCM is applied **by the application before SQLite**; the file
  and WAL contain ciphertext only.
- The encryption key comes from the environment, not from the volume.
- WAL mode, `busy_timeout=5000`, `synchronous=FULL`.
- The data directory is `0700` and the database file `0600`.
- Schema migrations use `PRAGMA user_version`.
- Backups must include the `token_broker_data` volume; take a
  consistent snapshot (`sqlite3 ... "VACUUM INTO ..."` or checkpoint +
  copy). The key is required to restore usable tokens.
- No horizontal scaling: a second replica needs a shared database
  (move to Postgres) and a shared key. The store layer is deliberately
  small so that swap stays local.

## Local development and tests

```bash
cd compose/token-broker
npm ci
npm test
```

The tests start a fake OAuth 2.0 provider on loopback and cover:
authorization URL/PKCE, code exchange, encrypted storage, refresh and
rotation, single-flight refresh, reauthorization on `invalid_grant`,
provider outage, callback state/user binding, secret/user enforcement,
returnTo allow-list, HTML escaping, the refusal to call the provider on
erase, zero/invalid expiry handling, and the refusal of provider
redirects/userinfo.

Run the broker against a local SQLite file:

```bash
TOKEN_BROKER_SHARED_SECRET=dev-secret \
TOKEN_BROKER_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
TOKEN_BROKER_PUBLIC_BASE_URL=http://127.0.0.1:4000 \
TOKEN_BROKER_DB_PATH=/tmp/token-broker.db \
npm start
```

## Docker Compose

The service is defined under the `token-broker` profile so a normal
`make deploy` does **not** start it before its secrets and provider are
ready:

```bash
docker compose --profile token-broker up -d --build token-broker
```

It is attached to `internal` only. `token_broker_data` is a named
volume; `providers.json` is mounted read-only, so adding/changing a
provider is a file edit + container restart (no image rebuild).

## Gateway integration (facades)

The public surface is split into two facades (see `docs/MCP.md` in the
gate-one repository), each filtered by consumer type:

| Host | Consumer | Content | Provider (broker) |
|---|---|---|---|
| `api.cladone.com` | REST | `/github/*` → `https://api.github.com` | `github` |
| `mcp.cladone.com` | MCP | `/grammar` (tools derived from the REST API) | — |

Only routes declaring `upstream.delegated` call the broker; the MCP
endpoint above is ordinary (no delegation). At startup and on `SIGHUP`
Gate One validates every delegated provider name against `GET /providers`;
an unknown/disabled provider or an unreachable broker makes Gate One
**refuse to start**. The broker must therefore be healthy *before* a
delegated route goes live (`make broker-check`, `broker-up`,
`broker-activate`).

The MCP endpoints are gated by auth-bridge on **per-endpoint audience**
(`X-MCP-Resource` in, `MCP_RESOURCE` comma-separated allow-list,
fail-closed), not by the broker. Client setup for OpenCode V2, Claude Code
and Codex is documented in gate-one's `docs/MCP.md`.

## GitHub App

`github` is **enabled** in `providers.json` (a GitHub App: `client_id`
set, secret via `GITHUB_CLIENT_SECRET`, `scopes: []` — permissions come
from the App). Setup, for reference or a rebuild:

1. create the GitHub App and set `client_id` + `enabled: true`;
2. put the client secret in `.env` as `GITHUB_CLIENT_SECRET`;
3. register the callback `https://login.cladone.com/oauth/github/callback`;
4. in the GitHub App settings, enable **Expire user authorization
   tokens** so the token endpoint also returns a refresh token and
   `expires_in` (the broker refreshes with single-flight);
5. set `GITHUB_CLIENT_SECRET` and the broker URL/secret for Gate One
   and Gate One;
6. grant the App the read-only permissions needed by the exposed
   routes/tools first, then widen them deliberately.

GitHub App user-to-server tokens are the target: per-user identity,
short-lived access tokens, refresh tokens, and permissions configured
on the App. A fine-grained PAT would be a shared service account, not
delegation. GitHub does not implement RFC 8693 token exchange, so the
authorization-code flow and stored refresh token are required.

## Security notes

- Never log tokens, authorization codes, client secrets, or state.
- The callback consumes state exactly once, binds it to the provider
  and user, and expires it.
- `returnTo` is allow-listed at connect time and stored server-side;
  the callback never trusts a fresh user-supplied redirect.
- The broker does not accept provider definitions or endpoints from
  Gate One (no SSRF/secret exfiltration surface).
- Disconnect pauses; Erase removes the local row. Neither calls the
  provider: the same credential may be used elsewhere. The user revokes
  the application authorization at the provider if needed.
