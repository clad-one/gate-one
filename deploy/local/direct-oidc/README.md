# Direct OIDC, locally

Gate One is the OIDC relying party and talks to one issuer directly,
with no IAM in between. The demo IdP stands in for Keycloak, Entra ID,
Auth0 or Google.

```text
browser → Gate One → demo IdP (OIDC issuer)
```

## Run

```bash
cd gate-one-src/deploy/local/direct-oidc
BIN_DIR=~/gate-one-bin ./run.sh     # gate-one + demo-idp
```

Open <http://app.demo.localhost:8080>; sign in as `alice@demo.test` or
`bob@demo.test`. The demo IdP auto-consents.

## What it shows

- discovery, authorization code, JWKS and the signed session, all against
  a real OIDC issuer flow;
- `roleClaims: ["groups"]`, so the badge shows the roles the issuer emits;
- no broker: the issuer is the only identity source.

## Production

Replace the `authProvider` block in `config/routes.json` with a real
issuer (`issuer`, `clientId`, `clientSecretEnv`, `loginBaseUrl` on a
public host). The [Keycloak with Google example](/docs/examples/keycloak-google/)
covers the external-IAM variant; [`deploy/vps/`](../../vps/) does it with
TLS and Traefik.
