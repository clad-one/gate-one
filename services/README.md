# Companion services

Reference implementations of the optional services Gate One talks to over
HTTP. They are **not** part of the `gate-one` binary: each runs as its own
process/container.

| Service | Role | Gate One config |
|---|---|---|
| `token-broker/` | Per-user delegated credentials: a provider registry plus an encrypted per-user token store. | `tokenBroker` + `routes[].upstream.tokenBroker` |
| `auth-bridge/` | Reference implementation of the `http-bridge` contract (external request verification, identity/IAM facts). | `authProvider.type: "http-bridge"` |

Neither service decides Gate One's policy: the token broker returns a
token for one authenticated user; the bridge returns identity/IAM facts.

[NOTE]
====
The managed billing ingestion service is **not** part of this repository.
It runs in Cladone's environment, not the customer's; its code, images
and runbooks are kept in a private repository.
====
See the product docs: **Delegated credentials**, **Token broker** and
**HTTP bridge contract**.

## Build

Each service is a self-contained Node.js project with its own `Dockerfile`:

```bash
docker build -t gate-one-token-broker services/token-broker
docker build -t gate-one-auth-bridge   services/auth-bridge
```

Or run the tests locally:

```bash
cd services/token-broker && npm ci && npm test
cd services/auth-bridge   && npm ci && npm test
```

## Configuration

Both are configured entirely through the environment (see each `README.md`).
Secrets (provider client secrets, the broker encryption key, the shared
secret) are read from the environment and never written to a config file.

## Licence

These services are part of the Gate One distribution and follow the
repository licence (`LICENSE`, BSL-CUSTOM). `auth-bridge` is an
authentication adapter and stays under the Gate One licence.
