# Getting started, locally

The smallest complete run: Gate One in front of a static site, with the
embedded `dev` identity provider. No external service, no Docker.

## Run

```bash
cd gate-one-src/deploy/local/getting-started
./run.sh          # needs gate-one on PATH or in ./bin (BIN_DIR)
```

Open <http://app.demo.localhost:3000>.

## Sign in

| User | Password | Role |
|---|---|---|
| `alice` | `alice` | `user` |
| `bob` | `bob` | `admin` |

The `dev` provider is loopback-only and must never be exposed.

## What to look at

- the redirect to `login.demo.localhost:3000`;
- the shared `demo.localhost` session cookie;
- the user badge in the top-right corner and its sign-out button;
- the `-check` output printed before startup.
