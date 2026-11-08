# Deploy

Runnable deployments of Gate One, from a laptop to a VPS.

| Directory | What it runs | Needs |
|---|---|---|
| [`local/`](local/) | Demos on `*.localhost`, plain HTTP | the Gate One binaries; Docker for the OIDC ones |
| [`vps/`](vps/) | Production shape: Traefik (TLS) + Gate One + `cladone-auth` | a public domain and a VPS |

## The binaries

Neither directory builds Gate One. Put these three binaries in one
directory and point `BIN_DIR` at it:

| Binary | Release asset | Role |
|---|---|---|
| `gate-one` | `gate-one_<v>_<os>_<arch>.tar.gz` | the gateway |
| `cladone-auth` | `cladone-auth_<v>_<os>_<arch>.tar.gz` | the optional embedded IAM |
| `demo-idp` | `gate-one-demo-idp_<v>_<os>_<arch>.tar.gz` | a fake OIDC provider, **demos only** |

`demo-idp` is `cmd/fake-google`: a Google-compatible OIDC provider with
auto-consent, used to exercise the real OIDC flow without an external
account. It must never be exposed publicly.

A source build produces the same three binaries:

```bash
./build.sh
go build -o bin/cladone-auth ./cmd/cladone-auth
go build -o bin/demo-idp    ./cmd/fake-google
```

## `local/` at a glance

| Demo | Stack |
|---|---|
| `getting-started` | Gate One + static site, embedded dev provider |
| `account-panel` | Gate One + an application that renders its own account panel |
| `injectable-ux` | Gate One + injection bundle + UI gating + nonce CSP |
| `usage-events` | Gate One + the reference audit plugin (needs Go) |
| `direct-oidc` | Gate One to demo IdP, no IAM |
| `sso-multi-apps` | two applications, one provider, one cookie domain |
| `embedded-iam` | Gate One to `cladone-auth` to demo IdP, with grants |
| `redis` | two tenants, two Gate One instances, shared Redis |

Every directory has its own README and a `run.sh` that prints the URLs.

## `vps/`

The same embedded-IAM shape with Traefik in front, TLS from Let's
Encrypt, a real domain and real Google as the upstream IdP. It is a
starting point, not a hardened platform: see its README for what is out
of scope.
