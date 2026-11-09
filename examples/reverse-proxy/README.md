# Gate One behind an ingress

Complete, minimal front-proxy configurations for Gate One. Each one
terminates TLS, forwards the public host and the `X-Forwarded-*` headers
Gate One needs, and streams responses (SSE, long-lived requests).

| File | Ingress | Notes |
|---|---|---|
| [`Caddyfile`](Caddyfile) | Caddy 2 | automatic TLS; forwarded headers and streaming are defaults |
| [`traefik.yml`](traefik.yml) + [`traefik-dynamic.yml`](traefik-dynamic.yml) | Traefik v3 | file provider, no Docker socket; active `/readyz` check |
| [`nginx.conf`](nginx.conf) | nginx | complete configuration; every detail is explicit |

Gate One listens on plain HTTP (`-addr :3000` by default) and must **not**
be reachable by clients: it trusts `X-Forwarded-*` from its immediate
peer. Bind it to loopback or keep it on a Docker network.

```text
browser ──► ingress :443 ──► Gate One :3000 ──► your application
            (TLS, forwarding headers, streaming)
```

## Common requirements

- **Host**: Gate One routes on `(host, path)`, so the ingress must pass the
  public `Host` unchanged (the nginx default replaces it).
- **`X-Forwarded-Proto`**: drives the redirect and `returnTo` URLs; without
  it, logins bounce to `http://`.
- **`X-Forwarded-For`**: Gate One uses the **last** entry as the client IP
  for rate limits. Behind a CDN, configure real-IP handling in the ingress.
- **No response buffering**: SSE and long streams must reach the browser as
  they are produced.
- **Uploads**: lift the request-body limit if the ingress has one.
- **TLS URL matches `loginBaseUrl`**: the session cookies are `Secure` when
  the configured login URL is `https://`, so a plain-HTTP public URL would
  make the browser drop them.

## Try a configuration

```bash
./validate.sh          # nginx -t, caddy validate, traefik start-up (Docker)
```

The script binds no host port and needs no network: it only parses the
configurations (Traefik is started briefly, because it has no dry-run).

## Using them

**Caddy** — `caddy run --config Caddyfile` (or copy it to
`/etc/caddy/Caddyfile`). Replace the hostnames; TLS is automatic.

**Traefik** — `traefik --configfile=traefik.yml`, with
`traefik-dynamic.yml` next to it. `127.0.0.1:3000` assumes Traefik shares
the host network; in Docker use the service name. The label-based Docker
form is in [`../../deploy/vps/`](../../deploy/vps/).

**nginx** — mount `nginx.conf` at `/etc/nginx/nginx.conf` with the
certificates at `/etc/nginx/certs/`, or copy the `map`/`upstream`/`server`
blocks into `/etc/nginx/conf.d/gate-one.conf`. Point the certificate paths
at your own (certbot: `/etc/letsencrypt/live/<domain>/`).

Every configuration here assumes one Gate One instance at `:3000`. For
several replicas, list them in the upstream/service and keep the session
store shared (see [Horizontal scaling](https://clad-one.github.io/gate-one-doc/docs/features/horizontal-scaling/)).
