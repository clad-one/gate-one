# Gate One on a VPS

A starting point for a real deployment: Traefik terminates TLS, Gate One
protects the application, and `cladone-auth` federates Google.

```text
browser ──► Traefik (443, Let's Encrypt)
              ├─► app.<domain>    Gate One ─► your application
              ├─► login.<domain>  Gate One (login surface)
              └─► auth.<domain>   cladone-auth ─► Google (or demo IdP)
```

Nothing phones home. Gate One, the IAM and Traefik are the whole
stack; Google is contacted only when a user signs in.

## What this is not

A hardened platform. It has no backups, no monitoring, no log rotation,
no intrusion detection and no firewall rules. Add those before you trust
it with production traffic.

## 1. Prerequisites

- a VPS with a public IPv4 address, Docker and Compose v2;
- a domain whose DNS you control;
- the three binaries, verified, in `./bin`:

  ```bash
  # on the machine where you verified the release
  scp gate-one cladone-auth demo-idp vps:/srv/gate-one/deploy/vps/bin/

  # or build them from this repository
  ./build.sh
  go build -o bin/cladone-auth ./cmd/cladone-auth
  go build -o bin/demo-idp    ./cmd/fake-google
  ```

## 2. DNS

Point these names at the VPS:

| Name | Purpose |
|---|---|
| `app.<domain>` | the protected application |
| `login.<domain>` | the login surface |
| `auth.<domain>` | the embedded IAM |
| `idp.<domain>` | demo IdP, only while smoke-testing |

Ports 80 and 443 must be reachable: port 80 is used for the ACME
challenge and the HTTPS redirect.

## 3. Deploy

```bash
scp -r deploy/vps vps:/srv/gate-one/
ssh vps
cd /srv/gate-one/vps

cp .env.example .env
$EDITOR .env        # DOMAIN, ACME_EMAIL (leave the secrets empty)
make init           # generates the secrets and renders config/
make up             # Traefik + Gate One + IAM + backend
```

`make init` creates `config/embedded-iam.json` (Google), `config/embedded-iam.demo.json`
(Google + demo IdP), `config/routes.json`, `config/routes.ha.json`,
`config/idp.json` and an IAM signing key.

`make up` needs Google credentials: the IAM refuses to start without at
least one usable upstream, and says so. That is why the demo comes first.

## 4. Smoke test with the demo IdP

Before touching Google, prove the stack end to end:

```bash
make demo           # adds idp.<domain> and the "Demo IdP" upstream
```

Open `https://app.<domain>`, choose **Demo IdP**, sign in as
`alice@demo.test` (auto-consent). You should land back on the
application with a user badge and `X-User-*` headers in the backend page.

If this fails, the problem is local (DNS, TLS, secrets) — not Google.

## 5. Configure Google

1. In the Google Cloud console, create an OAuth client (Web application)
   with the authorized redirect URI:

   ```text
   https://auth.<domain>/t/main/callback
   ```

   That is the **IAM** callback, not Gate One's.

2. Put the client id and secret in `.env`:

   ```text
   GOOGLE_CLIENT_ID=...
   GOOGLE_CLIENT_SECRET=...
   ```

3. Apply and stop the demo IdP:

   ```bash
   make down
   make up
   ```

The IAM advertises Google on its chooser; Gate One never sees the
Google token.

## 6. Operations

| Command | Effect |
|---|---|
| `make logs` | follow Traefik, Gate One and the IAM |
| `make reload` | `SIGHUP` Gate One: re-reads the config, refuses an invalid file |
| `make check` | validate the rendered Gate One configuration |
| `make ha` | add Redis and a second Gate One replica |
| `make destroy` | stop everything and delete the generated config |

Edit `config/routes.json` on the server, then `make reload`: no rebuild,
no container restart. An invalid file is refused and the previous
configuration stays active.

### High availability

`make ha` starts Redis and a second replica (`config/routes.ha.json`
uses `sessionStore: redis`). Both replicas share `GATE_ONE_SESSION_KEY`,
so a session created on one is accepted by the other. Keep the default
bbolt store for a single replica.

### Users and grants

```bash
docker compose exec cladone-auth /bin/cladone-auth user list -tenant main
docker compose exec cladone-auth /bin/cladone-auth user set  -tenant main \
    -issuer https://accounts.google.com -sub '<google-sub>' -roles admin
```

A federated user is looked up by issuer and subject (both shown by
`user list`) or by `-id`; `-email` targets local accounts.

Grant changes apply at the next login. A federated user appears after
their first sign-in.

### Add an application

Add a route in `config/routes.json`, point its DNS name at the VPS, add
the host to the Traefik rule (or use a wildcard), then `make reload`.

## 7. Checks and back-ups

- `data/acme.json` holds the TLS certificates: keep it, and keep it `600`.
- `config/iam.key` signs the IAM tokens: a back-up is required to
  keep sessions valid across a rebuild.
- `.env` holds every secret: it is the only copy unless you store it
  elsewhere. Back it up like a password.
- The Redis data is disposable (sessions); the IAM user directory is
  not. With the `ha` profile the user grants live in Redis — back it up
  or move it to a persistent volume before relying on it.

## Before production

- Put a firewall in front: only 80/443 public.
- Restrict access to the Docker socket (Traefik needs it).
- Add log rotation for the containers and Traefik.
- Monitor `/readyz` on Gate One and `/health` on the IAM.
- Back up `.env`, `config/iam.key` and the IAM directory.
