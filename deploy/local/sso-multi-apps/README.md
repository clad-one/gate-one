# Multi-application SSO, locally

One provider, one cookie domain, two applications.

```text
app.demo.localhost      ─┐
                         ├─ Gate One ─ demo IdP
reports.demo.localhost  ─┘
```

## Run

```bash
cd gate-one-src/deploy/local/sso-multi-apps
BIN_DIR=~/gate-one-bin ./run.sh     # gate-one + demo-idp + two backends
```

Open <http://app.demo.localhost:8080>, sign in, then open
<http://reports.demo.localhost:8080>: no second login.

## What enables SSO

Both are in `config/routes.json`:

- **the same `authProvider`** verifies both routes;
- **`cookieDomain: "demo.localhost"`** covers both hosts, so the browser
  sends the same session cookie to each.

Each application is unchanged: it receives a normal HTTP request and the
identity headers.

## What it shows

The backend page carries the application name, so you can tell which one
answered. The badge appears on the route that declares it and not on the
other, which is the per-route UX control.

## Production

Same shape with your own hosts and a public cookie domain; see
[`deploy/vps/`](../../vps/).
