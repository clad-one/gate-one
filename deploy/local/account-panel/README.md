# Account panel, locally

The application renders the session in its own account panel instead of
the built-in badge.

## Run

```bash
cd gate-one-src/deploy/local/account-panel
./run.sh          # needs gate-one on PATH or in ./bin (BIN_DIR)
```

Open <http://app.demo.localhost:3000> and sign in as `alice`/`alice` or
`bob`/`bob` (embedded `dev` provider, loopback only).

## What to look at

- `config/index.html` + `config/panel.js` read the session probe
  (`/__gate-one/auth`) and render the user, roles and claims;
- the route declares no `userBadge`: the account UI belongs to the
  application;
- sign-out goes through the same Gate One endpoint as the built-in badge.

The panel is display only: route rights stay in `auth.identity`.
