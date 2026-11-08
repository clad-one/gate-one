# Usage events, locally

Gate One emits signed usage events to the reference audit plugin, which
logs them. Everything runs on this machine; the plugin is built from the
source tree and needs Go.

## Run

```bash
cd gate-one-src/deploy/local/usage-events
./run.sh          # gate-one + static app + go run ./cmd/plugin-audit-echo
```

Open <http://app.demo.localhost:3000> and sign in as `alice`/`alice`. The
plugin prints the batches it verifies and acknowledges.

## What to look at

- the WAL under `config/usage-wal/`;
- the signed manifest (`config/audit.manifest.json`) and the trust store
  (`config/trust-store.json`): Gate One refuses a plugin whose signature,
  digest or subscription does not match;
- `auth` events are fail-closed: if the WAL cannot be written, the login
  is refused with `503` before the session exists;
- no token, cookie or email in the events: the user is the opaque
  `X-Gate-One-Subject` value.

Stop the plugin and reload the page: `request` and `error` events are
best-effort and stay in the WAL until it comes back.
