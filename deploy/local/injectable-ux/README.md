# Injectable UX, locally

The guard, the user badge, the injection bundle and the UI gating, on a
static site that has none of them.

## Run

```bash
cd gate-one-src/deploy/local/injectable-ux
./run.sh          # needs gate-one on PATH or in ./bin (BIN_DIR)
```

Open <http://app.demo.localhost:3000/dashboard.html> and sign in as
`alice`/`alice` (`user`) or `bob`/`bob` (`admin`).

## What to look at

| Element | Rule in config/routes.json | Expected |
|---|---|---|
| beta feature card | `hidden: "before"` | hidden while anonymous |
| export button | `auth: "before"` | opens the login first |
| danger zone card | `roles: ["admin"]` | only with `bob` |
| announcement banner | `inject: "bundle.json"`, `when: "/dashboard"` | injected on the dashboard page |
| nonce CSP | `csp.mode: "nonce"` | header carries a nonce, no violation in DevTools |

Sign in as `bob` for the danger zone, then `alice` to see it disappear.
