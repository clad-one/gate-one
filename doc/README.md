# Gate One developer documentation

Internal, contributor-facing documentation. These pages describe how the
gateway is built and tested; they are **not** the user documentation.

User documentation, examples and the generated configuration reference
live in the [`gate-one-doc`](https://github.com/clad-one/gate-one-doc)
repository and are published at
<https://clad-one.github.io/gate-one-doc/>.

## In this directory

| File | Contents |
|---|---|
| `auth-providers.adoc` | Provider contract and authentication internals: the four provider types, sessions, revocation, logout, claim mapping, migration. |
| `auth-broker.adoc` | `cladone-auth` internals: tenants, upstreams, mappings, users, policy, degraded mode, key rotation. |
| `auth-test-plan.adoc` | Authentication test plan: behaviour decisions, fixtures, traceability matrix and the detailed cases. |
| `plugins.adoc` | Plugin and usage-event internals: taxonomy, invariants, the event contract, WAL durability, the signed manifest and licensing. |

## User guides that are not internal

Two extended guides are maintained for **users** on the documentation
site, not here:

* Strict Content Security Policy —
  <https://clad-one.github.io/gate-one-doc/v0.4.5-docs.4/docs/guides/strict-csp/>
* Declarative UI gating (`data-gtw-*`) —
  <https://clad-one.github.io/gate-one-doc/v0.4.5-docs.4/docs/guides/ui-gating/>

## Related

* `README.md` at the repository root — build, quickstart, release.
* `services/README.md` — the `auth-bridge` and token broker companion
  services.
* `PLUGIN-LICENSING.md` — the plugin licence exception.
