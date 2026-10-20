# Cladone Gate One — sources

Config-driven reverse proxy written in Go: SSO delegation to
auth-bridge, role guards, PWA wrapping, upstream proxying and
userscript injection.

This repository holds the **sources** of Gate One. Two sibling
repositories complete the picture:

| Repository | Contents |
|---|---|
| `gate-one-src` (this one) | Go sources, unit tests, smoke tests, developer docs |
| `gate-one` (public) | user documentation, demo, Dockerfile / compose examples |
| `cladone-it-infra` | deployment stack: `compose/gate-one/` (prebuilt binary + live `api-routes.json`), Ansible, Keycloak |

The live production configuration lives in
`cladone-it-infra/compose/gate-one/api-routes.json`.
`testdata/` holds the live config and its JSON schema (the config copy
feeds `TestLoadRealConfigStrict`, the strict grammar check). Refresh
both from the infra repo when the live config changes:

```bash
cd ../cladone-it-infra && make sync-config
```

## Build

```bash
./build.sh                 # -> bin/gate-one
./run.sh                   # go run, reads testdata/api-routes.json
./bin/gate-one -config testdata/api-routes.json -check
```

## Tests

```bash
go vet ./...
go test ./...
./smoke.sh                 # end-to-end: fake backend + auth-bridge + gateway
```

`test/ui` contains the jsdom harness for the injected guard script
(`npm install && npm test`).

## Releasing to the infrastructure repository

From `cladone-it-infra`:

```bash
make gate-one              # builds this repo and copies bin/gate-one
                           # into compose/gate-one/bin/
```

`make deploy` (in `cladone-it-infra`) performs that build first. The
infra Dockerfile only packages the prebuilt binary — it never needs a
Go toolchain on the server.

## Layout

```
cmd/gate-one/       entrypoint (flags, SIGHUP hot reload, shutdown)
internal/core/      config grammar + route loading/validation
internal/proxy/     reverse proxy, auth, guards, rewriting, limits
internal/pwa/       PWA wrap (manifest, service worker, Workbox)
internal/mcp/       MCP endpoint
test/ui/            guard-script harness (jsdom)
sw-sim/             service-worker simulator
testdata/           reference production config
```

## License

Source-available, BSL-custom — see `LICENSE`.
