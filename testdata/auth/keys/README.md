# Test keys — TEST ONLY

These Ed25519 seeds were generated with:

```bash
go run ./cmd/cladone-auth keygen -out testdata/auth/keys/acme-2026.key
go run ./cmd/cladone-auth keygen -out testdata/auth/keys/contoso-2026.key
```

They are **only** for the local Compose/E2E stack. Never use them in
production, staging or any environment reachable from the internet.
