# Metering audit (local, user side)

The part of the billing chain that runs **inside your environment**, with
no receiver:

```text
client ──► Gate One ──► metric + tariff ──► hold (signed allowance)
                 │
                 └── settle ──► outbox (bounded, local)
                                   │
                                   └──► gate-one meter verify|export|check
```

Nothing is delivered here, so every record stays pending. That is the
point: the audit proves what the gateway priced, from local state only.

## Run it

```bash
./build.sh                 # once, from the repository root
cd deploy/local/metering-audit
./run.sh                   # terminal 1
./verify.sh                # terminal 2
```

`run.sh` generates a sink key and an allowance issuer, mints a signed
allowance, starts a static app and the gateway. `verify.sh` sends five
requests and then:

- **replays** each record against the tariff version it names;
- exports a **signed snapshot** and verifies it offline (signature,
  per-record hashes, body digest);
- **tampers** with a copy and shows that verification fails;
- prints the outbox: pending records, zero committed (no receipt, no
  truncation).

## What it demonstrates

| Observation | Where |
|---|---|
| The price is computed before the backend call | `routes[].metric` + `usage.tariffs` |
| A request is refused when the allowance is short | `402 insufficient_allowance` |
| Delivery is decoupled from the request path | `usage.outbox` + `usage.sink` |
| Nothing is deleted without an ack | `gate-one billing pending` |
| A record can be audited offline | `gate-one meter verify/export/check` |

## Delivery

With a receiver, `usage.sink.url` pushes signed batches and
`gate-one billing ack -receipt …` commits the acknowledged offset. With
`usage.profile: "airgap"`, the pusher writes signed bundles to
`usage.sink.exportDir` instead; the `billing-byo` licence feature is
required. Both paths are documented under
**Metering and billing** on the docs site.
