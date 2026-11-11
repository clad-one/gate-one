# Publishing rule

This repository is public. It contains only what runs **inside a
customer's Gate One environment**.

Managed-side code runs in Cladone's environment and lives in a private
repository: the billing ingestion service, the invoice adapter, the
reconciliation job and the end-to-end harness that drives them. It must
never be added here, linked from a public doc, or shipped in an archive.

Enforcement:

- `.gitignore` ignores `services/billing-ingest/` and
  `deploy/local/billing/`, so a local copy cannot be committed by
  accident;
- `release.sh` refuses to run if either path exists, archives only the
  public services (`token-broker`, `auth-bridge`), strips the managed
  demo from the demo archive, and asserts that the tarballs and the built
  site contain no managed-side code or runbook.

When in doubt: if the code would run on infrastructure the customer does
not control, it does not belong in this tree.
