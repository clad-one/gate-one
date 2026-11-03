# Release verification key

`cosign.pub` verifies the `SHA256SUMS` bundle attached to a Gate One
release. The release pipeline lives in this source repository (`release.sh`).
The private key is **not** in this repository.

- Public key: `release/cosign.pub`
- SHA-256 of the public key: see `release/cosign.pub.sha256`
- Private key on the build host: `~/.config/gate-one/release/cosign.key`
  (mode 600, encrypted with `~/.config/gate-one/release/cosign.password`)
- Key generated: 2026-11-03, cosign v3.1.4

## Verify a release

```bash
cosign verify-blob --key cosign.pub \
  --bundle SHA256SUMS.bundle SHA256SUMS
sha256sum -c SHA256SUMS
```

The public key is also copied into each release directory as
`cosign.pub` and covered by `SHA256SUMS`.

## Rotation

A release key is not a secret, but its private half is. To rotate:

1. generate a new pair (`cosign generate-key-pair`);
2. replace `release/cosign.pub` and `release/cosign.pub.sha256`;
3. sign the next release with the new private key;
4. keep old public keys available to verify old releases.

If the project adopts an organisation-owned KMS or an OIDC keyless flow,
replace this local key and update `release.sh` accordingly.
