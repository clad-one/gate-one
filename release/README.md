# Release verification key

`cosign.pub` verifies the `SHA256SUMS` bundle attached to a Gate One
release. The release pipeline lives in this source repository (`release.sh`).
The private key is **not** in this repository.

- Public key: `release/cosign.pub`
- SHA-256 of the public key: see `release/cosign.pub.sha256`
- Private key on the build host: `~/.config/gate-one/release/cosign.key`
  (mode 600, encrypted with `~/.config/gate-one/release/cosign.password`)
- Key generated: 2026-11-03, cosign v3.1.4

## Signing model: offline, key-based

The release is signed **offline**. `release/signing-config.json` carries no
Rekor transparency-log and no TSA service, so signing and verifying need no
external service. The trust anchor is the **pinned public key**
(`release/cosign.pub`), not a transparency log.

```bash
# sign (release.sh does this)
cosign sign-blob --yes --key "$COSIGN_KEY" \
  --signing-config release/signing-config.json \
  --bundle dist/SHA256SUMS.bundle dist/SHA256SUMS
```

The bundle therefore contains only `publicKey` + `messageSignature` (no
`tlogEntries`, no RFC-3161 timestamp). Rekor/TSA are deliberately not used:
the operator verifies against a key they already hold, and a public
transparency log would add a build-time dependency for no added trust here.

## Verify a release

```bash
cosign verify-blob --key cosign.pub --insecure-ignore-tlog \
  --bundle SHA256SUMS.bundle SHA256SUMS
sha256sum -c SHA256SUMS
```

`--insecure-ignore-tlog` is expected: the bundle has no transparency-log
entry by design. The pinned key and the SHA-256 checksums are still
enforced.

The public key is also copied into each release directory as
`cosign.pub` and covered by `SHA256SUMS`.

## Rotation

A release key is not a secret, but its private half is. To rotate:

1. generate a new pair (`cosign generate-key-pair`);
2. replace `release/cosign.pub` and `release/cosign.pub.sha256`;
3. sign the next release with the new private key;
4. keep old public keys available to verify old releases.

If the project adopts an organisation-owned KMS, replace this local key and
update `release.sh` accordingly. (An OIDC keyless flow would reintroduce a
transparency log and is intentionally not used.)
