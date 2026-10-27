#!/usr/bin/env bash
# release.sh — prepare LOCAL release artifacts. It never pushes, tags
# or uploads anything: this repository intentionally has no remote.
#
#   ./release.sh                 # version from ./VERSION
#   VERSION=1.0.0 ./release.sh   # override
#
# Output: dist/
#   gate-one_<version>_<os>_<arch>.tar.gz   binary + schemas + examples
#   SHA256SUMS
#   RELEASE_NOTES.md
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

version="${VERSION:-$(cat VERSION 2>/dev/null || echo 0.1.0)}"
version="${version#v}"
commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
dist="dist"

rm -rf "$dist"
mkdir -p "$dist"

targets=(
	linux/amd64
	linux/arm64
	darwin/amd64
	darwin/arm64
	windows/amd64
)

for target in "${targets[@]}"; do
	os="${target%/*}"
	arch="${target#*/}"
	bin="gate-one"
	[ "$os" = "windows" ] && bin="gate-one.exe"

	stage="$dist/stage/gate-one_${version}_${os}_${arch}"
	mkdir -p "$stage/examples" "$stage/doc"

	echo "building ${os}/${arch}…"
	CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build \
		-trimpath \
		-ldflags "-s -w -X main.version=${version} -X main.commit=${commit} -X main.date=${date}" \
		-o "$stage/$bin" ./cmd/gate-one

	cp testdata/api-routes.schema.json "$stage/"
	cp testdata/inject-bundle.schema.json "$stage/"
	cp examples/static.api-routes.json "$stage/examples/"
	cp examples/dev.api-routes.json "$stage/examples/"
	cp examples/http.api-routes.json "$stage/examples/"
	cp examples/oidc.api-routes.json "$stage/examples/"
	cp doc/auth-providers.adoc "$stage/doc/"
	cp doc/ui-gating.adoc "$stage/doc/"
	cp README.md LICENSE VERSION "$stage/"

	tar -czf "$dist/gate-one_${version}_${os}_${arch}.tar.gz" \
		-C "$stage" .
	rm -rf "$stage"
done

rmdir "$dist/stage" 2>/dev/null || true

# Checksums (sha256sum on Linux, shasum on macOS).
(
	cd "$dist"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum ./*.tar.gz > SHA256SUMS
	else
		shasum -a 256 ./*.tar.gz > SHA256SUMS
	fi
)

cat > "$dist/RELEASE_NOTES.md" <<EOF
# Gate One ${version} — ${date}

Commit: \`${commit}\`

Local release artifacts only: this repository has no remote and this
script never pushes, tags or uploads.

## Highlights

- **Instant onboarding.** \`gate-one init\` writes a minimal, working
  \`api-routes.json\`; \`gate-one -config api-routes.json\` starts it. Two
  commands, no external service for the dev template.
- **Embedded dev IdP** (\`authProvider.type: "dev"\`). A dedicated
  \`login.<domain>\` host, a real alice/bob login form, a shared session
  cookie and a loopback-only safety guard. No Node, no Keycloak, no Go
  toolchain on the target.
- **Native OIDC Relying Party** (\`authProvider.type: "oidc"\`).
  Discovery, authorization code + PKCE, state/nonce, JWKS validation,
  signed session, RP-initiated logout and local MCP bearer validation:
  Keycloak, Entra, Google, Authentik, Okta, Auth0 or any OIDC IdP —
  without auth-bridge. auth-bridge remains available as
  \`type: "http"\`, including in front of Keycloak.
- **Authentication provider abstraction.** \`authProvider.type: "http"\`
  keeps auth-bridge (Keycloak) as the reference adapter. Any other
  service must implement the Gate One auth contract (a custom adapter);
  overriding \`verifyUrl\`/\`headers\` only adapts the verification call.
  The legacy \`oidc\` block and \`-authBridge\` flag keep working
  unchanged: existing deployments do not need a config edit.
- **No silent login loops.** An unreachable provider now answers
  \`502 authentication_unavailable\` (readable HTML for a navigation,
  JSON for a fetch) instead of a 401/login redirect.
- **Public routes start alone.** A frontend route with no \`auth\` no
  longer requires an \`oidc\` block.
- **\`gate-one doctor\`** checks config grammar, provider construction,
  provider health and delegated-provider reachability before starting.
- **\`gate-one version\`** and release ldflags.

## Upgrade notes

- Existing configs (\`oidc\` + auth-bridge) are translated to an internal
  \`authProvider.type: "http"\`; no action required.
- A provider outage now returns 502 instead of 302/401. This is the
  intended fix for the login loop; alerts that keyed on 401 for an
  outage should key on 502.
- The embedded \`dev\` provider refuses a non-loopback bind. Use
  \`--dev-allow-remote\` only for a demo.
- Native OIDC is available (\`authProvider.type: "oidc"\`). The IdP must
  register the redirect URI \`<loginBaseUrl>/auth/callback\`. For MCP
  tokens, the scope is the gate; set \`mcpAudience\` for a strict
  \`aud\` check. auth-bridge remains fully supported (type \`http\`).

## Artifacts

Per platform: \`gate-one_${version}_<os>_<arch>.tar.gz\` containing the
static binary, both JSON schemas, the four onboarding examples, the
auth-provider guide, README, LICENSE and VERSION.
EOF

echo
echo "Changes since the previous local release (last 25 commits):" >> "$dist/RELEASE_NOTES.md"
echo >> "$dist/RELEASE_NOTES.md"
git log --oneline -25 >> "$dist/RELEASE_NOTES.md" 2>/dev/null || true

echo
echo "release artifacts ready in $dist/"
ls -lh "$dist"
echo
echo "no remote on this repository: nothing was pushed or tagged."
echo "to publish later: commit, then  git tag -a v${version} -m \"Gate One ${version}\""
