#!/usr/bin/env bash
# Build the signed Gate One release artefacts from this source repository.
#
#   ./release.sh --dry-run
#   VERSION=1.0.0 ./release.sh
#   GATE_ONE_PRODUCT=../gate-one-product ./release.sh
#
# Binaries are attached to a tagged release; they are never committed.
# The source tag is vX.Y.Z. When the product repository is present, its
# tag is either vX.Y.Z or vX.Y.Z-docs.N for a documentation-only release.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

DRY_RUN=0
ALLOW_UNTAGGED=0
ALLOW_UNSIGNED=0
VERSION_IN=""

while [ $# -gt 0 ]; do
	case "$1" in
		--dry-run) DRY_RUN=1 ;;
		--allow-untagged) ALLOW_UNTAGGED=1 ;;
		--allow-unsigned) ALLOW_UNSIGNED=1 ;;
		--version)
			shift
			[ $# -gt 0 ] || { echo "--version needs a value" >&2; exit 2; }
			VERSION_IN="$1"
			;;
		-h|--help)
			sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
			exit 0
			;;
		*)
			echo "release.sh: unknown argument $1" >&2
			exit 2
			;;
	esac
	shift
done

SRC="$PWD"
[ -f "$SRC/go.mod" ] && [ -d "$SRC/cmd/gate-one" ] || {
	echo "release.sh: run from the Gate One source root" >&2
	exit 1
}

# Managed-side code (ingestion, invoicing, reconciliation) lives in a
# private repository. It must never be in this tree, hence never in a
# public archive or the SBOM.
for private_path in services/billing-ingest deploy/local/billing; do
	if [ -e "$SRC/$private_path" ]; then
		echo "release.sh: $private_path is managed-side and must not be" >&2
		echo "  in the public tree; move it to the private billing repository" >&2
		exit 1
	fi
done

assert_public_archive() {
	local archive="$1"
	if tar -tzf "$archive" | grep -Eq '(^|/)(billing-ingest|billing)/|/lago\.js$|/reconcile\.js$'; then
		echo "release.sh: managed-side code found in $archive" >&2
		exit 1
	fi
}
PRODUCT="${GATE_ONE_PRODUCT:-../gate-one-product}"
if [ -d "$PRODUCT" ]; then
	PRODUCT="$(cd "$PRODUCT" && pwd)"
else
	PRODUCT=""
fi

VERSION="${VERSION_IN:-$(cat "$SRC/VERSION" 2>/dev/null || echo 0.1.0)}"
VERSION="${VERSION#v}"
COMMIT="$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo unknown)"
SOURCE_COMMIT="$(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo unknown)"
PRODUCT_COMMIT=""
if [ -n "$PRODUCT" ]; then
	PRODUCT_COMMIT="$(git -C "$PRODUCT" rev-parse HEAD 2>/dev/null || echo unknown)"
fi
DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DIST="$PWD/dist"
TARGETS=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64)

source_tag="$(git -C "$SRC" describe --tags --exact-match 2>/dev/null || true)"
product_tag=""
if [ -n "$PRODUCT" ]; then
	product_tag="$(git -C "$PRODUCT" describe --tags --exact-match 2>/dev/null || true)"
fi
docs_index=""
release_label="$VERSION"

validate_product_tag() {
	[ -n "$product_tag" ] || return 1
	case "$product_tag" in
		"v$VERSION")
			return 0
			;;
		"v$VERSION-docs."*)
			local n="${product_tag##*-docs.}"
			case "$n" in
				''|*[!0-9]*)
					return 2
					;;
			esac
			[ "$n" -ge 1 ] || return 2
			docs_index="$n"
			release_label="${VERSION}-docs.${n}"
			return 0
			;;
	esac
	return 2
}

product_tag_status=0
validate_product_tag || product_tag_status=$?
if [ -n "$product_tag" ] && [ "$product_tag_status" -ne 0 ]; then
	echo "release.sh: product tag $product_tag is invalid" >&2
	echo "  expected v$VERSION or v$VERSION-docs.N" >&2
	exit 1
fi
if [ "$DRY_RUN" = "0" ] && [ "$ALLOW_UNTAGGED" != "1" ] && \
	[ -n "$(git status --porcelain 2>/dev/null)" ]; then
	echo "release.sh: source working tree is dirty; commit first" >&2
	exit 1
fi
if [ -n "$PRODUCT" ] && [ "$DRY_RUN" = "0" ] && \
	[ -z "$product_tag" ] && [ "$ALLOW_UNTAGGED" != "1" ]; then
	echo "release.sh: product HEAD is not tagged" >&2
	echo "  expected v$VERSION or v$VERSION-docs.N" >&2
	echo "  use --allow-untagged for a local build" >&2
	exit 1
fi
if [ -n "$PRODUCT" ] && [ "$DRY_RUN" = "0" ] && \
	[ "$ALLOW_UNTAGGED" != "1" ] && \
	[ -n "$(git -C "$PRODUCT" status --porcelain 2>/dev/null)" ]; then
	echo "release.sh: product working tree is dirty; commit first" >&2
	exit 1
fi
if [ -n "$source_tag" ] && [ "$source_tag" != "v$VERSION" ]; then
	echo "release.sh: source tag $source_tag != v$VERSION" >&2
	[ "$ALLOW_UNTAGGED" = "1" ] || {
		echo "  use --allow-untagged for a local build" >&2
		exit 1
	}
elif [ -z "$source_tag" ] && [ "$DRY_RUN" = "0" ] && \
	[ "$ALLOW_UNTAGGED" != "1" ]; then
	echo "release.sh: source HEAD is not tagged" >&2
	echo "  expected v$VERSION" >&2
	echo "  use --allow-untagged for a local build" >&2
	exit 1
fi

have() { command -v "$1" >/dev/null 2>&1; }
go_bin="$(command -v go || true)"
syft_bin="$(command -v syft || true)"
cosign_bin="$(command -v cosign || true)"
minisign_bin="$(command -v minisign || true)"

if [ -z "$go_bin" ]; then
	echo "release.sh: go is required" >&2
	exit 1
fi
if [ "$DRY_RUN" = "1" ]; then
	echo "release.sh: dry run"
	echo "  source:  $SRC"
	echo "  product: ${PRODUCT:-not found (site/feature examples omitted)}"
	echo "  version: $VERSION (commit $COMMIT)"
	echo "  source tag:  ${source_tag:-MISSING}"
	echo "  product tag: ${product_tag:-MISSING}"
	echo "  release:     $release_label"
	echo "  product commit: ${PRODUCT_COMMIT:-none}"
	echo "  targets: ${TARGETS[*]}"
	echo "  output:  $DIST"
	echo "  go:      $go_bin"
	echo "  syft:    ${syft_bin:-MISSING (required for a real release)}"
	echo "  cosign:  ${cosign_bin:-MISSING}"
	echo "  minisign:${minisign_bin:-MISSING}"
	echo "  signing: COSIGN_KEY or MINISIGN_SECRET_KEY (required unless --allow-unsigned)"
	if [ -n "$PRODUCT" ] && [ -x "$PRODUCT/scripts/validate-examples" ]; then
		( cd "$PRODUCT" && ./scripts/validate-examples >/dev/null )
		echo "  examples: schema validation OK"
	else
		echo "  examples: skipped (product repository not available)"
	fi
	exit 0
fi

[ -n "$syft_bin" ] || {
	echo "release.sh: syft is required (SBOM)" >&2
	echo "  https://github.com/anchore/syft" >&2
	exit 1
}
if [ -z "${COSIGN_KEY:-}" ] && [ -z "${MINISIGN_SECRET_KEY:-}" ]; then
	echo "release.sh: set COSIGN_KEY or MINISIGN_SECRET_KEY" >&2
	[ "$ALLOW_UNSIGNED" = "1" ] || exit 1
fi

if [ -n "$PRODUCT" ] && [ -x "$PRODUCT/scripts/validate-examples" ]; then
	( cd "$PRODUCT" && ./scripts/validate-examples >/dev/null )
fi

rm -rf "$DIST"
mkdir -p "$DIST"

for target in "${TARGETS[@]}"; do
	os="${target%/*}"
	arch="${target#*/}"
	bin="gate-one"
	ext=".tar.gz"
	[ "$os" = "windows" ] && { bin="gate-one.exe"; ext=".zip"; }

	stage="$DIST/stage/gate-one_${VERSION}_${os}_${arch}"
	mkdir -p "$stage/schemas" "$stage/examples"

	echo "building ${os}/${arch}…"
	(
		cd "$SRC"
		CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" "$go_bin" build \
			-trimpath \
			-ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
			-o "$stage/$bin" ./cmd/gate-one
	)

	if [ -n "$PRODUCT" ] && [ -d "$PRODUCT/schemas" ]; then
		cp "$PRODUCT"/schemas/*.json "$stage/schemas/"
	else
		cp "$SRC"/testdata/api-routes.schema.json \
			"$SRC"/testdata/inject-bundle.schema.json \
			"$SRC"/testdata/usage-event.schema.json "$stage/schemas/"
	fi
	if [ -n "$PRODUCT" ] && [ -d "$PRODUCT/examples" ]; then
		cp -R "$PRODUCT"/examples/. "$stage/examples/"
	else
		cp -R "$SRC"/examples/. "$stage/examples/"
	fi
	cp "$SRC"/LICENSE "$SRC"/LICENSE.fr.md "$SRC"/PLUGIN-LICENSING.md \
		"$SRC"/README.md "$SRC"/VERSION "$stage/" 2>/dev/null || true

	archive="$DIST/gate-one_${VERSION}_${os}_${arch}${ext}"
	if [ "$os" = "windows" ]; then
		( cd "$stage" && zip -qr "$archive" . )
	else
		tar -czf "$archive" -C "$stage" .
	fi
	"$syft_bin" "dir:$stage" \
		--source-name "gate-one" --source-version "$VERSION" \
		-o "spdx-json=$DIST/gate-one_${VERSION}_${os}_${arch}.spdx.json" >/dev/null
	rm -rf "$stage"

	# --- cladone-auth (embedded IAM) -------------------------------
	iam_bin="cladone-auth"
	[ "$os" = "windows" ] && iam_bin="cladone-auth.exe"

	iam_stage="$DIST/stage/cladone-auth_${VERSION}_${os}_${arch}"
	mkdir -p "$iam_stage/schemas" "$iam_stage/examples"

	echo "building cladone-auth ${os}/${arch}…"
	(
		cd "$SRC"
		CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" "$go_bin" build \
			-trimpath \
			-ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
			-o "$iam_stage/$iam_bin" ./cmd/cladone-auth
	)

	if [ -n "$PRODUCT" ] && [ -f "$PRODUCT/schemas/embedded-iam.schema.json" ]; then
		cp "$PRODUCT"/schemas/embedded-iam.schema.json "$iam_stage/schemas/"
	fi
	if [ -n "$PRODUCT" ] && [ -f "$PRODUCT/examples/embedded-iam/embedded-iam.json" ]; then
		cp "$PRODUCT"/examples/embedded-iam/embedded-iam.json "$iam_stage/examples/"
	elif [ -f "$SRC"/testdata/auth/embedded-iam.example.json ]; then
		cp "$SRC"/testdata/auth/embedded-iam.example.json "$iam_stage/examples/"
	fi
	cp "$SRC"/LICENSE "$SRC"/LICENSE.fr.md "$SRC"/README.md "$SRC"/VERSION \
		"$iam_stage/" 2>/dev/null || true

	iam_archive="$DIST/cladone-auth_${VERSION}_${os}_${arch}${ext}"
	if [ "$os" = "windows" ]; then
		( cd "$iam_stage" && zip -qr "$iam_archive" . )
	else
		tar -czf "$iam_archive" -C "$iam_stage" .
	fi
	"$syft_bin" "dir:$iam_stage" \
		--source-name "cladone-auth" --source-version "$VERSION" \
		-o "spdx-json=$DIST/cladone-auth_${VERSION}_${os}_${arch}.spdx.json" >/dev/null
	rm -rf "$iam_stage"

	# --- demo IdP (fake Google, demos only) -------------------------
	# Local and VPS demos need an OIDC issuer that runs offline. It is
	# explicitly a demo/test tool: never a production identity provider.
	demo_bin="demo-idp"
	[ "$os" = "windows" ] && demo_bin="demo-idp.exe"

	demo_stage="$DIST/stage/gate-one-demo-idp_${VERSION}_${os}_${arch}"
	mkdir -p "$demo_stage"

	echo "building demo-idp ${os}/${arch}…"
	(
		cd "$SRC"
		CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" "$go_bin" build \
			-trimpath \
			-ldflags "-s -w" \
			-o "$demo_stage/$demo_bin" ./cmd/fake-google
	)
	if [ -n "$PRODUCT" ] && [ -d "$PRODUCT/examples" ]; then
		mkdir -p "$demo_stage/deploy"
		cp -R "$SRC"/deploy/local "$demo_stage/deploy/" 2>/dev/null || true
		# Managed-side harness: never published.
		rm -rf "$demo_stage/deploy/local/billing"
	fi
	cp "$SRC"/LICENSE "$SRC"/README.md "$SRC"/VERSION "$demo_stage/" 2>/dev/null || true

	demo_archive="$DIST/gate-one-demo-idp_${VERSION}_${os}_${arch}${ext}"
	if [ "$os" = "windows" ]; then
		( cd "$demo_stage" && zip -qr "$demo_archive" . )
	else
		tar -czf "$demo_archive" -C "$demo_stage" .
	fi
	if [ "$ext" = ".zip" ]; then
		demo_listing="$(unzip -Z1 "$demo_archive" 2>/dev/null || true)"
	else
		demo_listing="$(tar -tzf "$demo_archive" 2>/dev/null || true)"
	fi
	if printf '%s\n' "$demo_listing" | grep -Eq 'deploy/local/billing(/|$)'; then
		echo "release.sh: managed-side demo found in $demo_archive" >&2
		exit 1
	fi
	"$syft_bin" "dir:$demo_stage" \
		--source-name "gate-one-demo-idp" --source-version "$VERSION" \
		-o "spdx-json=$DIST/gate-one-demo-idp_${VERSION}_${os}_${arch}.spdx.json" >/dev/null
	rm -rf "$demo_stage"
done

rmdir "$DIST/stage" 2>/dev/null || true

# --- companion services (source) ----------------------------------
# Only the user-hosted services ship as source: the token broker and the
# auth-bridge. The managed billing ingestion service is private and is
# never part of a public archive.
PUBLIC_SERVICES=(token-broker auth-bridge)
services_stage="$DIST/stage/services_public"
mkdir -p "$services_stage"
for svc in "${PUBLIC_SERVICES[@]}"; do
	cp -R "$SRC/services/$svc" "$services_stage/" || {
		echo "release.sh: services/$svc is missing" >&2
		exit 1
	}
	rm -rf "$services_stage/$svc/node_modules"
done
services_archive="$DIST/services_${VERSION}_src.tar.gz"
tar -czf "$services_archive" -C "$services_stage" .
assert_public_archive "$services_archive"
"$syft_bin" "dir:$services_stage" \
	--source-name "gate-one-services" --source-version "$VERSION" \
	-o "spdx-json=$DIST/services_${VERSION}_src.spdx.json" >/dev/null
rm -rf "$services_stage"

site_line=""
if [ -n "$PRODUCT" ] && [ -x "$PRODUCT/scripts/build-site" ]; then
	# The product site also publishes the schemas/examples it mounts.
	# Build it with the URL under which the release folder is published so
	# both the site archive and GitHub Pages use the same absolute links.
	site_base_url="${SITE_BASE_URL:-https://clad-one.github.io/gate-one-doc/v${release_label}/}"
	( cd "$PRODUCT" && "$PRODUCT/scripts/build-site" --baseURL "$site_base_url" >/dev/null )
	# The published site must not describe the managed-side service.
	if grep -rIqE 'billing-ingest|/v1/reconcile|fake-lago|PRIVATE — do not distribute' "$PRODUCT/public"; then
		echo "release.sh: managed-side content found in the published site" >&2
		exit 1
	fi
	tar -czf "$DIST/gate-one_${release_label}_site.tar.gz" \
		-C "$PRODUCT/public" .
	site_line="- \`gate-one_${release_label}_site.tar.gz\` (static documentation, published at $site_base_url)"
fi

if [ -f "$SRC/release/cosign.pub" ]; then
	cp "$SRC/release/cosign.pub" "$DIST/cosign.pub"
fi

cat > "$DIST/RELEASE_MANIFEST.json" <<JSON
{
  "version": "${VERSION}",
  "releaseLabel": "${release_label}",
  "sourceTag": "${source_tag}",
  "sourceCommit": "${SOURCE_COMMIT}",
  "productTag": "${product_tag}",
  "productCommit": "${PRODUCT_COMMIT}",
  "docsIndex": ${docs_index:-null},
  "builtAt": "${DATE}",
  "binaries": ["gate-one", "cladone-auth", "demo-idp"],
  "services": ["token-broker", "auth-bridge"],
  "targets": ["linux/amd64", "linux/arm64", "darwin/amd64", "darwin/arm64", "windows/amd64"]
}
JSON

cat > "$DIST/RELEASE_NOTES.md" <<NOTES
# Gate One ${release_label} — ${DATE}

Source version: \`${VERSION}\` (commit \`${COMMIT}\`)
Source tag: \`${source_tag:-none}\`
Product tag: \`${product_tag:-none}\`

Artifacts:

- \`gate-one_${VERSION}_<os>_<arch>.tar.gz\` (or \`.zip\` on Windows)
- \`cladone-auth_${VERSION}_<os>_<arch>.tar.gz\` (or \`.zip\` on Windows)
- \`gate-one-demo-idp_${VERSION}_<os>_<arch>.tar.gz\` (fake OIDC IdP for the local/VPS demos; never production)
- \`services_${VERSION}_src.tar.gz\` (token-broker and auth-bridge sources)
${site_line}
- \`RELEASE_MANIFEST.json\` (source/product tags and commits)
- \`*.spdx.json\` (SBOM, syft)
- \`SHA256SUMS\` and its signature (\`SHA256SUMS.bundle\` for cosign)
- \`cosign.pub\` (the release verification key)
- \`schemas/\` and \`examples/\` in every binary archive

Verify the checksum signature:

\`\`\`bash
cosign verify-blob --key cosign.pub --bundle SHA256SUMS.bundle SHA256SUMS
sha256sum -c SHA256SUMS
\`\`\`

Supported: Linux amd64/arm64, macOS amd64/arm64, Windows amd64
(CGO disabled). Binaries are not committed to Git: attach this
directory to the source tag \`v${VERSION}\` under release label
\`${release_label}\`.

Source repository: https://github.com/clad-one/gate-one
Documentation: https://github.com/clad-one/gate-one-doc
NOTES

(
	cd "$DIST"
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum ./*.tar.gz ./*.zip ./*.spdx.json ./RELEASE_MANIFEST.json ./RELEASE_NOTES.md ./cosign.pub > SHA256SUMS 2>/dev/null || \
			sha256sum ./*.tar.gz ./*.spdx.json ./RELEASE_MANIFEST.json ./RELEASE_NOTES.md ./cosign.pub > SHA256SUMS
	else
		shasum -a 256 ./*.tar.gz ./*.zip ./*.spdx.json ./RELEASE_MANIFEST.json ./RELEASE_NOTES.md ./cosign.pub > SHA256SUMS 2>/dev/null || \
			shasum -a 256 ./*.tar.gz ./*.spdx.json ./RELEASE_MANIFEST.json ./RELEASE_NOTES.md ./cosign.pub > SHA256SUMS
	fi
)

if [ -n "${COSIGN_KEY:-}" ]; then
	# Offline signing: release/signing-config.json carries no Rekor
	# transparency-log or TSA service, so the signature is produced
	# without any external dependency. The pinned public key is the
	# trust anchor; verification is key-based (see release/README.md).
	signing_config="$SRC/release/signing-config.json"
	"$cosign_bin" sign-blob --yes --key "$COSIGN_KEY" \
		--signing-config "$signing_config" \
		--bundle "$DIST/SHA256SUMS.bundle" \
		"$DIST/SHA256SUMS"
	pub="${COSIGN_PUB:-${COSIGN_KEY%.key}.pub}"
	if [ -f "$pub" ]; then
		"$cosign_bin" verify-blob --key "$pub" --insecure-ignore-tlog \
			--bundle "$DIST/SHA256SUMS.bundle" "$DIST/SHA256SUMS"
	fi
	chmod 644 "$DIST/SHA256SUMS.bundle"
elif [ -n "${MINISIGN_SECRET_KEY:-}" ]; then
	"$minisign_bin" -S -s "$MINISIGN_SECRET_KEY" -m "$DIST/SHA256SUMS" \
		-x "$DIST/SHA256SUMS.minisig"
fi


echo "release.sh: wrote $DIST"
