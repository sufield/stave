---
title: "Verify a Release"
sidebar_label: "Verify Release"
sidebar_position: 6
description: "Step-by-step guide to verify Stave release integrity using checksums, Cosign, and provenance."
---

# Verify a Release

This is a quick-start guide for verifying a Stave release. For full details on how releases are built, see [Release Security](./02-release-security.md).

## Prerequisites

- **cosign** — for signature verification ([install](https://docs.sigstore.dev/cosign/system_config/installation/))
- **gh** (optional) — for provenance verification and artifact download

## Steps

### 1. Download artifacts

```bash
VERSION=vX.Y.Z
gh release download $VERSION --repo sufield/stave --pattern "*"
```

Or download manually from the [GitHub Releases page](https://github.com/sufield/stave/releases).

You need at minimum:
- `stave_<version>_<os>_<arch>.tar.gz` (the binary)
- `SHA256SUMS`
- `SHA256SUMS.sigstore.json`

Optional but recommended:
- `sbom.spdx.json`
- `sbom.spdx.json.sigstore.json`

### 2. Verify checksums (offline)

```bash
sha256sum -c SHA256SUMS
```

Every listed file should show `OK`.

### 3. Verify Cosign signature (offline)

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/sufield/stave/.github/workflows/release.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
```

Replace `$VERSION` with the actual tag (e.g., `v1.0.0`). Success means the checksums file was signed by the Stave release workflow.

### 4. Verify SBOM signature (offline, optional)

```bash
cosign verify-blob \
  --bundle sbom.spdx.json.sigstore.json \
  --certificate-identity "https://github.com/sufield/stave/.github/workflows/release.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  sbom.spdx.json
```

### 5. Verify build provenance (online, optional)

```bash
gh attestation verify stave_${VERSION}_linux_amd64.tar.gz \
  --repo sufield/stave
```

This proves the binary was built by the official CI workflow. Requires GitHub connectivity.

### 6. Verify Docker image (online, optional)

```bash
docker pull ghcr.io/sufield/stave:$VERSION
docker run --rm ghcr.io/sufield/stave:$VERSION --version
```

The Docker image uses a `scratch` base image containing only the static Stave binary.

## If Verification Fails

1. **Do not run the binary.** Delete the downloaded artifacts.
2. **Re-download** from the official release page — corrupt downloads are the most common cause.
3. **Check tool versions** — ensure `cosign` and `gh` are up to date.
4. **Open an issue** at [github.com/sufield/stave/issues](https://github.com/sufield/stave/issues) with the error message, OS, and release version.

## Connectivity Summary

| Step | Offline? |
|------|----------|
| Verify checksums | Yes |
| Verify Cosign signature | Yes |
| Verify SBOM signature | Yes |
| Verify build provenance | No (requires GitHub API) |

## Container-Based Verification

If you prefer not to install cosign locally:

```bash
docker run --rm -v "$(pwd):/work" -w /work ghcr.io/sigstore/cosign:v2.4.3 \
  verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/sufield/stave/.github/workflows/release.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
```

## Reproduce the Build Locally

Stave uses deterministic build flags so that anyone with the same Go version can reproduce the release binaries and compare checksums.

### Requirements

- **Go version**: Must match the release workflow exactly (see `go-version` in `.github/workflows/release.yml`)
- **Build flags**: `CGO_ENABLED=0 -trimpath -buildid= -ldflags "-s -w"`
- **Version injection**: `-X github.com/sufield/stave/internal/version.String=v<VERSION>`

### Reproduce

```bash
git clone --branch vX.Y.Z https://github.com/sufield/stave.git
cd stave

make reproduce-release

gh release download vX.Y.Z --repo sufield/stave --pattern "*.tar.gz" --pattern "*.zip"
for f in *.tar.gz; do tar xzf "$f"; done
for f in *.zip; do unzip -o "$f"; done
sha256sum stave_*
```

### Limitations

- **Archive metadata differs**: `tar.gz` and `.zip` archives include timestamps and filesystem metadata that vary between builds. Compare the raw binary checksums, not the archive checksums.
- **Go version must match exactly**: Different Go patch versions may produce different binaries even with the same flags.
- **OS does not matter**: Because `CGO_ENABLED=0` is set, cross-compilation from any OS produces identical binaries for a given target.
