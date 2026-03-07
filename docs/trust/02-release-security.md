---
title: "Release Security"
sidebar_label: "Release Security"
sidebar_position: 3
description: "How Stave releases are built, signed, and verified."
---

# Release Integrity & Verification

This document explains how to verify Stave release artifacts:

- Checksums  
- Cosign signatures  
- SBOM  
- Build provenance  

Checksum and signature verification can be performed offline after downloading artifacts. Provenance verification requires GitHub connectivity.

---

## How Releases Are Built

Every tagged release (`v*`) triggers an automated GitHub Actions workflow powered by [GoReleaser](https://goreleaser.com/) that:

1. **Validates the VERSION file** matches the git tag before building.
2. **Cross-compiles** for five targets: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`.
3. **Uses deterministic build flags** to ensure reproducibility:
   - `CGO_ENABLED=0` — pure Go, no C dependencies
   - `-trimpath` — removes local filesystem paths from the binary
   - `-buildid=` — removes the build ID for reproducibility
   - `-ldflags "-s -w"` — strips debug symbols and DWARF information
4. **Injects build metadata** at build time via ldflags (version, commit, date, built-by).
5. **Builds Docker images** for linux/amd64 and linux/arm64, published as multi-arch manifests to `ghcr.io/sufield/stave`.
6. **Updates the Homebrew formula** in `sufield/homebrew-tap`.
7. **Builds Linux packages** (deb, rpm, apk).

No matrix build is needed — Go cross-compiles natively from a single runner.

---

## Release Artifacts

Each GitHub Release includes:

| Artifact | Description |
|----------|-------------|
| `stave_<version>_<os>_<arch>.tar.gz` | Compressed binary for Linux and macOS targets |
| `stave_<version>_windows_amd64.zip` | Compressed binary for Windows |
| `stave_<version>_<os>_<arch>.deb` / `.rpm` / `.apk` | Linux packages (Debian, RPM, Alpine) |
| `SHA256SUMS` | SHA-256 checksums for all archives and packages |
| `SHA256SUMS.sigstore.json` | Sigstore cosign bundle signing the checksums |
| `sbom.spdx.json` | SPDX SBOM for the Stave source and its dependencies |
| `sbom.spdx.json.sigstore.json` | Sigstore cosign bundle signing the SBOM independently |
| Build provenance attestation | GitHub-native SLSA provenance (attached to each release artifact) |

### Installation Methods

| Method | Command |
|--------|---------|
| Homebrew | `brew tap sufield/tap && brew install stave` |
| Docker | `docker pull ghcr.io/sufield/stave:v<version>` |
| Debian/Ubuntu | `sudo dpkg -i stave_<version>_linux_amd64.deb` |
| RPM (Fedora/RHEL) | `sudo rpm -i stave_<version>_linux_amd64.rpm` |
| Alpine | `sudo apk add --allow-untrusted stave_<version>_linux_amd64.apk` |
| Binary | Download archive from GitHub Releases |

---

## Connectivity Requirements

| Step | Offline? | Notes |
|------|----------|-------|
| Download artifacts | No | Requires GitHub connectivity |
| Verify checksums (`sha256sum -c`) | **Yes** | Local computation only |
| Verify Cosign signature (`cosign verify-blob --bundle`) | **Yes** | Bundle contains certificate chain; no network needed |
| Verify SBOM signature (`cosign verify-blob --bundle`) | **Yes** | Bundle contains certificate chain; no network needed |
| Inspect SBOM (`jq`, `syft validate`) | **Yes** | Local file parsing |
| Verify build provenance (`gh attestation verify`) | No | Queries GitHub attestation API |

After downloading, checksum and Cosign verification work fully offline.

---

## Tool Installation

### Cosign

```bash
# macOS
brew install cosign

# Linux (official binary)
COSIGN_VERSION=v2.4.3
curl -fsSLO "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64"
chmod +x cosign-linux-amd64
sudo mv cosign-linux-amd64 /usr/local/bin/cosign

# Container-based (no local install)
docker run --rm -v "$(pwd):/work" -w /work ghcr.io/sigstore/cosign:v2.4.3 \
  verify-blob --bundle SHA256SUMS.sigstore.json SHA256SUMS
```

### GitHub CLI

```bash
# macOS
brew install gh

# Linux (Debian/Ubuntu)
sudo apt install gh

# Linux (Fedora/RHEL)
sudo dnf install gh

# Linux (binary)
GH_VERSION=2.67.0
curl -fsSLO "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_amd64.tar.gz"
tar xzf gh_${GH_VERSION}_linux_amd64.tar.gz
sudo mv gh_${GH_VERSION}_linux_amd64/bin/gh /usr/local/bin/
```

### Syft (optional, for SBOM validation)

```bash
# macOS
brew install syft

# Linux
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

---

## Verification

### 1. Download artifacts

Download the archive and verification files from the GitHub Release page:

- `stave_<version>_<os>_<arch>.tar.gz`
- `SHA256SUMS`
- `SHA256SUMS.sigstore.json`
- `sbom.spdx.json`
- `sbom.spdx.json.sigstore.json`

Or via CLI:

```bash
gh release download vX.Y.Z --repo sufield/stave --pattern "*"
```

---

### 2. Verify checksums (offline)

```bash
sha256sum -c SHA256SUMS
```

Expected output:

```
stave_<version>_<os>_<arch>.tar.gz: OK
```

The SBOM is also included in `SHA256SUMS`, so its integrity is verified here too.

---

### 3. Verify Cosign signature (offline)

Stave releases are signed using Sigstore keyless signing via GitHub Actions OIDC.
The `SHA256SUMS` file is signed (not each tarball individually), so verifying the checksums file covers all archives and the SBOM.

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/sufield/stave/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
```

Replace `vX.Y.Z` with the actual release tag.

**What the identity constraints verify:**
- `--certificate-identity` ensures the signature came from the Stave release workflow at the expected tag
- `--certificate-oidc-issuer` ensures the signing identity was issued by GitHub Actions

If verification succeeds, Cosign prints signature details and exits 0.

---

### 4. Verify SBOM signature (offline)

The SBOM is independently signed with Cosign keyless signing, in addition to being covered by the checksums signature.

```bash
cosign verify-blob \
  --bundle sbom.spdx.json.sigstore.json \
  --certificate-identity "https://github.com/sufield/stave/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  sbom.spdx.json
```

Replace `vX.Y.Z` with the actual release tag.

---

### 5. Inspect SBOM (offline)

The SBOM lists all Stave source dependencies used in the build.

```bash
jq . sbom.spdx.json | less
```

Validate SBOM structure:

```bash
syft validate sbom.spdx.json
```

The release workflow also runs `syft validate` before uploading, so released SBOMs are guaranteed to be well-formed.

---

### 6. Verify build provenance (online)

Each release archive has a GitHub-native build provenance attestation.
This step **requires internet connectivity** to query the GitHub attestation API.

```bash
gh attestation verify stave_<version>_<os>_<arch>.tar.gz \
  --repo sufield/stave
```

This proves the binary was built by the official GitHub Actions release workflow in this repository.

---

### 7. Full verification example

```bash
VERSION=vX.Y.Z
FILE=stave_${VERSION}_linux_amd64.tar.gz

# Download
gh release download $VERSION --repo sufield/stave --pattern "*"

# Offline: checksum
sha256sum -c SHA256SUMS

# Offline: Cosign signature on checksums
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/sufield/stave/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS

# Offline: Cosign signature on SBOM
cosign verify-blob \
  --bundle sbom.spdx.json.sigstore.json \
  --certificate-identity "https://github.com/sufield/stave/.github/workflows/release.yml@refs/tags/${VERSION}" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  sbom.spdx.json

# Online: provenance
gh attestation verify $FILE --repo sufield/stave
```

If all commands succeed, the release is authentic and untampered.

---

## If Verification Fails

If any verification step fails:

1. **Do not run the binary.** Delete the downloaded artifacts.
2. **Re-download** from the official [GitHub Releases page](https://github.com/sufield/stave/releases) and try again. Corrupt downloads are the most common cause of checksum failures.
3. **Verify the release tag** matches the version you expect. Check that the release exists at `https://github.com/sufield/stave/releases/tag/vX.Y.Z`.
4. **Check tool versions.** Ensure `cosign` and `gh` are up to date. Older versions may not support current Sigstore bundle formats.
5. **Open a GitHub issue** at [github.com/sufield/stave/issues](https://github.com/sufield/stave/issues) if the failure persists. Include:
   - Which verification step failed
   - The exact error message
   - Your OS and architecture
   - The release version you downloaded
   - Output of `cosign version` and `gh version`

---

## Reproducible Builds

Stave uses deterministic build flags so that anyone with the same Go version can reproduce the release binaries and compare checksums.

### Requirements

- **Go version**: Must match the release workflow exactly (see `go-version` in `.github/workflows/release.yml`)
- **Build flags**: `CGO_ENABLED=0 -trimpath -buildid= -ldflags "-s -w"`
- **Version injection**: `-X github.com/sufield/stave/internal/version.Version=v<VERSION>`

### Reproduce locally

```bash
# Clone the release tag
git clone --branch vX.Y.Z https://github.com/sufield/stave.git
cd stave

# Build all targets with the same flags as CI
make reproduce-release

# Compare binary checksums with the release
# Download release binaries and compute their checksums:
gh release download vX.Y.Z --repo sufield/stave --pattern "*.tar.gz" --pattern "*.zip"
for f in *.tar.gz; do tar xzf "$f"; done
for f in *.zip; do unzip -o "$f"; done
sha256sum stave_*
```

### Limitations

- **Archive metadata differs**: `tar.gz` and `.zip` archives include timestamps and filesystem metadata that vary between builds. Compare the raw binary checksums, not the archive checksums.
- **Go version must match exactly**: Different Go patch versions may produce different binaries even with the same flags.
- **OS does not matter**: Because `CGO_ENABLED=0` is set, cross-compilation from any OS produces identical binaries for a given target.

---

## SBOM Trust Chain

The SBOM (`sbom.spdx.json`) has two independent verification paths:

1. **Checksums path**: `SHA256SUMS` contains the checksum for `sbom.spdx.json`, and `SHA256SUMS` is signed by Cosign (`SHA256SUMS.sigstore.json`). Verifying the checksums signature covers the SBOM.
2. **Direct signature**: `sbom.spdx.json.sigstore.json` is a Cosign bundle signing the SBOM directly.

The release workflow also validates SBOM structure with `syft validate` before uploading, ensuring released SBOMs are well-formed SPDX.

To verify SBOM integrity via both paths:

```bash
# Path 1: Via signed checksums
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/sufield/stave/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing 2>/dev/null | grep sbom

# Path 2: Direct SBOM signature
cosign verify-blob \
  --bundle sbom.spdx.json.sigstore.json \
  --certificate-identity "https://github.com/sufield/stave/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  sbom.spdx.json
```

Expected output for path 1: `sbom.spdx.json: OK`

---

## Trust Model

Verification layers:

* **Checksum** — file integrity
* **Cosign** — signed by Stave CI
* **SBOM** — transparent dependencies
* **Provenance** — built from this repo in GitHub Actions

All must pass for a trusted release.

## Threat Model

Stave release verification defends against the following supply-chain risks:

| Threat | Remediation |
|--------|------------|
| **Artifact tampering in transit** (mirror compromise, MITM, CDN attack) | SHA-256 checksums detect any modification |
| **Malicious replacement of release files** | Cosign signature ensures artifacts originate from the Stave release workflow identity |
| **Compromised or untrusted build host** | GitHub provenance attestation proves binaries were built by the official CI workflow from this repository |
| **Hidden or vulnerable dependencies** | SBOM provides full dependency transparency for audit and scanning |
| **Repository compromise after release** | Signed checksums + provenance bind artifacts to the exact build event and commit |
| **Insider or unauthorized release upload** | Sigstore OIDC identity ties signing to GitHub Actions permissions and workflow context |

A release should be trusted only if:

- Checksum verification passes  
- Cosign signature verification passes  
- Provenance verification passes  

SBOM inspection is recommended for dependency review and compliance auditing.

---

## Supply Chain Security

| Property                         | How it's achieved                                                                           |
| -------------------------------- | ------------------------------------------------------------------------------------------- |
| **Tamper-evident checksums**     | SHA-256 checksums for all archives                                                          |
| **Signed checksums**             | Sigstore cosign with OIDC-based keyless signing                                             |
| **Build provenance**             | GitHub-native SLSA attestation                                                              |
| **Software Bill of Materials**   | SPDX SBOM generated by Syft, independently signed with Cosign, validated before release     |
| **License compliance**           | Automated `go-licenses` check in CI; forbidden licenses (GPL, AGPL, SSPL, LGPL) fail build  |
| **Dependency monitoring**        | Dependabot for Go modules and GitHub Actions                                                |
| **Vulnerability scanning**       | govulncheck runs on every PR                                                                |
| **No network access at runtime** | Stave makes zero network connections (see [Security and Trust](./01-security-and-trust.md)) |

---

## CI Quality Gates

Every pull request must pass six checks before merging:

1. **Test** — `go test -v -race ./...`
2. **Lint** — `golangci-lint` v2.8.0 with gosec, errcheck, govet, staticcheck
3. **Vulnerability check** — `govulncheck` against the Go vulnerability database
4. **License compliance** — `go-licenses check` with allowlist (Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC). Fails on GPL, AGPL, SSPL, LGPL, or unknown licenses. Run locally: `go-licenses check ./cmd/stave --allowed_licenses=Apache-2.0,MIT,BSD-2-Clause,BSD-3-Clause,ISC`
5. **E2E** — Full end-to-end test suite (`scripts/e2e.sh`)
6. **Release config** — `goreleaser check` validates the release configuration
