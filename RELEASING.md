# Releasing Stave

## Release Flow

1. Update `VERSION` file with the new version (e.g., `0.1.0`).
2. Commit: `git commit -am "Prepare release v0.1.0"`.
3. Tag: `git tag v0.1.0`.
4. Push: `git push origin main v0.1.0`.

The release workflow validates that the tag version matches the `VERSION` file before proceeding.

## What the Workflow Does

1. Validates `VERSION` file matches the git tag.
2. Runs **GoReleaser** which:
   - Cross-compiles for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64.
   - Creates tar.gz archives (zip for Windows).
   - Generates SHA256 checksums and signs them with Cosign.
   - Builds multi-arch Docker images and pushes to `ghcr.io/sufield/stave`.
   - Updates the Homebrew formula in `sufield/homebrew-tap`.
   - Builds deb/rpm/apk packages.
   - Creates the GitHub Release with changelog.
3. Generates SBOM with Syft, signs it with Cosign, uploads to the release.
4. Attests build provenance for archives.

## Pre-release Versions

Tags with pre-release suffixes (e.g., `v0.1.0-rc.1`) are automatically marked as pre-release on GitHub.

## Secrets Required

| Secret | Purpose |
|--------|---------|
| `GITHUB_TOKEN` | Automatic — used for release creation, Docker push to GHCR, Cosign OIDC signing |
| `TAP_GITHUB_TOKEN` | PAT with `repo` scope for pushing to `sufield/homebrew-tap` |

See [Homebrew Tap Setup](docs/homebrew-tap-setup.md) for `TAP_GITHUB_TOKEN` configuration.

## Local Testing

```bash
# Validate GoReleaser config
make release-check

# Build a local snapshot (no publish)
make release-local

# Check outputs
ls dist/stave_v*
```

## Reproducible Builds

The `make reproduce-release` target still works independently of GoReleaser. It builds all five targets with deterministic flags and prints checksums for comparison with the release `SHA256SUMS`.

## Docker Images

Released images are available at:

```bash
docker pull ghcr.io/sufield/stave:v0.1.0
docker pull ghcr.io/sufield/stave:latest
```

The images use a `scratch` base (static binary, zero CVE surface).
