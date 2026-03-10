# Releasing Stave

## Quick Release

```bash
make release V=0.0.3
```

This single command:

1. Updates `VERSION` file to the new version.
2. Regenerates `README.md` from `README.md.tmpl` (updates version, control counts).
3. Runs `make test` (unit tests).
4. Runs `make e2e` (end-to-end golden file tests).
5. Verifies CLI docs are up to date (`make docs-check`).
6. Verifies README matches template output (`make readme-check`).
7. Validates GoReleaser configuration (`goreleaser check`).
8. Commits the version bump.
9. Creates the git tag `v0.0.3`.

After it completes, push to trigger the release workflow:

```bash
git push origin main
git push git@github.com-sufield:sufield/stave.git v0.0.3
```

The push uses the `github.com-sufield` SSH host alias (configured in `~/.ssh/config`) to authenticate as the `sufield` account.

## What Gets Validated

| Check | When | What it catches |
|-------|------|-----------------|
| `make test` | Before commit | Broken code |
| `make e2e` | Before commit | Golden file regressions |
| `make docs-check` | Before commit + CI | CLI reference docs out of sync |
| `make readme-check` | Before commit + CI | README control counts or version stale |
| `goreleaser check` | Before commit | Invalid release config |
| `VERSION` ↔ tag match | CI release workflow | Version file forgotten |

Golden file comparisons (`scripts/e2e.sh`, `cmd/apply/verify/determinism_test.go`, `cmd/apply/profile_e2e_test.go`) strip `run.tool_version` before comparing, so version bumps do not require regenerating golden files.

## Generated Artifacts

Several files are generated from templates or live data. CI enforces they stay fresh; `make release` regenerates them automatically.

| Artifact | Source of truth | Generate | Verify |
|----------|----------------|----------|--------|
| `README.md` | `README.md.tmpl` + `VERSION` + `controls/s3/` | `make readme` | `make readme-check` |
| CLI reference docs | `stave --help` output | `make -C ../publisher docs-gen` | `make docs-check` |

### README template

`README.md` is generated from `README.md.tmpl` by `internal/tools/genreadme/` (a build-time tool, not part of the shipped binary). The template uses these placeholders:

| Placeholder | Value source |
|-------------|-------------|
| `{{.Version}}` | `VERSION` file |
| `{{.TotalControls}}` | Count of `*.yaml` files in `controls/s3/*/` |
| `{{.CategoryCount}}` | Count of subdirectories in `controls/s3/` |
| `{{ctrl "name"}}` | Count of `*.yaml` files in `controls/s3/<name>/` |

**When to regenerate:**

- Adding or removing a control YAML file → `make readme`
- Bumping the version → handled automatically by `make release`
- Changing prose → edit `README.md.tmpl`, then `make readme`

Never edit `README.md` directly — edits will be overwritten by the next `make readme`.

### Version propagation

The Go version is pinned once in `go.mod` (`toolchain` directive) and read everywhere else:

```
go.mod (toolchain go1.26.1)
  ├── CI workflows:    go-version-file: 'go.mod'
  ├── Dockerfile:      ARG GO_VERSION  ← Makefile reads from go.mod
  └── versions.md:     rationale only
```

To upgrade Go: update `go.mod` (`go 1.X` + `toolchain go1.X.Y`). CI, Docker, and Makefile read from it automatically.

## What the Release Workflow Does

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

The `make reproduce-release` target builds all five targets with deterministic flags and prints checksums for comparison with the release `SHA256SUMS`.

## Docker Images

Released images are available at:

```bash
docker pull ghcr.io/sufield/stave:v0.1.0
docker pull ghcr.io/sufield/stave:latest
```

The images use a `scratch` base (static binary, zero CVE surface).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| CI fails: "Tag version does not match VERSION file" | Forgot to update `VERSION` before tagging | Use `make release V=x.y.z` which handles this automatically |
| `brew install` fails with checksum mismatch | Retagged an existing version | Release a new version number instead of retagging |
| Golden file tests fail after version bump | Test comparison includes `tool_version` | Already fixed — comparisons strip this field |
