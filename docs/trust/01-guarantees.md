---
title: "Security Guarantees"
sidebar_label: "Guarantees"
sidebar_position: 1
description: "Stave's compile-time and runtime security guarantees: offline operation, no credentials, determinism, no code execution, filesystem safety, sanitization, and supply-chain integrity."
---

# Security Guarantees

Stave is designed so that running it cannot make your security posture worse. This page enumerates every guarantee the project makes and how each one is enforced.

## 1. Offline — No Network Access

Stave makes zero network connections at runtime. It does not import `net/http`, `net/rpc`, or `crypto/tls`. It reads local files and writes to stdout/stderr or user-specified output paths.

**How it is enforced:**

- `TestNoBannedImportsInRuntime` — CI test that fails if any banned package appears in the runtime binary's dependency graph.
- `TestNoHTTPSchemaIdentifiers` — ensures all schema `$id` values use `urn:stave:schema:` (not HTTP URLs).
- The `pflag` library transitively imports the `net` package for `net.ParseIP()` (parsing only — no sockets, no connections).

**How to verify independently:**

```bash
# Linux: strace shows zero network syscalls
strace -f -e trace=network ./stave apply \
  --controls ./inv --observations ./obs 2>&1 \
  | grep -E 'socket|connect|sendto|recvfrom'
# Expected: no output

# Any OS: container with no network
docker run --rm --network=none -v "$(pwd):/work" -w /work golang:1.26 \
  ./stave apply --controls ./inv --observations ./obs
```

The `--require-offline` flag is an operational convenience that refuses to run if proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) are set. It is not a security boundary — Stave is architecturally offline regardless.

All JSON output includes `"offline": true` in the `run` metadata, and `stave capabilities` includes `"offline": true` at the top level.

## 2. No Credentials

Stave never requires, reads, or processes cloud credentials.

| What Stave does NOT read | Examples |
|--------------------------|---------|
| Credential environment variables | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE`, `GOOGLE_APPLICATION_CREDENTIALS` |
| Credential files | `~/.aws/credentials`, `~/.aws/config`, service account keys |
| Cloud APIs | AWS, GCP, Azure — no API calls of any kind |

The only environment variable Stave reads is `NO_COLOR` (per [no-color.org](https://no-color.org/)).

Users export configuration snapshots using their own tools (AWS CLI, Terraform) outside of Stave. Stave reads the resulting local files only.

## 3. Determinism

Stave output is deterministic when `--now` is set. The same inputs and flags always produce byte-identical output.

- The evaluator caps `--now` to the last snapshot's `captured_at` timestamp (you cannot evaluate into the future beyond your data).
- Without `--now`, the evaluation timestamp is derived from the last snapshot's `captured_at` — wall-clock fallback only applies when there are zero snapshots.

Use `--now` in CI and golden-file tests for reproducible results.

## 4. No Code Execution

Stave never executes user-supplied code. Controls are data (YAML), not code.

**Banned imports (enforced by CI):**

| Package | Reason |
|---------|--------|
| `os/exec` | No subprocess execution |
| `plugin` | No plugin loading |
| `net/http` | No network I/O |
| `net/rpc` | No network I/O |
| `crypto/tls` | No TLS connections |

**Additional guarantees:**

- No plugins — the `plugin` package is not imported.
- No embedded interpreters, scripting engines, Lua, or WASM runtimes.
- Controls are restricted to a fixed set of 15 predicate operators combined via `any`/`all` logic. No custom functions, no user-defined operators, no hooks.

## 5. File Output Safety

Stave enforces strict filesystem safety properties:

| Property | Behavior | Override |
|----------|----------|---------|
| No file deletion during normal operation | Stave does not delete user files during normal operation | — |
| No overwrite | Write commands refuse to overwrite existing files | `--force` |
| No symlink writes | Write commands refuse to write through symbolic links | `--allow-symlink-output` |
| Path traversal protection | Control registry validates relative paths to prevent `../` traversal | — |
| Bucket name validation | Bucket names validated against S3 naming rules before use in paths | — |
| Path normalization | All CLI paths cleaned with `filepath.Clean` | — |
| Restricted permissions | Directories: `0700`, files: `0600` (owner-only) | — |
| No persistent state | No temp files, config dirs, caches, databases, lock files, or IPC sockets | — |

All writes are user-controlled — output files are only created when explicitly requested via `--out` flags.

**Shared-system guidance:** On multi-user systems, verify your umask is restrictive (`umask 077`) and write outputs into a private directory to prevent other users from reading evaluation results.

## 6. Sanitization

Stave provides two mechanisms for controlling sensitive data in output:

**`--sanitize`** replaces infrastructure identifiers with deterministic SHA-256 tokens:

| Field | Sanitized form |
|-------|--------------|
| `Finding.ResourceID` | `SANITIZED_<8hex>` |
| ARNs in `ResourceID` | `arn:aws:s3:::SANITIZED_<8hex>` (structure preserved) |
| `Finding.Source.File` | Basename only (directory stripped) |
| `Evidence.Misconfigurations[].ActualValue` | `[SANITIZED]` |

What is preserved: control IDs, names, rule IDs, counts, durations, timestamps, schema versions.

**`--path-mode`** controls file paths in error messages:

| Mode | Behavior |
|------|----------|
| `base` (default) | Absolute paths replaced with basenames |
| `full` | Paths shown as-is |

**`ingest --profile mvp1-s3 --scrub`** removes sensitive fields (tags, raw policies, ACL grants) from observations before sharing.

## 7. Supply-Chain Integrity

Every release includes verification artifacts:

| Artifact | Purpose |
|----------|---------|
| `SHA256SUMS` | File integrity checksums |
| `SHA256SUMS.sigstore.json` | Cosign signature proving CI origin |
| `sbom.spdx.json` | Full dependency transparency (SPDX SBOM) |
| `sbom.spdx.json.sigstore.json` | Independent SBOM signature |
| Build provenance attestation | GitHub-native SLSA provenance |

Checksum and Cosign verification work fully offline after downloading artifacts. Provenance verification requires GitHub connectivity.

For step-by-step verification instructions, see [Verify a Release](./verify-release.md).

## 8. Privileges

Stave requires no elevated privileges at any stage:

- **Build:** `make build` runs as the current user. No root or sudo.
- **Install:** `make install` writes to `$GOPATH/bin/`. No system directories modified.
- **Run:** No privileged syscalls, no `CAP_*` capabilities, no setuid/setgid.
- **Docker:** Demo image runs as non-root (UID 10001).

## Summary

| Guarantee | Enforcement |
|-----------|------------|
| Offline | Banned-import CI test, strace verification, `urn:` schema IDs |
| No credentials | No credential env vars or files read; only `NO_COLOR` |
| Determinism | `--now` flag; capped to last snapshot timestamp |
| No code execution | 8 banned imports enforced by CI; closed DSL |
| File safety | No-overwrite, no-symlink, path traversal guards, `0700`/`0600` perms |
| Sanitization | `--sanitize`, `--path-mode`, `--scrub` |
| Supply chain | SHA256, Cosign, SBOM, SLSA provenance |
| No privileges | No root, no capabilities, non-root container |
