# Security Policy

## Scope

This policy covers the **Stave CLI**.

## Reporting a Vulnerability

Please report security vulnerabilities through [GitHub Security Advisories](https://github.com/sufield/stave/security/advisories/new).

**Do not** open a public issue for security vulnerabilities.

### What to include

- Description of the vulnerability
- Steps to reproduce
- Affected versions (or "all" if unknown)
- Impact assessment

### What to expect

- **Acknowledgment** within 3 business days
- **Initial assessment** within 7 business days
- **Fix or remediation** timeline communicated after assessment

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor | Best effort |
| Older | No |

## Security Design

Stave is designed with a minimal attack surface:

- **No network access** — Stave makes zero network connections. It does not import `net/http`, open sockets, or make DNS lookups. It reads local files and writes to stdout/stderr.
- **No subprocess execution** — The runtime `stave` binary does not import `os/exec` or spawn subprocesses. See [Execution Safety](docs/trust/execution-safety.md) for the full guarantee.
- **No persistent state** — No databases, caches, or config files are created.
- **Read-only inputs** — Observation and control files are never modified.
- **Air-gapped, offline-only, network-isolated** — The Stave runtime binary contains no networking code and operates entirely on local files. It is safe to run in air-gapped, network-isolated, and offline-only environments. No conditional flags or environment variables can enable network access. Build and release processes (CI, signing, SBOM generation) require network access; see [Offline & Air-Gapped Operation](docs/offline-airgapped.md) for the full inventory.
- **No `--strict-offline` flag** — Stave does not provide a `--strict-offline` flag because the binary is **architecturally incapable** of networking. The `net/http`, `crypto/tls`, and `os/exec` packages are not imported (enforced by CI tests). A runtime flag would misleadingly imply that a non-strict mode with network capability exists. Verification is instead provided through `strace` (see below), `docker --network=none`, and the compile-time import guards in `TestNoBannedImportsInRuntime`.
- **`--require-offline` environment guard** — The `--require-offline` flag performs a best-effort runtime self-check that refuses to run if proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) are set. This is an operational convenience for environments that want to assert no proxy misconfiguration, not a security boundary — Stave is architecturally offline regardless.
- **Runtime offline confirmation** — All JSON output includes `"offline": true` in the `run` metadata, and `stave capabilities` includes `"offline": true` at the top level. These are constant values confirming the architectural guarantee.

### Transitive `net` package usage

The `pflag` library (used by Cobra for flag parsing) transitively imports the `net` package for `net.ParseIP()` and related IP address parsing functions. This is **parsing-only** — no sockets are opened, no connections are made, and no network I/O occurs. Stave does not import `net/http`, `net/rpc`, `crypto/tls`, or any other package that performs network I/O.

### Development tools that use os/exec

Stave repository code does not include a recording generator. Terminal recording automation is owned by the sibling `publisher` workspace (`../publisher/generate-recordings.sh`) and is outside the Stave runtime/release artifact scope.

### Filesystem Safety

Stave enforces strict filesystem safety properties:

- **No file deletion during normal operation** — Stave does not delete user files during normal operation.
- **All writes are user-controlled** — Output files are only created when explicitly requested via `--out` flags. No implicit temporary files, caches, or config directories.
- **No-overwrite by default** — All write commands refuse to overwrite existing files unless `--force` is passed. This prevents silent data loss.
- **No-symlink-write by default** — All write commands refuse to write through symbolic links unless `--allow-symlink-output` is passed. This prevents symlink-based write attacks where an attacker places a symlink at the output path pointing to a sensitive file.
- **Path traversal protection** — The control registry index (`_registry/controls.index.json`) validates all relative paths to prevent directory traversal (e.g., `../../../etc/passwd`). Paths are cleaned and verified to remain within the control root.
- **Bucket name validation** — Bucket names from AWS snapshot data are validated against S3 naming rules before being used in file paths, preventing path injection via crafted bucket names.
- **Path normalization** — All user-supplied paths from CLI flags are cleaned (`filepath.Clean`) to normalize `.`/`..` segments and duplicate separators.
- **Restricted output permissions** — Output directories are created with `0700` (owner-only) and files with `0600` (owner read/write only). Log files use `0644` for aggregation compatibility.

**Shared-system guidance:** On multi-user systems, verify your umask is restrictive (`umask 077`) and write outputs into a private directory (e.g., `~/stave-output/`) to prevent other users from reading evaluation results.

See [Data Flow and I/O](docs/trust/data-flow-and-io.md) for the per-command I/O model.

For a detailed security assessment, see [Security and Trust](docs/trust/01-security-and-trust.md), [Execution Safety](docs/trust/execution-safety.md), and [Data Flow and I/O](docs/trust/data-flow-and-io.md).

## How to Verify No Network at Runtime

You can independently verify that Stave makes zero network syscalls:

**Linux (strace):**

```bash
strace -f -e trace=network ./stave apply \
  --controls ./controls --observations ./obs 2>&1 | grep -E 'socket|connect|sendto|recvfrom|getaddrinfo'
# Expected: no output (zero network syscalls)
```

**macOS (dtruss):**

```bash
# dtruss requires root; run in a test environment
sudo dtruss -f ./stave apply \
  --controls ./controls --observations ./obs 2>&1 | grep -iE 'socket|connect'
# Note: macOS dtruss output is noisier; filter for socket/connect only
```

**Container-based (works on any OS):**

```bash
docker run --rm --network=none -v "$(pwd):/work" -w /work golang:1.26 \
  ./stave apply --controls ./controls --observations ./obs
# If this succeeds, the binary works with zero network access
```

## Network Policy

**Runtime:** Stave requires zero outbound network connections. Corporate firewalls, egress policies, and NSGs can deny all outbound traffic and Stave will operate normally. No proxy configuration, DNS resolution, or TLS certificates are needed.

**Build/CI/Release:** Building from source and release signing require network access for Go module downloads, CI runners, Sigstore signing, and artifact uploads. See [Offline & Air-Gapped Operation](docs/offline-airgapped.md) and [Release Security](docs/trust/02-release-security.md) for the full inventory.

## Privileges

Stave requires no elevated privileges at any stage:

- **Build:** `make build` runs as the current user. No root or sudo required.
- **Install:** `make install` writes to `$GOPATH/bin/`. No system directories are modified.
- **Run:** Stave reads user-owned files and writes to user-owned paths or stdout. It makes no privileged syscalls, requires no `CAP_*` capabilities, and has no setuid/setgid bits.
- **Docker:** The demo image runs as a non-root user (UID 10001). See `docs-content/demo/Dockerfile`.
- **Output permissions:** All output directories use `0700` and files use `0600` (owner-only access).

## Credential-Free Operation

Stave is architecturally credential-free. It never requires, reads, or processes cloud credentials:

- **Source type validation is local** — The `generated_by.source_type` field is validated against a built-in allowlist. Accepted source types do not imply cloud API access; all inputs are local snapshot files. Run `stave capabilities` to see the current allowlist.
- **No credential environment variables** — Stave does not read `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE`, `GOOGLE_APPLICATION_CREDENTIALS`, or any other credential-related environment variable. The only environment variable Stave reads is `NO_COLOR` (per [no-color.org](https://no-color.org/)).
- **No credential files** — Stave does not read `~/.aws/credentials`, `~/.aws/config`, service account key files, or any credential store.
- **No cloud API calls** — Stave never contacts AWS, GCP, Azure, or any other cloud API. All input is local files.
- **Snapshot export is external** — Users export configuration snapshots using their own tools (AWS CLI, Terraform) outside of Stave. Stave reads the resulting local files only.

The `internal/platform/logging/sanitize.go` file contains a list of sensitive key patterns (`token`, `secret`, `password`, etc.) used to sanitize values from log output. This is **defensive log hygiene** — it prevents accidental logging of secrets that users might pass as CLI arguments. Stave does not consume or process these values.

See [docs/s3-assessment.md](docs/s3-assessment.md) for the recommended workflow showing the credential boundary between user tools and Stave.

### Snapshot sensitivity

Terraform plan/state exports and AWS CLI snapshots may contain embedded credentials or sensitive values in rare cases. Stave treats all resource properties as opaque data and does not detect or filter secrets within snapshots.

**Recommendations:**
- Do not include raw secrets in Terraform state/plan exports passed to Stave.
- Use `--sanitize` when sharing evaluation output to replace infrastructure identifiers with deterministic tokens.
- Use `ingest --profile aws-s3 --scrub` to remove sensitive fields (tags, raw policies, ACL grants) from observations before sharing.
- Treat all snapshot files as sensitive data and apply your organization's data handling policies.

See [Sharing Outputs Safely](docs/sanitization.md) for details on sanitization and scrubbing.

## Synthetic Test Data

All AWS account IDs (e.g., `123456789012`, `777666555444`), ARNs, and bucket names appearing in `testdata/`, `case-studies/`, and documentation are **synthetic placeholders**. They do not correspond to real AWS accounts or infrastructure. AWS example credentials (`AKIAIOSFODNN7EXAMPLE`) are [official AWS documentation placeholders](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html).

## Sharing Outputs Safely

When sharing Stave outputs for review, use `--sanitize` to replace infrastructure identifiers with deterministic tokens and `ingest --profile aws-s3 --scrub` to remove sensitive fields from observations. See [Sharing Outputs Safely](docs/sanitization.md) for details.

## Output Sanitization Reference

Stave provides two flags for controlling sensitive data in output:

### `--sanitize`

Replaces infrastructure identifiers with deterministic tokens in findings, diagnostics, reports, and validation output. Applies uniformly to JSON, text, and markdown outputs.

**What is sanitized:**

| Field | Sanitized Form |
|-------|--------------|
| `Finding.ResourceID` | `SANITIZED_<8hex>` (deterministic SHA-256 token) |
| ARNs in `ResourceID` | `arn:aws:s3:::SANITIZED_<8hex>` (structure preserved) |
| `Finding.Source.File` | Basename only (directory stripped) |
| `Evidence.Misconfigurations[].ActualValue` | `[SANITIZED]` |
| `SourceEvidence.PolicyPublicStatements` | `[SANITIZED]` |
| `SourceEvidence.ACLPublicGrantees` | `[SANITIZED]` |
| `Diagnostic.Evidence` asset IDs | `SANITIZED_<8hex>` |
| `CounterfactualReport.IncidentID` | `[SANITIZED]` |
| `InputHashes` file keys | Basename only |
| Validation evidence directory/file paths | `[SANITIZED]` |

**What is preserved:** Control IDs, control names, rule IDs, counts, durations, timestamps, schema versions, root cause types.

**Determinism:** Same inputs always produce the same sanitized output. Tokens are derived from SHA-256 of the original value.

### `--path-mode`

Controls how file paths appear in error messages and logs.

| Mode | Behavior |
|------|----------|
| `base` (default) | Absolute paths are replaced with basenames (e.g., `/home/user/obs/snap.json` becomes `snap.json`) |
| `full` | Absolute paths are shown as-is |

Use `--path-mode=full` to include absolute paths in errors and logs.

### Producing Shareable Output

```bash
# Sanitize identifiers and use basename-only paths
stave apply --controls ./controls --observations ./obs --sanitize

# Full sanitization with scrubbed observations
stave ingest --profile aws-s3 --input ./snapshot --out obs.json --scrub
stave apply --profile aws-s3 --input obs.json --sanitize > report.json

# Diagnostics in JSON with sanitization
stave diagnose --controls ./controls --observations ./obs --format json --sanitize
```

### Panic Output

By default, panic recovery prints a generic message without the raw panic value. Use `-vv` to include sanitized panic details (paths shortened per `--path-mode`).
