# Evidence Bundling

Evidence bundling answers: "How do I get compliance evidence out
of an air-gapped environment and into my GRC platform?"

`stave bundle` produces a cryptographically sealed evidence archive
containing the assessment, logic trace, and resource snapshots.
A human or data diode transfers the `.stave-bundle` file to the
internet-connected side, where it can be verified and relayed to
GRC platforms (Vanta, Drata, ServiceNow).

## The portable attestation model

```
Air-Gapped Zone              │  Internet Zone
                             │
stave bundle                 │
  ↓                          │
.stave-bundle (tar.gz)       │
  ↓                          │
Human / Data Diode ─────────→│→ Verify signature
                             │    ↓
                             │  Push to GRC API
                             │    ↓
                             │  Vanta / Drata / ServiceHub
```

Stave generates evidence locally. The bundle is self-contained and
cryptographically verifiable — no network connection required during
generation.

## Command

```bash
# Generate unsigned bundle
stave bundle --controls ./controls --observations ./observations

# Generate signed bundle
stave bundle -i ./controls -o ./observations --sign-key audit-private.pem

# Include ASFF for Security Hub integration
stave bundle -i ./controls -o ./observations --include-asff
```

## Bundle contents

```
evidence-20260412T170000Z.stave-bundle (tar.gz)
├── summary.txt           # Human-readable cover letter
├── assessment.json       # Full out.v0.1 assessment with findings
├── metadata.json         # Stave version, timestamp, control count
├── snapshots.json        # Pruned: violation-only resource snippets
├── logic_trace.json      # Per-control reasoning steps (if traced)
├── manifest.json         # SHA-256 per file + overall digest
└── signature.json        # Ed25519 signature (if signed)
```

### The "Triple Crown of Evidence"

Each bundle provides three things auditors need:

1. **The Finding** — What was wrong (assessment.json)
2. **The Proof** — Why it was flagged, with CEL expression and
   reasoning steps (logic_trace.json)
3. **The State** — The actual cloud configuration that caused the
   violation (snapshots.json, pruned to violated assets only)

### Evidence pruning

The `snapshots.json` file contains only resources referenced in
findings — a bundle with 3 violations out of 10,000 assets includes
only 3 resource snippets. This prevents multi-gigabyte bundles while
preserving the exact evidence an auditor needs.

### Summary (cover letter)

```
Stave Evidence Bundle
=====================

Generated: 2026-04-12T17:00:00Z
Version:   1.0.0
Status:    NON_COMPLIANT

Assets evaluated:  2,450
Violations found:  7
Chain findings:    2
Signed:            true
```

## Signing and verification

### Generate a signing key pair

```bash
# Generate Ed25519 key pair (one-time setup)
openssl genpkey -algorithm ed25519 -out audit-private.pem
openssl pkey -in audit-private.pem -pubout -out audit-public.pem
```

### Sign the bundle

```bash
stave bundle -i ./controls -o ./observations --sign-key audit-private.pem
```

The bundle includes `signature.json` with the Ed25519 signature of
the manifest's SHA-256 digest. The relay or auditor verifies the
signature against the known public key before trusting the evidence.

### Verification

```bash
# Extract and verify manually
tar xzf evidence.stave-bundle
# Check manifest hashes match file contents
# Verify signature against public key
```

## ASFF integration

The `--include-asff` flag generates an additional `.asff.json` file
mapping Stave findings to the AWS Security Finding Format (v2018-10-08).
GRC tools with Security Hub connectors can ingest this directly.

ASFF mapping:

| Stave field | ASFF field |
|---|---|
| ControlID | `ProductFields.ControlId` |
| ControlSeverity | `Severity.Label` |
| AssetID | `Resources[0].Id` |
| ControlName | `Title` |
| ControlDescription | `Description` |
| RemediationSpec.Action | `Remediation.Recommendation.Text` |
| ChainID | `ProductFields.ChainId` |
| CompoundScore | `ProductFields.CompoundScore` |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Bundle created, no violations |
| 2 | Input error |
| 3 | Bundle created with violations |
| 4 | Internal error |

Exit code 3 with violations is expected — the bundle still contains
valid evidence for the GRC platform.

## Workflow: automated compliance reporting

```bash
# Daily: generate evidence from latest observations
stave bundle \
  -i ./controls \
  -o ./observations \
  --sign-key /secure/audit-private.pem \
  --include-asff \
  --output /evidence/$(date +%Y-%m-%d).stave-bundle

# Transfer to internet zone (manual or data diode)
# Relay reads bundle, verifies signature, pushes to GRC API
```

## Key files

| File | Purpose |
|---|---|
| `cmd/bundle/cmd.go` | Top-level bundle command |
| `internal/adapters/evidence/bundler.go` | Tar.gz packager with manifest + signing |
| `internal/adapters/output/asff/writer.go` | ASFF format mapper |
| `internal/core/ports/evidence.go` | EvidenceBundler interface |
| `internal/platform/crypto/ed25519.go` | Ed25519 signing infrastructure |
