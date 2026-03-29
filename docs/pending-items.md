# Pending Items

Tracks unimplemented controls and features that are referenced in code,
tests, documentation, or compound rules but do not yet have
implementations. Each item includes what blocks on it so the impact of
deferral is visible.

---

## Unimplemented HIPAA Controls

These controls were specified in the original HIPAA profile design. They
appear in `docs/hipaa.md`, test assertions, and (for ACCESS.003 /
ACCESS.006) compound rule trigger lists. The auto-discovery profile
system will pick them up automatically once implemented — create the
control file with `init()`, `WithComplianceProfiles("hipaa")`, and
`WithProfileRationale(...)`.

### AUDIT.002 — Object-Level Logging for PHI Access

| Field | Value |
|-------|-------|
| Severity | HIGH (override from default) |
| HIPAA Citation | §164.312(b) |
| Rationale | Object-level logging for PHI access audit trail |
| Blocks | Nothing downstream |
| Registry | `ControlRegistry` |

When implemented, add `WithProfileSeverityOverride("hipaa", High)` to
set the severity override (re-add the builder option from `control.go`
first — it was removed in d48d48d8b because no callers existed).

### ACCESS.003 — Transmission Security (VPC Endpoint / IP Restriction)

| Field | Value |
|-------|-------|
| Severity | HIGH (override from default) |
| HIPAA Citation | §164.312(e)(1) |
| Rationale | Transmission security — VPC endpoint or IP restriction |
| Blocks | COMPOUND.003 (cannot fire without this) |
| Registry | `ControlRegistry` |

Design context in `tutorials/26.md` and `tutorials/45.md`.

### ACCESS.006 — VPC Endpoint Policy Restriction

| Field | Value |
|-------|-------|
| Severity | HIGH |
| HIPAA Citation | §164.312(e)(1) |
| Rationale | VPC endpoint policy restricts access to approved bucket ARNs |
| Blocks | COMPOUND.003 (cannot fire without this) |
| Registry | `ControlRegistry` |

Coupled with ACCESS.003 — COMPOUND.003 detects the case where VPC
endpoint exists (ACCESS.003 passes) but the endpoint policy is missing
(ACCESS.006 fails), creating a false sense of network isolation.

### ACCESS.009 — Presigned URL Restriction for PHI Buckets

| Field | Value |
|-------|-------|
| Severity | MEDIUM (override from default) |
| HIPAA Citation | §164.312(a)(1) |
| Rationale | Presigned URL restriction for PHI buckets |
| Blocks | Nothing downstream |
| Registry | `ControlRegistry` |

---

## Non-Functional Compound Rule

### COMPOUND.003 — VPC Endpoint Without Endpoint Policy

- **File**: `internal/core/hipaa/compound/rules.go`
- **Trigger IDs**: ACCESS.003, ACCESS.006
- **Status**: Defined, tested, documented — but will never fire because
  both trigger controls are unimplemented.
- **Action**: No code change needed. The rule will activate automatically
  once ACCESS.003 and ACCESS.006 are implemented and registered. Verify
  COMPOUND.003 fires correctly at that time.

---

## Infrastructure for Severity Overrides

The `WithProfileSeverityOverride` builder option was removed (d48d48d8b)
because no implemented control uses it. When AUDIT.002, ACCESS.003, or
ACCESS.009 are implemented with severity overrides, re-add it:

```go
// In internal/core/hipaa/control.go

func WithProfileSeverityOverride(profile string, sev Severity) Option {
    return func(d *Definition) {
        if d.profileSeverities == nil {
            d.profileSeverities = make(map[string]Severity)
        }
        d.profileSeverities[profile] = sev
    }
}
```

The `profileSeverities` field and `ProfileSeverityOverride()` getter
already exist on `Definition`. Only the builder option needs to be
restored.

---

## Checklist for Implementing a New HIPAA Control

1. Create `internal/core/hipaa/<category>_<behavior>.go` with struct + `Evaluate()`
   - Use snake_case functional naming (e.g., `access_vpc_endpoint.go`, not `access003.go`)
   - Struct name matches file: `accessVpcEndpoint`
2. Add `init()` calling `ControlRegistry.MustRegister(...)` with:
   - `WithID("...")`
   - `WithDescription("...")`
   - `WithSeverity(...)`
   - `WithComplianceProfiles("hipaa")`
   - `WithComplianceRef("hipaa", "§...")`
   - `WithProfileRationale("hipaa", "...")`
   - `WithProfileSeverityOverride("hipaa", ...)` if severity differs from default
3. Create `internal/core/hipaa/<category>_<behavior>_test.go`
4. Run `go test ./internal/core/hipaa/... ./internal/profile/...`
5. No changes to `hipaa.go` or `profile.go` required — auto-discovery handles it
