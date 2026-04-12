# Multi-Profile Evaluation

Multi-profile evaluation allows a single `stave apply` run to
evaluate multiple compliance frameworks simultaneously. Controls
are deduplicated, compliance citations merged, and the report
shows per-framework readiness scores.

## Usage

```bash
# Evaluate HIPAA and SOC 2 in one pass
stave apply --profile hipaa,soc2 --input observations.json --include-all --format json

# Three frameworks at once
stave apply --profile hipaa,pci-dss-v4.0,soc2 --input observations.json --include-all
```

Single-profile mode is unchanged: `--profile hipaa` works as before.

## How it works

Controls already carry multi-framework compliance mappings in their
YAML definitions. A control with `hipaa: "164.312(a)(1)"` and
`soc2: "CC6.1"` already knows it satisfies both. Multi-profile
evaluation simply loads controls matching ANY of the requested
frameworks instead of exactly one.

### Control deduplication

If CTL.S3.ENCRYPT.001 appears in both HIPAA and PCI-DSS, it is
evaluated once. The finding carries all compliance citations from
the control's metadata.

### Strictness principle

When multiple profiles are active, the global `--max-unsafe` flag
applies the same threshold to all frameworks. This is the most
restrictive approach — a finding that violates any framework's SLA
is reported.

## Framework readiness

Each requested framework is scored independently:

```
readiness = (controls with no violations) / (total controls in framework) × 100
```

### Text output

```
Framework Readiness
-------------------
  hipaa                92%  (46/50 controls passing)
  soc2                 87%  (68/78 controls passing)
  pci_dss_v4.0         45%  (27/60 controls passing)

Compliance ROI: fixing 12 violations covers 38 framework citations
```

### JSON output

```json
{
  "summary": {
    "total_assets": 200,
    "violations": 12,
    "framework_readiness": [
      {"framework": "hipaa", "total_controls": 50, "passing_controls": 46, "readiness_percent": 92},
      {"framework": "soc2", "total_controls": 78, "passing_controls": 68, "readiness_percent": 87}
    ],
    "framework_citations_satisfied": 38
  }
}
```

## Super-Fix highlighting

The report identifies the single highest-impact remediation — the
violated control that satisfies the most framework citations:

```
[!] High-Impact Remediation: fixing CTL.S3.ENCRYPT.001 satisfies 4 requirements across hipaa, soc2, pci_dss_v4.0
```

This tells the security team which fix delivers the most compliance
value per hour of engineering effort.

## Nearby frameworks (gap analysis)

Stave checks all frameworks (including those not requested) and
reports any where the organization is already >= 80% compliant:

```
Nearby Frameworks (already >80% ready)
  fedramp_moderate      88% ready (6 gaps to close)
  nist_800_53_r5        92% ready (4 gaps to close)
```

This encourages adoption of higher security standards by proving
the organization is "already almost there."

## Evidence bundle compatibility

When `stave bundle` is run after a multi-profile evaluation, the
ASFF output includes all compliance citations per finding:

```json
{
  "ProductFields": {
    "ControlId": "CTL.S3.ENCRYPT.001",
    "Compliance.hipaa": "164.312(a)(2)(iv)",
    "Compliance.soc2": "CC6.7",
    "Compliance.pci_dss_v4.0": "3.5.1"
  }
}
```

GRC tools that integrate via Security Hub see the finding mapped
to every relevant dashboard.

## Key files

| File | Purpose |
|---|---|
| `cmd/apply/profile.go` | ParseProfiles, filterByComplianceUnion, loadControlsMulti |
| `internal/core/evaluation/audit.go` | FrameworkReadiness, SuperFix, NearbyFramework, CalculateReadiness |
| `internal/adapters/output/text/finding_writer.go` | writeFrameworkReadiness rendering |
| `internal/adapters/output/asff/writer.go` | buildProductFields with multi-citation |
