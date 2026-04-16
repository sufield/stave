# How to Compare Two Compliance Frameworks

Analyze the marginal cost of adopting a second compliance framework.

---

## Run the Gap Analysis

```bash
stave compare \
  --from hipaa \
  --to fedramp_moderate \
  --assessment findings.json
```

## Read the Output

The output shows:

- **Shared violations** — controls failing in both frameworks. Fix once, satisfy both.
- **Target-only violations** — additional work required for the target framework.
- **Adoption readiness** — percentage of target controls already satisfied.
- **Upgrade roadmap** — Phase 1 (shared, highest ROI) then Phase 2 (target-specific).

## Available Framework Keys

`hipaa`, `nist_800_53_r5`, `fedramp_moderate`, `soc2`, `pci_dss_v4.0`, `cis_aws_v3.0`, `gdpr`, `iso_27001_2022`

## Export as Markdown

```bash
stave compare \
  --from hipaa \
  --to fedramp_moderate \
  --assessment findings.json \
  --format markdown \
  --out gap-analysis.md
```

## JSON for Downstream Processing

```bash
stave compare \
  --from hipaa \
  --to soc2 \
  --assessment findings.json \
  --format json
```
