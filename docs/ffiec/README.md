# FFIEC Compliance Pack — Control Catalog

Federal Financial Institutions Examination Council (FFIEC) mapping for
Stave. Covers the Cybersecurity Assessment Tool (CAT), Information
Security Handbook (ISH), Business Continuity Planning (BCP) Handbook,
and Outsourcing Technology Services (OTS) Handbook.

## Coverage

| File | FFIEC Area | Total | Mapped | Manual |
|---|---|---|---|---|
| ffiec-access-identity.yaml | Access & Identity (CAT-D3) | 12 | 12 | 0 |
| ffiec-data-security.yaml | Data Security (ISH) | 13 | 13 | 0 |
| ffiec-cybersecurity.yaml | Cybersecurity Controls (CAT-D3) | 8 | 6 | 2 |
| ffiec-resilience.yaml | Resilience (BCP) | 8 | 6 | 2 |
| ffiec-governance.yaml | Governance & Examiner | 11 | 0 | 11 |
| **Total** | | **52** | **37** | **15** |

## Examiner-Ready Evidence

Stave's snapshot-based evaluation produces the point-in-time compliance
evidence that FFIEC examiners require:

```bash
# doctest:skip — requires observation bundle file and creates output files
stave apply --profile ffiec --input observations.json \
  --include-all --format json > evidence/ffiec-$(date +%Y%m%d).json
```

The JSON output includes control IDs, compliance references, finding
details, and remediation guidance — directly usable in examiner reports.
