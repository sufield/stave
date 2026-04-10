# PCI-DSS v4.0 — Control Catalog

Complete mapping of PCI-DSS v4.0 requirements to Stave control
definitions. One YAML file per PCI requirement section.

## Coverage

| File | Requirement | Total | Mapped | New | Manual |
|---|---|---|---|---|---|
| pci-req1-network.yaml | Req 1 — Network Security | 7 | 5 | 0 | 2 |
| pci-req2-hardening.yaml | Req 2 — Secure Configurations | 4 | 3 | 0 | 1 |
| pci-req3-stored-data.yaml | Req 3 — Protect Stored Data | 6 | 5 | 1 | 0 |
| pci-req4-transit.yaml | Req 4 — Data in Transit | 6 | 6 | 0 | 0 |
| pci-req5-malware.yaml | Req 5 — Malicious Software | 2 | 2 | 0 | 0 |
| pci-req6-development.yaml | Req 6 — Secure Development | 4 | 2 | 0 | 2 |
| pci-req7-access.yaml | Req 7 — Restrict Access | 5 | 5 | 0 | 0 |
| pci-req8-authentication.yaml | Req 8 — Authentication | 10 | 10 | 0 | 0 |
| pci-req10-logging.yaml | Req 10 — Logging & Monitoring | 10 | 8 | 1 | 1 |
| pci-req11-testing.yaml | Req 11 — Security Testing | 4 | 2 | 0 | 2 |
| pci-req12-policy.yaml | Req 12 — Policies | 4 | 0 | 0 | 4 |
| **Total** | | **62** | **48** | **2** | **12** |

## Classification

- **MAPPED (48)**: Already covered by existing HIPAA, CIS v3.0, or SOC 2
  controls. Require `pci_dss_v4.0:` compliance tag on existing controls.
- **NEW (2)**: S3 KMS CMK requirement (maps to existing ENCRYPT.003) and
  CloudWatch log retention >= 365 days.
- **MANUAL (12)**: Organizational processes (policies, training, pen tests,
  vendor management, segmentation validation, log reviews).

## PCI Requirement IDs in Stave Output

When `stave apply --profile pci-dss-v4.0` runs, each finding includes:

```json
{
  "control_compliance": {
    "pci_dss_v4.0": "3.4.1",
    "hipaa": "164.312(a)(2)(iv)"
  }
}
```

This allows auditors to filter findings by PCI requirement ID directly.
