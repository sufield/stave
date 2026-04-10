# NIST SP 800-53 Rev 5 — Control Catalog

Complete mapping of NIST 800-53 Rev 5 control families to Stave
control definitions. One YAML file per control family.

## Coverage

| File | Family | Total | Mapped | Manual |
|---|---|---|---|---|
| nist-ac.yaml | AC — Access Control | 15 | 13 | 2 |
| nist-au.yaml | AU — Audit & Accountability | 12 | 10 | 2 |
| nist-sc.yaml | SC — System & Comms Protection | 14 | 13 | 1 |
| nist-ia.yaml | IA — Identification & Auth | 10 | 9 | 1 |
| nist-cm.yaml | CM — Configuration Management | 7 | 5 | 2 |
| nist-si.yaml | SI — System & Info Integrity | 6 | 4 | 2 |
| nist-ir.yaml | IR — Incident Response | 4 | 2 | 2 |
| nist-mp.yaml | MP — Media Protection | 4 | 3 | 1 |
| nist-ra.yaml | RA — Risk Assessment | 3 | 2 | 1 |
| nist-sa.yaml | SA — System & Services Acquisition | 3 | 1 | 2 |
| **Total** | | **78** | **62** | **16** |

## Classification

- **MAPPED (62)**: Already covered by existing HIPAA, CIS v3.0, SOC 2,
  or PCI-DSS v4.0 controls. Require `nist_800_53_r5:` tag on existing controls.
- **NEW (0)**: All NIST requirements map to existing controls.
- **MANUAL (16)**: Organizational processes (policies, procedures, training,
  risk assessments, media sanitization).
