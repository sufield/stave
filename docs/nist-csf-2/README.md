# NIST CSF 2.0 — Control Catalog

NIST Cybersecurity Framework v2.0 mapping for Stave. CSF 2.0 is an
outcome-based taxonomy organized into 6 functions, not prescriptive
controls like NIST 800-53.

## Coverage

| File | Function | Total | Mapped | Manual |
|---|---|---|---|---|
| csf-govern.yaml | GV — Govern | 5 | 0 | 5 |
| csf-identify.yaml | ID — Identify | 4 | 2 | 2 |
| csf-protect.yaml | PR — Protect | 15 | 15 | 0 |
| csf-detect.yaml | DE — Detect | 6 | 5 | 1 |
| csf-respond.yaml | RS — Respond | 3 | 0 | 3 |
| csf-recover.yaml | RC — Recover | 5 | 4 | 1 |
| **Total** | | **38** | **26** | **12** |

## Function Summary

- **Govern** — Entirely organizational (policies, risk appetite, roles)
- **Identify** — Config as asset inventory + Access Analyzer; risk assessment manual
- **Protect** — Fully covered by existing encryption, access, and hardening controls
- **Detect** — Fully covered by CloudTrail, GuardDuty, Security Hub, CloudWatch
- **Respond** — Entirely organizational (IR plan, investigation, communication)
- **Recover** — Backup and failover controls mapped; DR testing manual
