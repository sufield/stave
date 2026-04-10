# FedRAMP Compliance Pack — Control Catalog

FedRAMP Moderate baseline mapping for Stave. FedRAMP inherits NIST SP
800-53 Rev 5 and adds requirements for FIPS 140 cryptography,
continuous monitoring, personnel vetting, and authorization boundary.

## Coverage

| File | Area | Total | Mapped | New | Manual |
|---|---|---|---|---|---|
| fedramp-baseline.yaml | NIST 800-53 Baseline | 20 | 20 | 0 | 0 |
| fedramp-cryptography.yaml | FIPS 140 | 6 | 4 | 1 | 1 |
| fedramp-monitoring.yaml | Continuous Monitoring | 8 | 3 | 0 | 5 |
| fedramp-access.yaml | Personnel & Access | 8 | 3 | 0 | 5 |
| fedramp-incident.yaml | IR & Boundary | 7 | 1 | 0 | 6 |
| **Total** | | **49** | **31** | **1** | **17** |

## FedRAMP Baselines

| Baseline | NIST Controls | Stave Coverage |
|---|---|---|
| Low | 125 | Covered via NIST profile (57 automatable controls) |
| Moderate | 325 | Same controls + organizational/manual requirements |
| High | 421 | Same + GovCloud, US Persons, PIV/CAC |

Most of the difference between Low/Moderate/High is organizational
requirements (personnel vetting, ConMon frequency, assessment scope),
not technical configuration.

## Relationship to NIST Profile

FedRAMP inherits all NIST 800-53 controls. Running `--profile fedramp`
evaluates the same technical controls as `--profile nist-800-53` with
additional FIPS cryptography validation. The organizational requirements
(ConMon, POA&M, 3PAO, personnel) are documented as MANUAL entries.
