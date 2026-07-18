# Compliance Frameworks

Stave maps controls to compliance frameworks. Each framework directory
contains YAML mappings from framework requirements to Stave control IDs.

## Supported Frameworks

| Framework | Directory | Controls Mapped |
|-----------|-----------|-----------------|
| NIST 800-53 | [nist-800-53/](../nist-800-53/README.md) | AC, AU, CM, IA, IR, MP, RA, SA, SC, SI |
| NIST CSF 2.0 | [nist-csf-2/](../nist-csf-2/README.md) | Govern, Identify, Protect, Detect, Respond, Recover |
| ISO 27001 | [iso27001/](../iso27001/README.md) | Organizational, People, Physical, Technological |
| FFIEC | [ffiec/](../ffiec/README.md) | CAT, ISH, BCP |
| CSA CCM | [CSA coverage](../csa-coverage.md) | Cloud Controls Matrix v4 |
| HIPAA | [hipaa.md](../hipaa.md) | Security Rule technical safeguards |
| OWASP NHI Top 10 | [owasp-nhi-top10](../compliance/owasp-nhi-top10.md) | Non-Human Identity risks |

## Framework data files

Machine-readable framework definitions live in [`data/frameworks/`](../../data/README.md).
These YAML files drive `stave compare` and `stave compliance` output.

## Compliance commands

```bash
# doctest:skip — requires observation data; compare uses --from/--to not --frameworks
# Check posture against a framework
stave compliance --framework cis-aws-v3

# Compare two frameworks
stave compare --frameworks cis-aws-v3,nist-800-53

# Export compliance evidence
stave export compliance --framework hipaa
```
