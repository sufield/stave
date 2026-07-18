# Use Compliance Lenses

Map Stave findings to compliance frameworks — HIPAA, SOC2, PCI-DSS,
NIST 800-53, CIS, FFIEC, ISO 27001, and more.

## Check compliance posture

```bash
# doctest:skip — requires observation data; flag names may differ from CLI
# Evaluate against a framework
stave compliance --framework cis-aws-v3 --observations ./snapshots/

# Compare two frameworks side by side
stave compare --frameworks cis-aws-v3,nist-800-53

# Export evidence for auditors
stave export compliance --framework hipaa --observations ./snapshots/
```

## Available frameworks

See [compliance frameworks](../reference/compliance-frameworks.md) for the
full list with coverage details.

## Scorecard

```bash
# doctest:skip — requires observation data
# Posture across several frameworks at once
stave scorecard --observations ./snapshots/
```
