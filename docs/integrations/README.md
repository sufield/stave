# SBOM and Vulnerability Scanner Integration

## The Two-Layer Model

Security intelligence for cloud infrastructure has two distinct layers:

**Stave owns: configuration-observable security**
- Resource misconfigurations with reasoning traces
- Compliance citations (HIPAA, PCI-DSS, SOC2)
- Attack stage context and blast radius
- Stable finding identity (`finding_id`)
- Remediation guidance with confidence scores

**External tools own: runtime dependency and binary security**
- Package manifests and dependency trees (Syft)
- CVE matches against packages (Grype, Trivy)
- Container image layer analysis
- Fix version availability

These are complementary, not competing. Stave evaluates what you configured. Scanners evaluate what you deployed.

## The Join Key

Both layers identify the same AWS resources. The join key is `resource_arn`:

- Stave finding: `"asset_id": "arn:aws:lambda::123:function/patient-api"`
- Grype scan target: the container image for the same Lambda function

The adapter scripts in this directory perform the join.

## Pipeline Example

```bash
# Step 1: Stave assessment (runs on schedule or per-deploy)
stave apply --controls controls/ --observations obs/ --format json > assessment.json

# Step 2: Grype scan of Lambda container images
grype lambda:patient-api --output json > grype-patient-api.json

# Step 3: Join into unified security records
python3 docs/integrations/grype.py \
  --stave assessment.json \
  --grype grype-patient-api.json \
  --resource arn:aws:lambda::123:function/patient-api \
  > unified-patient-api.json
```

All three steps work on local files. No API calls required.

## When to Use Each Adapter

| Adapter | Scanner | Use case |
|---------|---------|----------|
| `grype.py` | Grype | Join Stave findings with Grype vulnerability JSON |
| `trivy.py` | Trivy | Join Stave findings with Trivy vulnerability JSON |
| `cyclonedx.py` | Syft | Enrich a CycloneDX SBOM with Stave finding annotations |
| `dependency-track.py` | Dependency Track | Upload enriched SBOM to Dependency Track instance |

## Air-Gapped Note

All adapters work on local files. The join step never calls external services. `dependency-track.py` has an optional upload step (step 2) that requires network access — it is clearly separated and can be skipped.

## Scanner Tool References

- **Syft** — SBOM generation: https://github.com/anchore/syft
- **Grype** — Vulnerability scanning: https://github.com/anchore/grype
- **Trivy** — Combined SBOM + scanning: https://github.com/aquasecurity/trivy
