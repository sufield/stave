# Use Assessment Templates

Templates bundle controls, chains, and parameters into a ready-to-run
assessment. Instead of assembling flags manually, pick a template.

## Find the right template

```bash
# See which template fits your snapshot
stave recommend --snapshot ./observations/

# List all templates
stave template list
```

## Built-in templates

| Template | Job |
|----------|-----|
| `critical-findings` | Surface critical/high findings for whatever services appear |
| `independent-audit` | Broad-scope audit across all services |
| `m-and-a-diligence` | Due-diligence posture snapshot for acquisitions |
| `breach-reconstruction` | Timeline reconstruction after a security incident |
| `bucket-hijacking-assessment` | Router-to-S3 destination binding evaluation |

## Run a template

```bash
# Initialize with parameters
stave template init critical-findings --param severity_threshold=high

# Run the assessment
stave apply --values ./stave-values.yaml --snapshot ./observations/
```

## Custom templates

```bash
# Scaffold a new template
stave template new my-org-assessment

# Fork a built-in for customization
stave template eject critical-findings

# Verify a template
stave template verify my-org-assessment
```

See [`templates/README.md`](../../templates/README.md) for template structure.
