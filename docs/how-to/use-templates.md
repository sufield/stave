# Use Assessment Templates

Templates bundle controls, chains, and parameters into a ready-to-run
assessment. Instead of assembling flags manually, pick a template.

## Find the right template

```bash
# doctest:skip — recommend snapshot loading not yet wired
# See which template fits your snapshot
stave recommend --snapshot ./observations/

# List available templates
stave template
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
# doctest:skip — creates stave-values.yaml in working tree
# Zero arguments — defaults to critical-findings, severity_threshold=high
stave template init
```

Arguments are overrides, not requirements:

```bash
# doctest:skip — creates stave-values.yaml in working tree
# Override the template type
stave template init independent-audit

# Override a parameter
stave template init --param severity_threshold=critical
```

```bash
# doctest:skip — --values flag not yet implemented
# Run the assessment
stave apply --values ./stave-values.yaml --snapshot ./observations/
```

## Custom templates

```bash
# doctest:skip — creates files in working tree
# Scaffold a new template
stave template new my-org-assessment

# Fork a built-in for customization
stave template eject critical-findings
```

```bash
# doctest:skip — requires template fixture files
# Verify a template
stave template verify my-org-assessment
```

See [`templates/README.md`](../../templates/README.md) for template structure.
