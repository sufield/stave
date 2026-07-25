# Write a Control

Contribute a new control to the Stave catalog.

## Interactive scaffolding

```bash
# doctest:skip — interactive command
# Create a new control interactively
stave forge new

# doctest:skip — requires bundle-format snapshot file
# Preview a predicate before committing
stave forge preview

# Discover fields to write a predicate against
stave forge paths --asset-type aws_s3_bucket --snapshot snapshot-bundle.json
```

## Test the control

```bash
# Lint a control definition
stave forge lint --control controls/s3/access/CTL.S3.ACCESS.001.yaml
```

```bash
# doctest:skip — requires specific control and fixture scaffolding
# Scaffold pass/fail fixtures
stave forge scaffold CTL.S3.MY_CONTROL.001

# Run the test
stave forge test CTL.S3.MY_CONTROL.001
```

## Guided walkthrough

The [write-your-first-control skill](../../_skills/write-your-first-control/SKILL.md)
walks through the full process step by step.

## Contributing checklist

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the full PR checklist,
including golden file regeneration and consistency checks.
