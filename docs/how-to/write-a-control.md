# Write a Control

Contribute a new control to the Stave catalog.

## Interactive scaffolding

```bash
# doctest:skip — interactive commands
# Create a new control interactively
stave forge new

# Preview a predicate before committing
stave forge preview

# Discover fields to write a predicate against
stave forge paths --asset-type s3_bucket
```

## Test the control

```bash
# doctest:skip — requires a control YAML to exist
# Scaffold pass/fail fixtures
stave forge scaffold CTL.S3.MY_CONTROL.001

# Run the test
stave forge test CTL.S3.MY_CONTROL.001

# Lint the control definition
stave forge lint
```

## Guided walkthrough

The [write-your-first-control skill](../../_skills/write-your-first-control/SKILL.md)
walks through the full process step by step.

## Contributing checklist

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for the full PR checklist,
including golden file regeneration and consistency checks.
