# Observations

Pre-captured observation snapshots of the SadCloud environment in
obs.v0.1 format.

## For Tools That Accept JSON Input

Tools like Stave can evaluate directly against observation snapshots
without a live AWS deployment:

```bash
stave apply --observations observations/ --format json
```

## Capturing Your Own

After deploying SadCloud, capture observations using the AWS CLI:

```bash
# Example: capture IAM roles
aws iam list-roles > raw/iam-roles.json
aws iam get-role --role-name <name> >> raw/iam-role-detail.json

# Transform to obs.v0.1 using Lean 4 extractors
# See iam-explainer/Stave/Extract/ for the conversion modules
```

Two snapshots (captured at different times) are required for
duration-based analysis.
