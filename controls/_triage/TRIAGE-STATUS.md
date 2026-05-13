# _triage Status

## What this directory actually is

Despite the name `_triage`, this is **not** a queue of unvalidated
controls awaiting promotion. It's a **narrative supplement layer**
for the main catalog under `controls/`. Two subdirectories with
two distinct schemas:

### `overrides/` (1,196 files)

Each file augments an existing main-catalog control with a
structured DEFECT / INFECTION / FAILURE narrative. Schema:

```yaml
control: CTL.<existing-main-catalog-id>
defect: >
  What the configuration defect is, in plain language.
infection: >
  How an attacker exploits this defect — the attack path
  the defect enables.
failure: >
  The worst-case outcome — what happens when the defect
  is exploited.
```

The `control:` field is a foreign key into the main catalog. Each
override file's basename matches its `control:` field; there is
exactly one override per control (no duplicates).

### `families/` (103 files)

Each file provides a family-level narrative for a CTL prefix
(e.g. `CTL.DMS`, `CTL.IAM`, `CTL.S3`) that applies to every
control under that prefix. Schema:

```yaml
family: CTL.<service>
infection: >
  Generic attack path for any control in this family.
failure: >
  Generic worst-case for any control in this family.
```

## Audit performed 2026-05-12

Verified every claim a "cleanup" task would care about:

| Audit category | Finding | Action |
|---|---|---|
| Overrides referencing IDs absent from main catalog (dangling) | 0 | none |
| Duplicate overrides (multiple files for same `control:`) | 0 | none |
| Family prefixes with zero matching main-catalog controls | 0 | none |
| Filename vs `control:` field drift | 0 | none |

The directory is already clean. Nothing to delete.

## Coverage stats

| Metric | Count |
|---|---|
| Main catalog total controls | 2,657 |
| Controls with a `_triage/overrides/` narrative | 1,196 |
| Controls with no override yet | 1,461 (55%) |
| Family-level narratives in `_triage/families/` | 103 |

## What WOULD be actionable

This directory's purpose is supplementing the main catalog. The
backlog isn't cleanup; it's **coverage expansion**: 1,461 of the
2,657 main-catalog controls still have no narrative override.
Adding overrides for high-priority controls would improve the
rendered finding text for those controls.

That's a separate task, scoped per-control, not done in bulk.
Don't author "stub" overrides without thinking through the
defect/infection/failure narrative — it would dilute the value
the existing overrides provide.

## Why the name "_triage" is misleading

The directory was originally created during a triage workflow
where defect/infection/failure narratives were being authored
in bulk. The name persisted after the workflow finished. The
underscore prefix kept it visually distinct in directory
listings.

Renaming the directory to something like `narratives/` or
`finding-text/` would be more accurate but would require
updating embed paths, build tooling, and audit tools that
reference `_triage/` by name. Not worth the churn.
