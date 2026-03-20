# Control DSL Migration Guide

This guide describes how to migrate control files across DSL schema versions.

Current stable DSL version: `ctrl.v1`

## Version Policy

- Breaking DSL changes require a new schema version.
- Existing stable versions remain supported for a defined transition period.
- Migration guidance is published before removing support for an older version.

## Current State (`ctrl.v1`)

No migration is required today if your controls already use:

```yaml
dsl_version: ctrl.v1
```

## Migration Checklist

When a future DSL version is introduced, use this checklist:

1. Update `dsl_version` in each control.
2. Validate with `stave validate --controls <dir>`.
3. Run evaluation against known test fixtures.
4. Compare findings for intentional changes only.
5. Update any internal docs or examples pinned to old syntax.

## Validation Command

```bash
stave validate --controls ./controls
```

Fix all validation issues before release.
