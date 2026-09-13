# Find controls referencing deprecated property paths

Search for controls that reference a field path that was renamed or removed
in the collector contract. Parameterize by editing the pattern's field name.

Usage: Edit the `old_field_name` literal below, then run:
  `grit apply deprecated_field_usage internal/controls/ --language yaml`

```grit
language yaml

`field: $f` where {
  $f <: contains `old_field_name`
}
```
