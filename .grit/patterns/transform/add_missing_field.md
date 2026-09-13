# Add a missing field to controls

Adds a specified field with a default value to control YAMLs that lack it.
Edit the field name, value, and anchor before running.

Usage: Edit the pattern, then:
  `grit apply add_missing_field internal/controls/ --dry-run --language yaml`

```grit
language yaml

`severity: $sev` as $anchor where {
  $anchor <: not within contains `new_field_name: $_`
} => `severity: $sev
new_field_name: default_value`
```
