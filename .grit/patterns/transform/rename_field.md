# Rename a field across all control YAMLs

Renames a top-level field key. Edit old_name and new_name before running.

Usage: Edit the pattern, then:
  `grit apply rename_field internal/controls/ --dry-run --language yaml`
Review the diff, then remove `--dry-run` to apply.

```grit
language yaml

`old_name: $v` => `new_name: $v`
```
