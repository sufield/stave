---
title: Severity Vocabulary
tags: [yaml, error]
level: error
---

# Severity must be a known vocabulary term

Catches control YAMLs where `severity:` is not one of the five allowed values.

```grit
language yaml

`severity: $sev` where {
  $sev <: not or {`critical`, `high`, `medium`, `low`, `info`}
}
```
