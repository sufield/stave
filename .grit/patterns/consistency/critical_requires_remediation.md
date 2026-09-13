---
tags: [yaml, error]
level: error
---

# Critical controls must have a remediation block

A control with `severity: critical` that has no `remediation:` block.

```grit
language yaml

file($body) where {
  $body <: contains `severity: critical`,
  $body <: not contains `remediation: $r`
}
```
