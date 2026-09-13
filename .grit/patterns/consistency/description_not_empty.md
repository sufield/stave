---
tags: [yaml, error]
level: error
---

# Controls must have a non-empty description

A ctrl.v1 control with an empty or missing `description:` field.

```grit
language yaml

file($body) where {
  $body <: contains `dsl_version: ctrl.v1`,
  $body <: not contains `description: $d`
}
```
