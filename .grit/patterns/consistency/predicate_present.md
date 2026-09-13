---
tags: [yaml, error]
level: error
---

# Controls must have an unsafe predicate

A ctrl.v1 control that has neither `unsafe_predicate:` nor `unsafe_predicate_alias:`.

```grit
language yaml

file($body) where {
  $body <: contains `dsl_version: ctrl.v1`,
  $body <: not contains `unsafe_predicate: $p`,
  $body <: not contains `unsafe_predicate_alias: $a`
}
```
