# Find controls lacking compliance framework mapping

Returns ctrl.v1 controls that have no `compliance:` block.

```grit
language yaml

file($body) where {
  $body <: contains `dsl_version: ctrl.v1`,
  $body <: not contains `compliance: $c`
}
```
