---
tags: [yaml, error]
level: error
---

# Predicate values must not use raw wildcards

A predicate `value:` field containing `"*"` as a string literal — use
a helper function or explicit resource enumeration instead.

```grit
language yaml

`value: "*"` => .
```
