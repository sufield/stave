---
tags: [yaml, info]
level: info
---

# Chain control references (cross-file — limited)

GritQL cannot validate cross-file references. This pattern finds chain
files that reference control IDs — manual or Go-test verification is
needed to confirm the referenced controls exist.

Limitation: this is a search aid, not a CI check. Cross-file reference
validation should be implemented as a Go test (see architecture/
for precedent).

```grit
language yaml

`controls: $c` where {
  $c <: contains `- $id`
}
```
