# Find controls by scope tag

Returns all controls tagged with a given service scope.

Usage: `grit apply controls_by_service internal/controls/ --language yaml`

```grit
language yaml

`scope_tags: $tags` where {
  $tags <: contains `- $tag`
}
```
