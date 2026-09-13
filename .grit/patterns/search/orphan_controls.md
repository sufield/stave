# Find controls not referenced by any chain

Search for controls that no chain definition references — potential
orphans that may be lower priority or need chain integration.

Limitation: GritQL cannot do cross-file joins. Use this to list all
control IDs, then diff against chain references. Better as a Go test.

```grit
language yaml

`id: $id`
```
