# Compound Chains

A compound chain models a multi-step attack path. Each chain declares
prerequisite controls — all must fire for the chain to activate. A
single IAM overpermission finding is medium; combined with a public
endpoint and missing logging, the chain is critical.

## How chains work

1. `stave apply` evaluates individual controls against observations
2. The chain engine checks which chains have all prerequisites satisfied
3. Chains that fire produce compound findings with elevated severity
4. Chain severity is derived from the component controls' combined risk

## Browse chains

```bash
stave catalog --kind chain              # all chains, grouped by family
stave catalog --kind chain --family iam  # just IAM chains
stave catalog --kind chain --verbose     # full descriptions
```

## Chain structure

Each chain YAML in `chains/` declares:
- `controls`: list of prerequisite control IDs (all must fire)
- `compound_severity`: the severity of the chain as a whole
- `description`: what the attack path looks like end-to-end

See [`chains/README.md`](../../chains/README.md) for the full chain catalog.
