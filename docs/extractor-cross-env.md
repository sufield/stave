# Cross-Environment Extractor

Detects transitive trust paths from non-production to production
environments via `sts:AssumeRole` chains.

## Implementation

**Source:** `iam-explainer/Stave/Extract/CrossEnv.lean`
(`Extract.CrossEnv` namespace)

Pure function over already-collected IAM role JSON. No live API calls.

### Types

```lean
inductive EnvClass where
  | production | staging | development | unknown

structure TrustEdge where
  sourceAccount : String
  targetAccount : String
  targetRoleArn : String
```

### Pipeline

1. **`buildTrustGraph`** — Parses each role's `AssumeRolePolicyDocument`,
   extracts cross-account `Principal.AWS` ARNs, builds directed edges.
   Self-loops (same account) are filtered out.

2. **`bfsFromAccounts`** — BFS from all lower-environment accounts,
   following trust edges. Returns `(account, roleArn, hopCount, bridgeRole)`
   tuples. Fuel-bounded (default 10 hops × edge count).

3. **`analyzeCrossEnv`** — Orchestrator. Takes an environment map
   (`List (String × EnvClass)`) and role JSON list. Filters BFS results
   to only production-account targets. Outputs `List ObsAsset`.

### Input

The `roles` parameter expects the raw `aws iam list-roles` JSON —
each element has `Arn` and `AssumeRolePolicyDocument` fields.

The `envMap` maps 12-digit account IDs to environment classifications.
Source this from AWS Organizations tags, SSM parameters, or a
configuration file.

## Output (obs.v0.1)

```json
{
  "id": "arn:aws:iam::111111111111:role/devops-deploy",
  "type": "aws_iam_role",
  "vendor": "aws",
  "properties": {
    "identity": {
      "kind": "role",
      "role": {
        "cross_env": {
          "reachable_from_lower_env": true,
          "source_env": "development",
          "path_hop_count": 2,
          "via_bridge_role": "arn:aws:iam::999999999999:role/shared-deploy"
        }
      }
    }
  }
}
```

## Verified properties

- `arnAccount` extracts the correct 12-digit field (proved via `native_decide`)
- Single-hop trust chain produces hop count 1 (`#guard`)
- Two-hop chain (dev → staging → prod) produces 2 results (`#guard`)
- Unreachable accounts produce empty results (`#guard`)

## Controls that evaluate this output

| Control | What it checks | Severity |
|---|---|---|
| CTL.IAM.CROSS.ENV.001 | Direct cross-env access (boolean) | critical |
| CTL.IAM.CROSS.ENV.PATH.001 | Transitive trust path | critical |
