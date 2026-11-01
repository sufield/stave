# Supply Chain Ingress Extractor

Analyzes OIDC federation trust policies for CI/CD ingress risks.
Determines whether the subject claim is scoped, whether wildcards
are used, and whether the assumed role has admin-level permissions.

## Implementation

**Source:** `iam-explainer/Stave/Extract/SupplyChain.lean`

Pure function over already-collected IAM role JSON. No live API calls.

### Types

```lean
structure OIDCTrust where
  roleArn : String
  roleName : String
  hasOidcTrust : Bool
  provider : String          -- "github" | "gitlab" | "bitbucket" | "google" | "unknown"
  subClaimIsScoped : Bool
  subClaimValue : String
  hasWildcardSub : Bool
  hasAdminPermissions : Bool
```

### Pipeline

1. **`identifyProvider`** — Maps the federated principal URL to a
   provider name. Matches `token.actions.githubusercontent.com` →
   `github`, `gitlab.com` → `gitlab`, `bitbucket.org` → `bitbucket`,
   `accounts.google.com` → `google`.

2. **`isWildcardSub`** — Returns true for `*` or `*:` prefix patterns.

3. **`analyzeOIDCTrust`** — Parses a single role's trust policy.
   Finds OIDC-federated `Allow` statements, extracts the `:sub`
   condition from `StringEquals` or `StringLike` blocks, checks
   for `AdministratorAccess` in attached policies.

4. **`transformSupplyChain`** — Orchestrator. Takes `List Json` (raw
   IAM roles), outputs `List ObsAsset`. Non-OIDC roles produce no
   output.

### Input

The `roles` parameter expects the raw `aws iam list-roles` JSON
enriched with `AttachedPolicies`. Each element needs `Arn`,
`RoleName`, `AssumeRolePolicyDocument`, and `AttachedPolicies` fields.

## Output (obs.v0.1)

```json
{
  "id": "arn:aws:iam::123456789:role/github-deploy",
  "type": "aws_iam_role",
  "vendor": "aws",
  "properties": {
    "identity": {
      "kind": "role",
      "trust": {
        "oidc": {
          "has_oidc_trust": true,
          "provider": "github",
          "sub_claim_scoped": false,
          "sub_claim_value": "*",
          "has_wildcard_sub": true,
          "has_admin_permissions": true
        }
      }
    }
  }
}
```

## Verified properties

- GitHub provider correctly identified (`native_decide`)
- GitLab provider correctly identified (`native_decide`)
- `*` is a wildcard sub (`native_decide`)
- `*:ref` is a wildcard sub (`native_decide`)
- Scoped claim (`repo:org/repo:ref:refs/heads/main`) is not wildcard (`native_decide`)
- Wildcard sub + admin permissions detected from trust policy (`#guard`)
- Non-OIDC role (Lambda service principal) returns none (`#guard`)

## Controls that evaluate this output

| Control | What it checks | Severity |
|---|---|---|
| CTL.IAM.TRUST.OIDC.001 | Unscoped subject claim | critical |
| CTL.IAM.TRUST.OIDC.002 | Wildcard subject claim | critical |
| CTL.IAM.TRUST.OIDC.003 | Admin permissions on OIDC role | high |
