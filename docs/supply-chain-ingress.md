# Supply Chain Ingress

Supply chain ingress analysis answers: "Can an external CI/CD
pipeline assume a production role with excessive permissions?"

Modern cloud deployments use OIDC federation (GitHub Actions,
GitLab CI, Bitbucket Pipelines) to grant CI/CD workflows temporary
AWS credentials. When the trust policy is misconfigured — unscoped
subject claims, wildcard conditions, or admin-level permissions — any
pipeline in the provider's namespace becomes a production ingress
path.

## The trust model

```
GitHub Actions → OIDC Provider → IAM Role → Production Resources
```

The extractor analyzes the IAM trust policy to determine:
1. Is the subject claim scoped to a specific repository and branch?
2. Does the trust policy use wildcard conditions?
3. Does the assumed role have admin-level permissions?

## Controls

### CTL.IAM.TRUST.OIDC.001 — Unscoped OIDC trust

```
Fires when: has_oidc_trust == true
        AND sub_claim_scoped == false
Severity: critical
```

The trust policy accepts any repository from the OIDC provider.
Any project in the provider's namespace can assume this role.

**Remediation:** Add a StringEquals condition on the sub claim:
`"token.actions.githubusercontent.com:sub": "repo:org/repo:ref:refs/heads/main"`

### CTL.IAM.TRUST.OIDC.002 — Wildcard subject claim

```
Fires when: has_oidc_trust == true
        AND has_wildcard_sub == true
Severity: critical
```

The trust policy uses a wildcard (`*`) for the subject claim,
defeating the purpose of OIDC federation entirely.

**Remediation:** Replace the wildcard with an exact or prefix-scoped
subject match.

### CTL.IAM.TRUST.OIDC.003 — Overprivileged CI/CD role

```
Fires when: has_oidc_trust == true
        AND has_admin_permissions == true
Severity: high
```

The OIDC-trusted role has AdministratorAccess or broad wildcard
actions. Pipeline compromise grants full account access.

**Remediation:** Scope permissions to the deployment task. Replace
AdministratorAccess with task-specific policies.

## Safety chain: supply_chain_ingress

```yaml
id: supply_chain_ingress
controls:
  - CTL.IAM.TRUST.OIDC.001
  - CTL.IAM.TRUST.OIDC.002
  - CTL.IAM.TRUST.OIDC.003
  - CTL.IAM.TRUST.EXTERNALID.001
escalation_threshold: 2
compound_severity: critical
```

When an unscoped OIDC trust combines with admin permissions, the
compound finding fires: any CI/CD pipeline in the provider's
namespace has production-grade credentials.

## Observation properties

```yaml
properties:
  identity:
    kind: role
    trust:
      oidc:
        has_oidc_trust: true
        provider: github
        sub_claim_scoped: false
        sub_claim_value: "*"
        has_wildcard_sub: true
        has_admin_permissions: true
```

## Stave's own provenance

Stave provides its own supply chain provenance via `stave version --sbom`,
which generates a CycloneDX 1.5 JSON SBOM from Go build info. This
allows auditors to verify that the tool auditing supply chain ingress
paths is itself provenance-aware:

```bash
stave version --sbom > stave-sbom.json
stave version --verify   # binary hash, policy hash, module list
```

## Key files

| File | Purpose |
|---|---|
| `controls/iam/trust/CTL.IAM.TRUST.OIDC.001-003.yaml` | 3 OIDC trust controls |
| `chains/supply_chain_ingress.yaml` | Compound chain definition |
| `docs/extractor-supply-chain.md` | Extractor implementation guide |
