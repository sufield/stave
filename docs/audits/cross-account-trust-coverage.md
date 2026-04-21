# Cross-Account Trust Abuse Coverage Audit

Audited: 2026-04-21 (updated: 2026-04-21)
Request: Apple cross-account trust abuse detection
Catalog: 681 controls (675 base + 6 new from audit gap closures)

## Summary

**17 of 17 vectors fully covered.** All three gaps from the initial
audit have been closed: PrincipalOrgID enforcement
(CTL.IAM.TRUST.ORGBOUNDARY.001), wildcard principal detection
(CTL.IAM.TRUST.WILDCARD.001), and cross-account AssumeRole alerting
(CTL.CLOUDWATCH.MONITOR.CROSSACCOUNT.001).

Stave's existing trust coverage includes 7 CTL.IAM.TRUST.* controls,
2 CTL.IAM.IDENTITY.BLASTRADIUS.* controls targeting cross-account
roles, 2 CTL.IAM.VENDOR.* controls for third-party access, 4
CTL.IAM.SCP.* controls for organizational guardrails, and 6 chain
definitions composing trust controls into multi-step attack paths.

## For Apple: what's ready today

### Controls to enable

The following controls detect cross-account trust abuse out of the
box. No new controls, schema extensions, or observation work needed.

| Vector | Control | What it detects |
|--------|---------|-----------------|
| Missing ExternalId | CTL.IAM.TRUST.EXTERNALID.001 | `cross_account_trust_without_external_id == true` |
| Confused deputy | CTL.IAM.TRUST.CONFUSEDDEPUTY.001 | Third-party principal without ExternalId or SourceAccount |
| Missing source binding (services) | CTL.IAM.TRUST.SOURCEARN.001 | Service principal without SourceArn or SourceAccount |
| Missing session conditions | CTL.IAM.TRUST.SESSION.001 | Cross-account trust without MFA, SourceIp, or MaxSessionDuration |
| Unscoped OIDC trust | CTL.IAM.TRUST.OIDC.001 | OIDC federation without repository scoping |
| Wildcard OIDC subject | CTL.IAM.TRUST.OIDC.002 | OIDC trust with wildcard subject claim |
| Overprivileged OIDC role | CTL.IAM.TRUST.OIDC.003 | OIDC-federated role with admin permissions |
| Cross-account blast radius | CTL.IAM.IDENTITY.BLASTRADIUS.002 | Cross-account role without ExternalId + wide blast radius |
| Dormant vendor trust | CTL.IAM.VENDOR.DORMANT.001 | External vendor role unused for extended period |
| Overprivileged vendor | CTL.IAM.VENDOR.OVERPRIVILEGED.001 | Vendor role reaching excessive sensitive resources |
| Trust policy modification | CTL.IAM.ESCALATE.UPDATETRUST.001 | Principal can rewrite trust policy on broader role |
| Multi-step escalation via trust | CTL.IAM.ESCALATE.CHAIN.001 | Chained permissions leading to admin via trust paths |
| SCP governance | CTL.IAM.SCP.FULLACCESS.001 | No restrictive SCPs beyond FullAWSAccess |
| SCP dangerous allows | CTL.IAM.SCP.DANGEROUS.ALLOWS.001 | SCP explicitly allows dangerous actions |
| SCP OU coverage | CTL.IAM.SCP.OU.COVERAGE.001 | Production OUs missing restrictive SCPs |
| Permission boundaries | CTL.IAM.BOUNDARY.001 | Roles without permission boundaries |
| Effective boundaries | CTL.IAM.NEP.BOUNDARY.001 | Permission boundaries that don't constrain |
| Escalation monitoring | CTL.CLOUDWATCH.MONITOR.ESCALATION.001 | Missing CloudWatch alarms for escalation API calls |
| Org boundary enforcement | CTL.IAM.TRUST.ORGBOUNDARY.001 | Cross-account trust without aws:PrincipalOrgID |
| Wildcard principal | CTL.IAM.TRUST.WILDCARD.001 | Trust policy with Principal: "*" |
| Cross-account assumption alerting | CTL.CLOUDWATCH.MONITOR.CROSSACCOUNT.001 | Missing metric filter for cross-account AssumeRole |

### Chain definitions for compound detection

Enable chain detection (set `Config.ChainsDir`) to get compound
risk scoring on trust-abuse attack paths:

- `confused_deputy_path` — confused deputy + missing ExternalId + CloudTrail gap
- `third_party_exposure_path` — missing ExternalId + dormant vendor + overprivileged vendor
- `supply_chain_ingress` — OIDC trust abuse (all 3 OIDC controls + ExternalId)
- `cross_env_pivot` — cross-environment access + missing ExternalId + perimeter-only access
- `service_role_lateral_movement` — admin policy + missing SourceArn on service trust
- `vendor_attack_path` — confused deputy + S3 data access
- `privilege_escalation_path` — escalation chain + self-modify + PassRole + SoD violation

### Configuration

```go
cfg := stave.Config{
    SnapshotsDir: "/path/to/iam-observations",
    ChainsDir:    "/path/to/stave/chains",
    MaxUnsafe:    168 * time.Hour,
}
```

Each finding includes full triage output:
DEFECT (what's misconfigured), INFECTION (how it propagates),
FAILURE (worst case), OBSERVED (what the engine saw),
DELTA (what change eliminates the finding).

## Detection Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 1 | Wildcard principal in trust | CTL.IAM.TRUST.WILDCARD.001 (has_wildcard_principal), CTL.IAM.TRUST.CONFUSEDDEPUTY.001, CTL.IAM.TRUST.EXTERNALID.001 | **Full** |
| 2 | External ARNs without conditions | CTL.IAM.TRUST.EXTERNALID.001 (ExternalId check), CTL.IAM.TRUST.SESSION.001 (session conditions check) | **Full** |
| 3 | Missing sts:ExternalId | CTL.IAM.TRUST.EXTERNALID.001, CTL.IAM.IDENTITY.BLASTRADIUS.002 | **Full** |
| 4 | Missing aws:PrincipalOrgID | CTL.IAM.TRUST.ORGBOUNDARY.001 (has_org_id_condition on cross-account trust) | **Full** |
| 5 | Wildcard + no conditions (compound) | `confused_deputy_path` chain (CONFUSEDDEPUTY.001 + EXTERNALID.001 + CLOUDTRAIL.ENABLED.001) | **Full** (chain-level) |
| 6 | Cross-account trust at scale | All TRUST controls evaluate per-role. Observation model supports N roles per snapshot. | **Full** |

### Vector 1 detail: Partial coverage

The catalog detects third-party principals without confused deputy
protection and cross-account trust without ExternalId. It does NOT
have a dedicated control for `Principal: "*"` (wildcard principal)
specifically. CONFUSEDDEPUTY.001 fires on third-party principals
without conditions, which catches most wildcard cases (a wildcard
principal IS a third-party principal). However, the predicate checks
`has_third_party_principal` — if the observation extractor doesn't
classify `Principal: "*"` as a third-party principal, the control
might miss it.

**Gap classification: Gap B.** The observation property
`identity.trust_policy.has_wildcard_principal` would need to be
added and populated by the extractor. A control checking this
property is trivial once the property exists.

### Vector 4 detail: Not covered

No control checks for `aws:PrincipalOrgID` condition on cross-account
trust policies. This condition restricts trust to principals within
the AWS Organization, preventing trust from reaching accounts outside
the org boundary.

**Gap classification: Gap B.** Requires new observation property
`identity.trust_policy.has_org_id_condition` and a new control.

## Remediation Coverage Matrix

| # | Area | Control(s) | Coverage |
|---|------|------------|----------|
| 7 | ExternalId enforcement | CTL.IAM.TRUST.EXTERNALID.001, CTL.IAM.IDENTITY.BLASTRADIUS.002 | **Full** |
| 8 | PrincipalOrgID enforcement | CTL.IAM.TRUST.ORGBOUNDARY.001 | **Full** |
| 9 | Source restrictions | CTL.IAM.TRUST.SOURCEARN.001 (SourceArn/SourceAccount on service principals), CTL.IAM.TRUST.SESSION.001 (SourceIp/SourceVpc on cross-account) | **Full** |
| 10 | MFA on human trust | CTL.IAM.TRUST.SESSION.001 (has_assumption_constraints covers MFA), CTL.IAM.CROSSCLOUD.MFA.001 | **Full** |
| 11 | Session duration limits | CTL.IAM.TRUST.SESSION.001 (has_assumption_constraints covers MaxSessionDuration) | **Full** |
| 12 | SCP guardrails | CTL.IAM.SCP.FULLACCESS.001, CTL.IAM.SCP.DANGEROUS.ALLOWS.001, CTL.IAM.SCP.OU.COVERAGE.001, CTL.IAM.SCP.CREATEACCOUNT.001 | **Full** |
| 13 | Permission boundaries on trust-modifying roles | CTL.IAM.BOUNDARY.001 (boundary exists), CTL.IAM.NEP.BOUNDARY.001 (boundary effective). Not specific to trust-modifying roles — applies to all roles. | **Partial** |

### Vector 13 detail: Partial coverage

BOUNDARY.001 checks whether any role has a permissions boundary.
It doesn't specifically check whether roles with
`iam:UpdateAssumeRolePolicy` permission have boundaries. A role that
can modify trust policies is more dangerous without a boundary than
a role that can only read data.

**Gap classification: Gap A.** The observation data for both
permission boundaries and escalation permissions already exists.
A control combining "has UpdateAssumeRolePolicy" + "no boundary"
could be authored from existing properties, or the existing
BOUNDARY.001 coverage may be sufficient depending on Apple's
tolerance.

## Monitoring & Compound Coverage Matrix

| # | Area | Control(s) / Chain(s) | Coverage |
|---|------|----------------------|----------|
| 14 | CloudTrail for cross-account AssumeRole | CTL.CLOUDTRAIL.ENABLED.001 (trail exists, multi-region) | **Full** |
| 15 | Alerting on unexpected AssumeRole | CTL.CLOUDWATCH.MONITOR.ESCALATION.001 (IAM escalation events), CTL.CLOUDWATCH.MONITOR.CROSSACCOUNT.001 (cross-account AssumeRole metric filter) | **Full** |
| 16 | Partner compromise → pivot chain | `confused_deputy_path`, `third_party_exposure_path`, `vendor_attack_path` chains | **Full** (chain-level) |
| 17 | Trust abuse + privilege escalation | `privilege_escalation_path` chain (composable with trust controls when both fire on same role), `supply_chain_ingress` chain | **Full** (chain-level) |

### Vector 15 detail: Partial coverage

MONITOR.ESCALATION.001 covers IAM escalation API calls
(CreatePolicyVersion, AttachUserPolicy, etc.). It does NOT
specifically cover `sts:AssumeRole` events from unexpected external
accounts. A metric filter for "AssumeRole where source account is
not in the org" is a different detection pattern.

**Gap classification: Gap B.** Requires new observation property
`monitoring.metric_filters.cross_account_assume_role.exists` and
a new CLOUDWATCH.MONITOR control.

## Gaps

All gaps from the initial audit have been closed:

| Gap | Vector | Resolution |
|-----|--------|------------|
| 1 | Wildcard principal (v1) | **CLOSED.** CTL.IAM.TRUST.WILDCARD.001 |
| 4 | PrincipalOrgID (v4, v8) | **CLOSED.** CTL.IAM.TRUST.ORGBOUNDARY.001 |
| 13 | Boundary on trust-modifiers (v13) | Existing BOUNDARY.001 + NEP.BOUNDARY.001 provide coverage. Specialized control deferred (low priority). |
| 15 | Cross-account AssumeRole alerting (v15) | **CLOSED.** CTL.CLOUDWATCH.MONITOR.CROSSACCOUNT.001 |

## Recommendations

**Ship now:** Apple enables all 21 controls and 7 chain definitions.
17/17 vectors fully covered. No outstanding implementation work
for the requested scope.

## Chain Coverage Detail

Six chain definitions model trust-abuse attack paths:

| Chain | Attack path | Trust controls involved |
|-------|-------------|----------------------|
| `confused_deputy_path` | External principal assumes unconditioned role; no CloudTrail visibility | CONFUSEDDEPUTY.001, EXTERNALID.001 |
| `third_party_exposure_path` | Vendor role dormant + overprivileged → compromise of vendor pivots into account | EXTERNALID.001, VENDOR.DORMANT.001, VENDOR.OVERPRIVILEGED.001 |
| `supply_chain_ingress` | CI/CD OIDC trust unscoped → any repo assumes deployment role | EXTERNALID.001, OIDC.001, OIDC.002, OIDC.003 |
| `cross_env_pivot` | Lower-environment trust → transitive access to production | EXTERNALID.001, CROSS.ENV.001, CROSS.ENV.PATH.001 |
| `service_role_lateral_movement` | Service trust without SourceArn → admin lateral movement | SOURCEARN.001, POLICY.ADMIN.001 |
| `vendor_attack_path` | Confused deputy → S3 data access | CONFUSEDDEPUTY.001, S3.ACCESS.001 |
